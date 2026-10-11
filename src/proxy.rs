//! Proxy de filtrage : on le branche devant une API existante, il masque.
//!
//! `POST /proxy/api.openai.com/v1/chat/completions` relaie l'appel vers
//! `https://api.openai.com/v1/chat/completions`, en remplaçant les données
//! sensibles du corps par des jetons à l'aller, et en restituant les vraies
//! valeurs dans la réponse au retour. Côté appelant, une seule chose change :
//! l'URL de base de son client. Aucun appel à `/v1/pseudonymize`, aucun code de
//! masquage à écrire, rien à changer dans la lecture de la réponse.
//!
//! Les deux en-têtes ont des rôles distincts, et c'est le point à retenir :
//!
//! | En-tête | Contenu | Devenir |
//! |---|---|---|
//! | `X-Api-Key` | clé de la passerelle (`pgw_…`) | consommée ici, **jamais relayée** |
//! | `Authorization` | clé de votre fournisseur | relayée telle quelle, jamais lue |
//!
//! Choix assumé : **si le corps ne peut pas être inspecté, la requête est
//! refusée** (415) au lieu d'être relayée en clair. Un proxy de filtrage qui
//! laisse passer ce qu'il ne comprend pas ne filtre pas, il donne l'illusion de
//! filtrer.

use crate::app::AppState;
use crate::auth::Principal;
use crate::error::AppError;
use crate::ner;
use crate::pseudonymize::CustomTerm;
use axum::body::{Body, Bytes};
use axum::extract::{Path, RawQuery, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use axum::response::Response;
use axum::Extension;
use futures_util::StreamExt;
use once_cell::sync::Lazy;
use serde_json::Value;

/// Valeur de `PROXY_ALLOWED_HOSTS` qui éteint le proxy (route non montée).
pub const DESACTIVE: &str = "none";

/// Cibles joignables sans configuration : les API publiques de modèles, plus la
/// boucle locale pour un modèle servi sur la machine (Ollama, LM Studio).
///
/// Une liste fermée, et non « tout ouvert », parce qu'un proxy qui relaie
/// n'importe quelle adresse laisse atteindre depuis l'extérieur ce que seule la
/// passerelle voit : réseau interne de l'hébergeur, et surtout les services de
/// métadonnées des clouds (`169.254.169.254`), qui distribuent des jetons
/// d'identité. `PROXY_ALLOWED_HOSTS` remplace cette liste.
pub const HOTES_PAR_DEFAUT: &[&str] = &[
    "api.openai.com",
    "api.anthropic.com",
    "api.mistral.ai",
    "api.groq.com",
    "api.cerebras.ai",
    "api.deepseek.com",
    "api.cohere.ai",
    "api.together.xyz",
    "api.perplexity.ai",
    "generativelanguage.googleapis.com",
    "openrouter.ai",
    "localhost",
    "127.0.0.1",
];

/// Clés JSON dont la valeur n'est **jamais** du texte libre : la masquer
/// casserait l'appel. `model` choisit le modèle, `stop` est une séquence
/// littérale, `name` désigne une fonction dans un appel d'outil, `url` une
/// ressource. Le filtre les traverse sans les toucher.
const CLES_TECHNIQUES: &[&str] = &[
    "model",
    "id",
    "object",
    "type",
    "role",
    "url",
    "href",
    "key",
    "api_key",
    "apikey",
    "token",
    "secret",
    "password",
    "finish_reason",
    "format",
    "encoding",
    "mime",
    "tool_call_id",
    "name",
    "stop",
    "b64_json",
    "detail",
    "voice",
    "fingerprint",
];

/// Suffixes techniques : `session_id`, `callback_url`, `response_format`…
const SUFFIXES_TECHNIQUES: &[&str] = &[
    "_id",
    "_key",
    "_token",
    "_url",
    "_type",
    "_format",
    "_secret",
    "_fingerprint",
];

/// En-têtes jamais relayés vers l'API cible.
///
/// `x-api-key` et `x-tenant-id` nous appartiennent — relayer la clé de la
/// passerelle à un tiers serait une fuite. `accept-encoding` est retiré pour
/// obtenir une réponse non compressée, seule forme dans laquelle on peut
/// restituer les valeurs. Les autres sont les en-têtes « saut par saut », qui
/// décrivent *cette* connexion et pas la suivante.
const EN_TETES_NON_RELAYES: &[&str] = &[
    "host",
    "x-api-key",
    "x-tenant-id",
    "content-length",
    "accept-encoding",
    "connection",
    "keep-alive",
    "transfer-encoding",
    "te",
    "trailer",
    "upgrade",
    "expect",
    "proxy-authenticate",
    "proxy-authorization",
];

/// En-têtes de réponse non recopiés : le corps change de taille et d'encodage
/// après restitution, annoncer l'ancienne longueur casserait la lecture.
const EN_TETES_REPONSE_IGNORES: &[&str] = &[
    "content-length",
    "content-encoding",
    "transfer-encoding",
    "connection",
    "keep-alive",
    "trailer",
    "te",
    "upgrade",
];

/// Garde-fous sur le corps : au-delà, on refuse plutôt que de masquer à moitié.
const MAX_CHAINES: usize = 500;
const MAX_PROFONDEUR: usize = 64;
/// Plafond de la réponse chargée en mémoire (hors flux SSE, lui jamais stocké).
const MAX_REPONSE: usize = 32 * 1024 * 1024;

/// Un client réutilisé : rétablir TLS à chaque appel ajouterait un aller-retour
/// complet à chaque requête. Le délai est fixé par appel, pas ici.
static CLIENT: Lazy<reqwest::Client> = Lazy::new(|| {
    reqwest::Client::builder()
        // On restitue les valeurs dans le corps : il doit arriver en clair.
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
});

/// Liste d'hôtes autorisés, lue depuis la configuration.
/// `None` = proxy éteint.
pub fn hotes_autorises(brut: Option<&str>) -> Option<Vec<String>> {
    match brut.map(str::trim) {
        Some(v) if v.eq_ignore_ascii_case(DESACTIVE) => None,
        None | Some("") => Some(HOTES_PAR_DEFAUT.iter().map(|h| h.to_string()).collect()),
        Some(v) => {
            let liste: Vec<String> = v
                .split(',')
                .map(|h| h.trim().to_ascii_lowercase())
                .filter(|h| !h.is_empty())
                .collect();
            if liste.is_empty() {
                None
            } else {
                Some(liste)
            }
        }
    }
}

/// `true` si l'hôte demandé est joignable. Une entrée commençant par un point
/// couvre un domaine entier (`.openai.com`), `*` ouvre tout — auquel cas les
/// adresses internes restent refusées, elles ne sont jamais une cible légitime
/// d'un appel sortant.
fn hote_autorise(hote: &str, liste: &[String]) -> bool {
    let hote = hote.to_ascii_lowercase();
    let sans_port = hote_nu(&hote).to_string();
    if liste.iter().any(|e| e == "*") {
        return !adresse_interne(&sans_port);
    }
    liste.iter().any(|e| {
        if let Some(domaine) = e.strip_prefix('.') {
            sans_port == domaine || sans_port.ends_with(&format!(".{domaine}"))
        } else {
            *e == hote || *e == sans_port
        }
    })
}

/// Hôte débarrassé de son port, et des crochets d'une adresse IPv6.
///
/// Découper bêtement sur le premier « : » transformait `[::1]` en `[`, qui ne
/// ressemble plus à une adresse locale : la boucle locale passait alors le
/// contrôle en mode ouvert.
fn hote_nu(hote: &str) -> &str {
    if let Some(reste) = hote.strip_prefix('[') {
        return reste.split(']').next().unwrap_or(reste);
    }
    // Plus d'un « : » : adresse IPv6 écrite sans crochets, donc sans port.
    if hote.matches(':').count() > 1 {
        return hote;
    }
    hote.split(':').next().unwrap_or(hote)
}

/// Adresse de la machine ou du réseau privé. Reconnue sur la forme littérale :
/// un nom de domaine qui *résout* vers une adresse privée n'est pas détecté ici,
/// c'est le rôle de la liste d'hôtes de ne pas l'y faire figurer.
fn adresse_interne(hote: &str) -> bool {
    let hote = hote_nu(hote);
    if hote == "localhost" || hote.ends_with(".localhost") {
        return true;
    }
    match hote.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(v4)) => {
            v4.is_loopback() || v4.is_private() || v4.is_link_local() || v4.is_unspecified()
        }
        Ok(std::net::IpAddr::V6(v6)) => {
            v6.is_loopback() || v6.is_unspecified() || (v6.segments()[0] & 0xfe00) == 0xfc00
        }
        Err(_) => false,
    }
}

/// `http` pour la boucle locale et le réseau privé, `https` partout ailleurs :
/// un modèle servi en local n'a pas de certificat, une API publique l'exige.
fn schema(hote: &str) -> &'static str {
    if adresse_interne(hote) {
        "http"
    } else {
        "https"
    }
}

fn non_relaye(nom: &str) -> bool {
    let nom = nom.to_ascii_lowercase();
    EN_TETES_NON_RELAYES.contains(&nom.as_str())
}

fn cle_technique(nom: &str) -> bool {
    let nom = nom.to_ascii_lowercase();
    CLES_TECHNIQUES.contains(&nom.as_str()) || SUFFIXES_TECHNIQUES.iter().any(|s| nom.ends_with(s))
}

/// Chemin d'une chaîne dans le document JSON, pour la réécrire après masquage.
#[derive(Clone, Debug, PartialEq)]
enum Clef {
    Index(usize),
    Nom(String),
}

/// Relève toutes les chaînes de texte libre du document, avec leur emplacement.
fn collecter(valeur: &Value, chemin: Vec<Clef>, out: &mut Vec<(Vec<Clef>, String)>, niveau: usize) {
    if niveau > MAX_PROFONDEUR || out.len() > MAX_CHAINES {
        return;
    }
    match valeur {
        // Une image ou un fichier encodé n'est pas du texte : le passer aux
        // détecteurs coûterait cher pour rien et risquerait de l'abîmer.
        Value::String(s) if !s.is_empty() && !s.starts_with("data:") => {
            out.push((chemin, s.clone()));
        }
        Value::Array(items) => {
            for (i, item) in items.iter().enumerate() {
                let mut c = chemin.clone();
                c.push(Clef::Index(i));
                collecter(item, c, out, niveau + 1);
            }
        }
        Value::Object(map) => {
            for (k, v) in map {
                if cle_technique(k) {
                    continue;
                }
                let mut c = chemin.clone();
                c.push(Clef::Nom(k.clone()));
                collecter(v, c, out, niveau + 1);
            }
        }
        _ => {}
    }
}

/// Réécrit la chaîne située à `chemin`.
fn remplacer(valeur: &mut Value, chemin: &[Clef], nouvelle: String) {
    let mut courant = valeur;
    for clef in chemin {
        courant = match (clef, courant) {
            (Clef::Index(i), Value::Array(items)) => match items.get_mut(*i) {
                Some(v) => v,
                None => return,
            },
            (Clef::Nom(n), Value::Object(map)) => match map.get_mut(n) {
                Some(v) => v,
                None => return,
            },
            _ => return,
        };
    }
    *courant = Value::String(nouvelle);
}

/// Masque un texte libre : détecteurs stricts (regex) + NER, puis jetonnage.
async fn masquer_texte(st: &AppState, tenant: &str, texte: &str) -> Result<String, AppError> {
    let mut terms: Vec<CustomTerm> = Vec::new();
    ner::enrichir(texte, &mut terms).await;
    let (masque, _) = st.vault.pseudonymize(tenant, texte, &terms).await?;
    Ok(masque)
}

/// Le corps est-il du texte que l'on sait inspecter ?
fn inspectable(content_type: &str) -> Option<bool> {
    let ct = content_type.to_ascii_lowercase();
    let ct = ct.split(';').next().unwrap_or(&ct).trim().to_string();
    if ct == "application/json" || ct.ends_with("+json") {
        Some(true) // JSON : on parcourt les champs
    } else if ct.starts_with("text/") {
        Some(false) // texte brut : on masque tout le corps
    } else {
        None
    }
}

/// Masque le corps de la requête avant de la relayer.
async fn masquer_corps(
    st: &AppState,
    tenant: &str,
    content_type: &str,
    corps: &Bytes,
) -> Result<Bytes, AppError> {
    if corps.is_empty() {
        return Ok(corps.clone());
    }
    let json = match inspectable(content_type) {
        Some(json) => json,
        None => {
            return Err(AppError::UnsupportedContent(format!(
                "corps « {} » : le filtre n'inspecte que JSON et text/* — relayer \
                 ce corps enverrait des données non masquées à l'API cible, la \
                 requête est donc refusée",
                if content_type.is_empty() {
                    "sans Content-Type"
                } else {
                    content_type
                }
            )))
        }
    };
    let texte = std::str::from_utf8(corps)
        .map_err(|_| AppError::BadRequest("corps annoncé en texte mais non UTF-8".into()))?;

    if !json {
        return Ok(Bytes::from(masquer_texte(st, tenant, texte).await?));
    }

    let mut document: Value = serde_json::from_str(texte).map_err(|e| {
        AppError::BadRequest(format!(
            "corps JSON malformé : vérifiez les accolades, les virgules et les guillemets ({e})"
        ))
    })?;
    let mut chaines = Vec::new();
    collecter(&document, Vec::new(), &mut chaines, 0);
    if chaines.len() > MAX_CHAINES {
        return Err(AppError::BadRequest(format!(
            "corps trop fragmenté : plus de {MAX_CHAINES} champs texte à inspecter"
        )));
    }
    for (chemin, texte) in chaines {
        let masque = masquer_texte(st, tenant, &texte).await?;
        if masque != texte {
            remplacer(&mut document, &chemin, masque);
        }
    }
    let corps = serde_json::to_vec(&document)
        .map_err(|e| AppError::BadRequest(format!("corps JSON non ré-encodable : {e}")))?;
    Ok(Bytes::from(corps))
}

/// Restitue les vraies valeurs dans la réponse de l'API cible.
async fn restituer_corps(
    st: &AppState,
    tenant: &str,
    content_type: &str,
    corps: &Bytes,
) -> Result<Bytes, AppError> {
    if corps.is_empty() {
        return Ok(corps.clone());
    }
    // Une réponse binaire (audio, image) ne contient aucun jeton : on la rend
    // telle quelle. Rien ne fuit, c'est la réponse du fournisseur.
    let json = match inspectable(content_type) {
        Some(json) => json,
        None => return Ok(corps.clone()),
    };
    let texte = match std::str::from_utf8(corps) {
        Ok(t) => t,
        Err(_) => return Ok(corps.clone()),
    };
    if !json {
        return Ok(Bytes::from(st.vault.depseudonymize(tenant, texte).await?));
    }
    let mut document: Value = match serde_json::from_str(texte) {
        Ok(v) => v,
        // Réponse d'erreur non JSON malgré l'en-tête : on restitue en texte,
        // plutôt que de masquer l'explication derrière une erreur de parsing.
        Err(_) => return Ok(Bytes::from(st.vault.depseudonymize(tenant, texte).await?)),
    };
    let mut chaines = Vec::new();
    collecter(&document, Vec::new(), &mut chaines, 0);
    for (chemin, texte) in chaines {
        let clair = st.vault.depseudonymize(tenant, &texte).await?;
        if clair != texte {
            remplacer(&mut document, &chemin, clair);
        }
    }
    let corps = serde_json::to_vec(&document)
        .map_err(|e| AppError::Upstream(format!("réponse non ré-encodable : {e}")))?;
    Ok(Bytes::from(corps))
}

/// Longueur du préfixe que l'on peut livrer tout de suite, dans un flux.
///
/// Un jeton `[PERSON_1]` peut être coupé en deux par la découpe des morceaux
/// réseau : livrer `…[PER` puis `SON_1]…` les rendrait tous les deux
/// méconnaissables, et le lecteur verrait passer des jetons au lieu des vraies
/// valeurs. On retient donc la fin dès qu'elle peut encore devenir un jeton.
fn coupe_sur_jeton(texte: &str) -> usize {
    match texte.rfind('[') {
        Some(i) => {
            let fin = &texte[i + 1..];
            // Un jeton se ferme par `]` : si la fermeture est là, plus rien à attendre.
            if fin.contains(']') {
                return texte.len();
            }
            // Forme possible d'un jeton en cours : TYPE, puis `_`, puis des chiffres.
            let plausible = fin.len() < 32
                && fin
                    .chars()
                    .all(|c| c.is_ascii_uppercase() || c == '_' || c.is_ascii_digit());
            if plausible {
                i
            } else {
                texte.len()
            }
        }
        None => texte.len(),
    }
}

/// Relaie une réponse en flux (SSE) en restituant les valeurs au passage.
fn flux_restitue(
    st: AppState,
    tenant: String,
    amont: reqwest::Response,
) -> impl futures_util::Stream<Item = Result<Bytes, std::io::Error>> {
    struct Etat {
        amont: std::pin::Pin<Box<dyn futures_util::Stream<Item = reqwest::Result<Bytes>> + Send>>,
        /// Octets reçus ne formant pas encore un caractère UTF-8 complet.
        octets: Vec<u8>,
        /// Texte décodé pouvant encore faire partie d'un jeton coupé en deux.
        retenu: String,
        termine: bool,
    }
    let etat = Etat {
        amont: Box::pin(amont.bytes_stream()),
        octets: Vec::new(),
        retenu: String::new(),
        termine: false,
    };
    futures_util::stream::unfold(etat, move |mut e| {
        let st = st.clone();
        let tenant = tenant.clone();
        async move {
            loop {
                if e.termine {
                    return None;
                }
                match e.amont.next().await {
                    Some(Ok(morceau)) => {
                        e.octets.extend_from_slice(&morceau);
                        // Décodage incrémental : un caractère accentué peut être
                        // coupé entre deux morceaux réseau.
                        match std::str::from_utf8(&e.octets) {
                            Ok(s) => {
                                e.retenu.push_str(s);
                                e.octets.clear();
                            }
                            Err(err) => {
                                let valide = err.valid_up_to();
                                if let Ok(s) = std::str::from_utf8(&e.octets[..valide]) {
                                    e.retenu.push_str(s);
                                }
                                if err.error_len().is_some() {
                                    // Octets réellement invalides : on les écarte
                                    // pour ne pas bloquer le flux.
                                    e.retenu.push(char::REPLACEMENT_CHARACTER);
                                    e.octets.drain(..valide + 1);
                                } else {
                                    e.octets.drain(..valide);
                                }
                            }
                        }
                        let coupe = coupe_sur_jeton(&e.retenu);
                        if coupe == 0 {
                            continue; // tout est retenu : on attend la suite
                        }
                        let pret: String = e.retenu.drain(..coupe).collect();
                        match st.vault.depseudonymize(&tenant, &pret).await {
                            Ok(clair) => return Some((Ok(Bytes::from(clair)), e)),
                            Err(err) => {
                                e.termine = true;
                                return Some((Err(std::io::Error::other(err.to_string())), e));
                            }
                        }
                    }
                    Some(Err(err)) => {
                        e.termine = true;
                        return Some((Err(std::io::Error::other(err.to_string())), e));
                    }
                    None => {
                        e.termine = true;
                        // Fin du flux : plus rien ne viendra compléter la retenue.
                        if e.retenu.is_empty() && e.octets.is_empty() {
                            return None;
                        }
                        let mut reste = std::mem::take(&mut e.retenu);
                        if !e.octets.is_empty() {
                            reste.push_str(&String::from_utf8_lossy(&e.octets));
                            e.octets.clear();
                        }
                        let clair = st
                            .vault
                            .depseudonymize(&tenant, &reste)
                            .await
                            .unwrap_or(reste);
                        return Some((Ok(Bytes::from(clair)), e));
                    }
                }
            }
        }
    })
}

/// Relaie la requête vers l'API cible, en filtrant dans les deux sens.
pub async fn relayer(
    State(st): State<AppState>,
    Extension(principal): Extension<Principal>,
    method: Method,
    Path(cible): Path<String>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
    corps: Bytes,
) -> Result<Response, AppError> {
    let Some(autorises) = &st.proxy_hosts else {
        return Err(AppError::Disabled);
    };

    // /proxy/<hôte>/<chemin…> — l'hôte est le premier segment.
    let cible = cible.trim_start_matches('/');
    let (hote, chemin) = match cible.split_once('/') {
        Some((h, c)) => (h, c),
        None => (cible, ""),
    };
    if hote.is_empty() {
        return Err(AppError::BadRequest(
            "cible manquante : la forme attendue est \
             /proxy/<hôte>/<chemin> (ex. /proxy/api.openai.com/v1/chat/completions)"
                .into(),
        ));
    }
    if !hote_autorise(hote, autorises) {
        return Err(AppError::Forbidden(format!(
            "hôte « {hote} » non autorisé par cette passerelle : demandez à \
             l'exploitant de l'ajouter à PROXY_ALLOWED_HOSTS"
        )));
    }

    let tenant = principal.tenant(
        headers
            .get("x-tenant-id")
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
            .filter(|t| !t.is_empty()),
    )?;

    let content_type = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let corps_masque = masquer_corps(&st, &tenant, &content_type, &corps).await?;

    let url = format!(
        "{}://{hote}/{chemin}{}",
        schema(hote),
        match &query {
            Some(q) if !q.is_empty() => format!("?{q}"),
            _ => String::new(),
        }
    );
    let mut relayees = HeaderMap::new();
    for (nom, valeur) in headers.iter() {
        if !non_relaye(nom.as_str()) {
            relayees.insert(nom.clone(), valeur.clone());
        }
    }

    tracing::info!(%tenant, %method, %hote, "relais proxy");
    let reponse = CLIENT
        .request(method, &url)
        .headers(relayees)
        .timeout(st.proxy_timeout)
        .body(corps_masque)
        .send()
        .await
        .map_err(|e| {
            AppError::Upstream(format!(
                "{} ({url})",
                if e.is_timeout() {
                    "délai dépassé".to_string()
                } else {
                    e.to_string()
                }
            ))
        })?;

    let statut = reponse.status();
    let ct_reponse = reponse
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let mut sortie = Response::builder().status(statut);
    {
        let entetes = sortie
            .headers_mut()
            .expect("constructeur de réponse valide");
        for (nom, valeur) in reponse.headers().iter() {
            if !EN_TETES_REPONSE_IGNORES.contains(&nom.as_str().to_ascii_lowercase().as_str()) {
                entetes.insert(nom.clone(), valeur.clone());
            }
        }
        // Dire par quel tenant la réponse a été restituée aide au diagnostic,
        // sans rien révéler du contenu.
        if let Ok(v) = HeaderValue::from_str(&tenant) {
            entetes.insert(HeaderName::from_static("x-pseudo-tenant"), v);
        }
    }

    // Réponse en flux (SSE) : on restitue au fil de l'eau, sans tout charger.
    if ct_reponse.to_ascii_lowercase().contains("event-stream") {
        let flux = flux_restitue(st.clone(), tenant, reponse);
        return sortie
            .body(Body::from_stream(flux))
            .map_err(|e| AppError::Upstream(e.to_string()));
    }

    let mut brut = Vec::new();
    let mut flux = reponse.bytes_stream();
    while let Some(morceau) = flux.next().await {
        let morceau = morceau.map_err(|e| AppError::Upstream(e.to_string()))?;
        if brut.len() + morceau.len() > MAX_REPONSE {
            return Err(AppError::Upstream(format!(
                "réponse de l'API cible au-delà de {} Mio",
                MAX_REPONSE / (1024 * 1024)
            )));
        }
        brut.extend_from_slice(&morceau);
    }
    let clair = restituer_corps(&st, &tenant, &ct_reponse, &Bytes::from(brut)).await?;
    sortie
        .body(Body::from(clair))
        .map_err(|e| AppError::Upstream(e.to_string()))
}

/// Explique la marche à suivre sur `/proxy` sans cible : sinon un appel mal
/// formé tombe sur « endpoint inconnu », qui ne dit pas quoi corriger.
pub async fn mode_emploi() -> (StatusCode, axum::Json<serde_json::Value>) {
    (
        StatusCode::BAD_REQUEST,
        axum::Json(serde_json::json!({
            "error": "bad_request",
            "message": "proxy de filtrage : appelez /proxy/<hôte>/<chemin de l'API cible>",
            "exemple": {
                "url_de_base": "https://cette-passerelle/proxy/api.openai.com/v1",
                "en_tetes": {
                    "X-Api-Key": "pgw_… (clé de cette passerelle)",
                    "Authorization": "Bearer sk-… (clé de votre fournisseur, relayée telle quelle)",
                    "X-Tenant-Id": "optionnel : cloisonne les jetons par dossier"
                }
            },
            "hotes_autorises": HOTES_PAR_DEFAUT,
        })),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn liste_par_defaut_sans_configuration() {
        let liste = hotes_autorises(None).expect("proxy actif par défaut");
        assert!(liste.contains(&"api.openai.com".to_string()));
        assert!(hotes_autorises(Some("none")).is_none());
        assert!(hotes_autorises(Some("NONE")).is_none());
    }

    #[test]
    fn liste_explicite_remplace_la_liste_par_defaut() {
        let liste = hotes_autorises(Some("api.exemple.fr, .interne.lan")).unwrap();
        assert_eq!(liste, vec!["api.exemple.fr", ".interne.lan"]);
        assert!(hote_autorise("api.exemple.fr", &liste));
        assert!(hote_autorise("srv.interne.lan", &liste));
        assert!(hote_autorise("interne.lan", &liste));
        // Un hôte hors liste reste refusé, même proche.
        assert!(!hote_autorise("api.openai.com", &liste));
        assert!(!hote_autorise("exemple.fr", &liste));
        // Et le suffixe ne doit pas se laisser abuser par un domaine voisin.
        assert!(!hote_autorise("interne.lan.attaquant.fr", &liste));
    }

    /// Le piège classique d'un proxy : servir de relais vers le réseau interne
    /// de l'hébergeur, dont le service de métadonnées qui distribue des jetons.
    #[test]
    fn tout_ouvert_refuse_quand_meme_les_adresses_internes() {
        let liste = hotes_autorises(Some("*")).unwrap();
        assert!(hote_autorise("api.openai.com", &liste));
        for interne in [
            "169.254.169.254",
            "127.0.0.1",
            "localhost",
            "10.0.0.5",
            "192.168.1.1",
            "172.16.0.1",
            "0.0.0.0",
            "[::1]",
            "[::1]:8080",
            "::1",
            "[fc00::1]",
        ] {
            assert!(
                !hote_autorise(interne, &liste),
                "{interne} ne doit pas être joignable même en mode ouvert"
            );
        }
    }

    /// La boucle locale reste joignable si l'exploitant l'a demandée : un modèle
    /// servi sur la machine (Ollama) est une cible légitime.
    #[test]
    fn boucle_locale_joignable_si_explicitement_listee() {
        let liste = hotes_autorises(Some("127.0.0.1")).unwrap();
        assert!(hote_autorise("127.0.0.1:11434", &liste));
        assert_eq!(schema("127.0.0.1:11434"), "http");
        assert_eq!(schema("api.openai.com"), "https");
    }

    #[test]
    fn cles_techniques_epargnees() {
        for clef in [
            "model",
            "Model",
            "tool_call_id",
            "session_id",
            "callback_url",
        ] {
            assert!(cle_technique(clef), "{clef} doit être épargnée");
        }
        for clef in ["content", "text", "prompt", "feedback", "user"] {
            assert!(!cle_technique(clef), "{clef} doit être inspectée");
        }
    }

    #[test]
    fn la_cle_de_la_passerelle_n_est_jamais_relayee() {
        assert!(non_relaye("X-Api-Key"));
        assert!(non_relaye("x-api-key"));
        assert!(non_relaye("accept-encoding"));
        // La clé du fournisseur, elle, doit passer.
        assert!(!non_relaye("authorization"));
        assert!(!non_relaye("content-type"));
    }

    #[test]
    fn collecte_le_texte_libre_et_ignore_la_technique() {
        let doc: Value = serde_json::json!({
            "model": "gpt-4o",
            "temperature": 0.2,
            "messages": [
                {"role": "user", "content": "Contactez Marie à marie@exemple.fr"},
                {"role": "assistant", "content": "Entendu."}
            ],
            "image": "data:image/png;base64,AAAA"
        });
        let mut out = Vec::new();
        collecter(&doc, Vec::new(), &mut out, 0);
        let valeurs: Vec<&str> = out.iter().map(|(_, v)| v.as_str()).collect();
        assert_eq!(
            valeurs,
            vec!["Contactez Marie à marie@exemple.fr", "Entendu."]
        );
    }

    #[test]
    fn remplacement_au_bon_endroit() {
        let mut doc: Value = serde_json::json!({"messages": [{"content": "a"}, {"content": "b"}]});
        let chemin = vec![
            Clef::Nom("messages".into()),
            Clef::Index(1),
            Clef::Nom("content".into()),
        ];
        remplacer(&mut doc, &chemin, "masqué".into());
        assert_eq!(doc["messages"][0]["content"], "a");
        assert_eq!(doc["messages"][1]["content"], "masqué");
    }

    #[test]
    fn un_jeton_coupe_en_deux_est_retenu() {
        // Rien à retenir : aucun crochet ouvert.
        assert_eq!(coupe_sur_jeton("bonjour"), 7);
        // Jeton complet : tout peut partir.
        let t = "voici [PERSON_1] ok";
        assert_eq!(coupe_sur_jeton(t), t.len());
        // Jeton en cours : on retient depuis le crochet.
        assert_eq!(coupe_sur_jeton("voici [PER"), 6);
        assert_eq!(coupe_sur_jeton("voici [PERSON_"), 6);
        assert_eq!(coupe_sur_jeton("voici [PERSON_1"), 6);
        // Un crochet qui ne peut pas devenir un jeton ne bloque pas le flux.
        assert_eq!(coupe_sur_jeton("un [tableau de bord"), 19);
        let long = format!("x [{}", "A".repeat(40));
        assert_eq!(coupe_sur_jeton(&long), long.len());
    }

    #[test]
    fn types_de_contenu_reconnus() {
        assert_eq!(inspectable("application/json"), Some(true));
        assert_eq!(inspectable("application/json; charset=utf-8"), Some(true));
        assert_eq!(inspectable("application/ld+json"), Some(true));
        assert_eq!(inspectable("text/plain"), Some(false));
        assert_eq!(inspectable("text/event-stream"), Some(false));
        assert_eq!(inspectable("multipart/form-data"), None);
        assert_eq!(inspectable("application/octet-stream"), None);
        assert_eq!(inspectable(""), None);
    }
}
