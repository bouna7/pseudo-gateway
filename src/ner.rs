//! Client pour le service NER Microsoft Presidio.
//!
//! Détecte les entités que la regex ne sait pas reconnaître (noms de personnes,
//! organisations, lieux…). Configurable par variables d'environnement :
//!   PRESIDIO_URL   (défaut http://127.0.0.1:5002)
//!   PRESIDIO_LANG  (défaut en)

use once_cell::sync::Lazy;
use serde::Deserialize;
use std::time::Duration;

#[derive(Deserialize, Debug)]
pub struct PresidioEntity {
    pub entity_type: String,
    /// ATTENTION : Presidio renvoie des index en CARACTÈRES (offsets Python),
    /// pas en octets. On les convertit côté Rust (voir `char_slice`).
    pub start: usize,
    pub end: usize,
    #[allow(dead_code)] // présent dans la réponse ; filtrage déjà fait via score_threshold
    pub score: f32,
}

/// Timeout (ms) de l'appel Presidio. La détection NER reste best-effort : si
/// Presidio est lent ou indisponible, on n'attend pas indéfiniment.
fn timeout_ms() -> u64 {
    std::env::var("PRESIDIO_TIMEOUT_MS")
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(4000)
}

/// Client HTTP réutilisé (pool de connexions) avec timeout — évite de recréer un
/// client par requête et de bloquer `/pseudonymize` si Presidio ne répond pas.
static CLIENT: Lazy<reqwest::Client> = Lazy::new(|| {
    reqwest::Client::builder()
        .timeout(Duration::from_millis(timeout_ms()))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
});

fn presidio_url() -> String {
    std::env::var("PRESIDIO_URL").unwrap_or_else(|_| "http://127.0.0.1:5002".to_string())
}

fn presidio_lang() -> String {
    std::env::var("PRESIDIO_LANG").unwrap_or_else(|_| "en".to_string())
}

/// Appelle Presidio /analyze. Renvoie les entités détectées.
pub async fn analyze(text: &str) -> Result<Vec<PresidioEntity>, reqwest::Error> {
    CLIENT
        .post(format!("{}/analyze", presidio_url()))
        .json(&serde_json::json!({
            "text": text,
            "language": presidio_lang(),
            "score_threshold": 0.6  // écarte les faux positifs faibles (ex. URL à 0.5)
        }))
        .send()
        .await?
        .json::<Vec<PresidioEntity>>()
        .await
}

/// Texte témoin de la sonde. Un modèle sain en tire une personne et un lieu ;
/// aucune des quatre regex de la passerelle ne les reconnaîtrait.
const TEMOIN: &str = "Jean Martin habite a Lyon";

/// Vérifie que la détection automatique fonctionne vraiment.
///
/// Distingue trois états que rien ne séparait jusqu'ici, la passerelle
/// répondant « ok » dans les trois cas :
///   - Presidio injoignable ou muet (worker mort : le port écoute, personne
///     ne répond — vu en prod le 2026-07-18 **et** le 2026-11-11) ;
///   - Presidio répond mais ne détecte rien (conf de langue ou de modèle
///     cassée, mapping NER perdu) ;
///   - Presidio en état de servir.
///
/// Les deux premiers cas laissent partir les noms et les villes en clair au
/// modèle, sans aucun signal. D'où une sonde qui exige une **détection**, pas
/// seulement une réponse HTTP.
pub async fn sonde() -> Result<usize, String> {
    let entities = analyze(TEMOIN)
        .await
        .map_err(|e| format!("Presidio injoignable ({}) : {e}", presidio_url()))?;
    let utiles = entities
        .iter()
        .filter(|e| map_type(&e.entity_type).is_some())
        .count();
    if utiles == 0 {
        return Err(format!(
            "Presidio repond mais ne detecte rien sur le texte temoin \
             (langue demandee : {}) — les noms et les lieux partent en clair",
            presidio_lang()
        ));
    }
    Ok(utiles)
}

/// Mappe un type Presidio vers un type de jeton interne. `None` = type ignoré
/// (URL, DATE_TIME… souvent faux positifs ou non sensibles).
pub fn map_type(presidio_type: &str) -> Option<&'static str> {
    match presidio_type {
        "PERSON" => Some("PERSON"),
        "EMAIL_ADDRESS" => Some("EMAIL"),
        "PHONE_NUMBER" => Some("PHONE"),
        "LOCATION" | "GPE" => Some("LOC"),
        "NRP" | "ORGANIZATION" | "ORG" => Some("ORG"),
        "IBAN_CODE" => Some("IBAN"),
        "CREDIT_CARD" => Some("CARD"),
        _ => None,
    }
}

/// Découpe `text` selon des offsets en CARACTÈRES (et non en octets), pour rester
/// correct sur du texte accentué (français).
fn char_slice(text: &str, start_char: usize, end_char: usize) -> Option<String> {
    if start_char >= end_char {
        return None;
    }
    let chars: Vec<(usize, char)> = text.char_indices().collect();
    let n = chars.len();
    if end_char > n {
        return None;
    }
    let start_byte = chars[start_char].0;
    let end_byte = if end_char == n {
        text.len()
    } else {
        chars[end_char].0
    };
    Some(text[start_byte..end_byte].to_string())
}

/// Remet une capitale initiale sur chaque mot écrit ENTIÈREMENT en majuscules.
/// Renvoie `None` quand il n'y a rien à adoucir.
///
/// # Pourquoi
///
/// Le modèle français de Presidio ne reconnaît pas un nom tout en capitales :
/// mesuré le 31/10/2026, « MAMADOU SOUMARE » ne produit aucune entité, alors
/// que « Mamadou Soumare » sort en `PERSON` à 0.85. Or c'est précisément ainsi
/// qu'un CV écrit le nom du candidat, en tête de page — le nom partait donc en
/// clair au modèle, le cas qui a motivé ce correctif.
///
/// # L'invariant qui fait marcher la reprojection
///
/// Le nombre de CARACTÈRES est préservé. Les offsets que Presidio renvoie sur
/// le texte adouci désignent donc exactement les mêmes caractères dans le texte
/// d'origine, dont on extrait la valeur telle qu'elle y est réellement écrite —
/// c'est elle qu'il faut jetonner, pas sa version adoucie.
fn adoucir_majuscules(text: &str) -> Option<String> {
    let mut chars: Vec<char> = text.chars().collect();
    let mut modifie = false;
    let mut i = 0;
    while i < chars.len() {
        if !chars[i].is_alphabetic() {
            i += 1;
            continue;
        }
        let debut = i;
        while i < chars.len() && chars[i].is_alphabetic() {
            i += 1;
        }
        // Une lettre isolée n'est pas un mot en capitales (« J. Dupont »).
        if i - debut < 2 || !chars[debut..i].iter().all(|c| c.is_uppercase()) {
            continue;
        }
        for c in &mut chars[debut + 1..i] {
            let mut bas = c.to_lowercase();
            // Une minuscule qui s'écrit sur plusieurs caractères (« İ ») est
            // laissée telle quelle : décaler les offsets coûterait plus cher
            // que ce cas ne vaut.
            if let (Some(unique), None) = (bas.next(), bas.next()) {
                *c = unique;
                modifie = true;
            }
        }
    }
    modifie.then(|| chars.into_iter().collect())
}

/// Entités de la seconde passe retenues : uniquement des personnes, et
/// uniquement sur au moins deux mots.
///
/// Les deux restrictions sont mesurées, pas prudentielles. Adoucir le texte
/// fait aussi apparaître des faux positifs d'un seul mot (« CDI » lu comme
/// `Cdi`), et seul `PERSON` gagne quelque chose à l'opération : ni les
/// organisations ni les lieux en capitales ne sont mieux reconnus une fois
/// adoucis. Un nom de personne en tête de CV, lui, fait toujours deux mots.
fn noms_en_capitales(original: &str, entities: &[PresidioEntity]) -> Vec<(String, String)> {
    entities
        .iter()
        .filter(|e| e.entity_type == "PERSON")
        .filter_map(|e| char_slice(original, e.start, e.end))
        .filter(|v| v.split_whitespace().count() >= 2)
        .map(|v| ("PERSON".to_string(), v))
        .collect()
}

/// Ajoute à `terms` ce que la détection automatique trouve dans `text`.
///
/// **Best effort assumé** : si Presidio est absent ou en panne, on continue avec
/// les détecteurs à format strict (regex) et les termes fournis, plutôt que de
/// refuser la requête. Les deux appelants (l'endpoint `/v1/pseudonymize` et le
/// proxy de filtrage) passent par ici, pour qu'un texte soit masqué de la même
/// façon quel que soit le chemin emprunté.
///
/// Deux passes : le texte tel quel, puis — seulement s'il contient des mots en
/// capitales — sa version adoucie, pour les noms que le modèle rate autrement
/// (cf. [`adoucir_majuscules`]). Les valeurs trouvées deux fois ne posent pas de
/// problème : la résolution de chevauchement du coffre écarte les doublons.
pub async fn enrichir(text: &str, terms: &mut Vec<crate::pseudonymize::CustomTerm>) {
    let entities = match analyze(text).await {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!(error = %e, "NER (Presidio) indisponible — repli regex + termes manuels");
            return;
        }
    };
    for (typ, value) in to_terms(text, &entities) {
        terms.push(crate::pseudonymize::CustomTerm { typ, value });
    }

    let Some(adouci) = adoucir_majuscules(text) else {
        return;
    };
    match analyze(&adouci).await {
        Ok(entities) => {
            for (typ, value) in noms_en_capitales(text, &entities) {
                terms.push(crate::pseudonymize::CustomTerm { typ, value });
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "seconde passe NER (capitales) ignorée")
        }
    }
}

/// Convertit les entités Presidio en couples (type interne, valeur réelle),
/// prêts à être jetonnés comme des `custom_terms`.
pub fn to_terms(text: &str, entities: &[PresidioEntity]) -> Vec<(String, String)> {
    entities
        .iter()
        .filter_map(|e| {
            let typ = map_type(&e.entity_type)?;
            let value = char_slice(text, e.start, e.end)?;
            Some((typ.to_string(), value))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entite(typ: &str, start: usize, end: usize) -> PresidioEntity {
        PresidioEntity {
            entity_type: typ.to_string(),
            start,
            end,
            score: 0.85,
        }
    }

    #[test]
    fn un_nom_en_capitales_retrouve_sa_casse_de_titre() {
        assert_eq!(
            adoucir_majuscules("MAMADOU SOUMARE").as_deref(),
            Some("Mamadou Soumare")
        );
        assert_eq!(
            adoucir_majuscules("DUPONT Marie").as_deref(),
            Some("Dupont Marie")
        );
    }

    #[test]
    fn le_trait_d_union_separe_deux_mots() {
        // « Jean-pierre » serait un prenom improbable : chaque fragment garde sa
        // capitale, ce qui aide le modele plutot que de le gener.
        assert_eq!(
            adoucir_majuscules("JEAN-PIERRE LEFEVRE").as_deref(),
            Some("Jean-Pierre Lefevre")
        );
    }

    #[test]
    fn les_accents_survivent_a_l_adoucissement() {
        assert_eq!(
            adoucir_majuscules("HÉLÈNE LEFÈVRE").as_deref(),
            Some("Hélène Lefèvre")
        );
    }

    #[test]
    fn rien_a_adoucir_ne_declenche_pas_de_seconde_passe() {
        // `None` est le signal qui evite un appel Presidio inutile.
        assert_eq!(adoucir_majuscules("Marie Dupont habite ici."), None);
        assert_eq!(adoucir_majuscules(""), None);
        // Une initiale isolee n'est pas un mot en capitales.
        assert_eq!(adoucir_majuscules("J. Dupont"), None);
    }

    #[test]
    fn le_nombre_de_caracteres_est_preserve() {
        // L'invariant dont depend la reprojection des offsets de Presidio.
        for texte in [
            "MAMADOU SOUMARE\nDeveloppeur Full Stack\n\nEXPERIENCE",
            "HÉLÈNE LEFÈVRE, 06.11.81.18.14",
            "SNCF, CDI, BTS INFORMATIQUE",
            "ПРИВЕТ МИР",
        ] {
            if let Some(adouci) = adoucir_majuscules(texte) {
                assert_eq!(
                    adouci.chars().count(),
                    texte.chars().count(),
                    "« {texte} » a change de longueur"
                );
            }
        }
    }

    #[test]
    fn les_offsets_de_la_seconde_passe_designent_le_texte_d_origine() {
        let original = "MAMADOU SOUMARE\nDeveloppeur";
        let adouci = adoucir_majuscules(original).expect("il y a des capitales");
        assert_eq!(adouci, "Mamadou Soumare\nDeveloppeur");
        // Presidio travaille sur `adouci` ; on veut la valeur telle qu'ecrite.
        let trouves = noms_en_capitales(original, &[entite("PERSON", 0, 15)]);
        assert_eq!(
            trouves,
            vec![("PERSON".to_string(), "MAMADOU SOUMARE".to_string())]
        );
    }

    #[test]
    fn un_faux_positif_d_un_seul_mot_est_ecarte() {
        // Mesure du 31/10/2026 : « CDI » adouci en « Cdi » sort en PERSON.
        // Un nom de personne en tete de CV fait au moins deux mots.
        assert!(noms_en_capitales("CDI chez Acme", &[entite("PERSON", 0, 3)]).is_empty());
    }

    #[test]
    fn seules_les_personnes_sont_reprises_de_la_seconde_passe() {
        // Ni les organisations ni les lieux ne gagnent a l'adoucissement.
        let e = [entite("ORG", 0, 16), entite("LOCATION", 0, 16)];
        assert!(noms_en_capitales("SOCIETE GENERALE", &e).is_empty());
    }
}
