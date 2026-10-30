//! Logique de pseudonymisation réversible.
//!
//! - `pseudonymize` : détecte les données sensibles (regex + termes fournis),
//!   les remplace par des jetons `[TYPE_N]`, et chiffre la valeur réelle dans le coffre.
//! - `depseudonymize` : retrouve chaque jeton et le remplace par sa valeur déchiffrée.
//!
//! Cohérence : une même valeur reçoit toujours le même jeton (déduplication par
//! **blind index**, cf. [`crate::keys`]), pour que le LLM garde le fil au sein d'un
//! document — et désormais aussi d'une requête à l'autre dès que le store est
//! persistant (Phase 2).
//!
//! La persistance passe par le trait [`VaultStore`] : ni le clair ni les clés ne
//! transitent par le store.

use crate::error::VaultError;
use crate::normalize;
use crate::keys::Keyring;
use crate::store::VaultStore;
use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashSet;
use std::sync::Arc;

/// Terme nommé fourni par l'appelant (nom de personne, organisation, etc.)
/// que la regex seule ne sait pas détecter.
pub struct CustomTerm {
    pub typ: String,
    pub value: String,
}

/// Détecteurs pour les données à format strict. L'ordre compte : on traite
/// EMAIL/IBAN/CARD avant PHONE pour éviter les faux positifs sur des suites de chiffres.
static PATTERNS: Lazy<Vec<(&'static str, Regex)>> = Lazy::new(|| {
    vec![
        ("EMAIL", Regex::new(r"[\w.+-]+@[\w-]+\.[\w.-]+").unwrap()),
        ("IBAN", Regex::new(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{2,4}){2,7}\b").unwrap()),
        ("CARD", Regex::new(r"\b\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}\b").unwrap()),
        ("PHONE", Regex::new(r"(?:\+33|0)[1-9](?:[ .]?\d{2}){4}").unwrap()),
    ]
});

/// Reconnaît un jeton `[TYPE_N]` lors du dé-jetonnage.
static TOKEN_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\[([A-Z]+_\d+)\]").unwrap());

/// Une correspondance détectée dans le texte : plage d'octets + type + valeur.
struct Hit {
    start: usize,
    end: usize,
    typ: String,
    value: String,
    /// Détecteur à format strict (regex : EMAIL, IBAN, CARD, PHONE) par opposition
    /// aux termes fournis et au NER, qui sont probabilistes.
    strict: bool,
}

/// Coffre logique : détient les clés (chiffrement + blind index) et délègue la
/// persistance à un [`VaultStore`] interchangeable (mémoire, Redis, …).
pub struct Vault {
    keyring: Keyring,
    store: Arc<dyn VaultStore>,
}

impl Vault {
    pub fn new(keyring: Keyring, store: Arc<dyn VaultStore>) -> Self {
        Vault { keyring, store }
    }

    /// Sonde la disponibilité du store sous-jacent (pour `GET /health`).
    pub async fn ping(&self) -> Result<(), VaultError> {
        self.store.ping().await
    }

    /// Renvoie le jeton existant pour `value`, ou en crée un nouveau et chiffre la valeur.
    /// Jeton d'une valeur, créé si elle est nouvelle.
    ///
    /// L'index porte sur la FORME CANONIQUE de la valeur ([`crate::normalize`])
    /// et non sur la chaîne brute : sans cela, « MAMADOU SOUMARE » dans un
    /// document et « Soumare Mamadou » dans une question reçoivent deux jetons
    /// différents, et le modèle ne peut plus relier la question au contexte.
    ///
    /// Le blob chiffré, lui, garde la valeur TELLE QU'ÉCRITE la première fois :
    /// la restitution rend la vraie orthographe, pas la forme d'index.
    async fn token_for(&self, tenant: &str, typ: &str, value: &str) -> Result<String, VaultError> {
        let bi = self.keyring.blind_index(tenant, typ, &normalize::index_form(typ, value));
        if let Some(token) = self.store.token_for_index(tenant, &bi).await? {
            return Ok(token);
        }

        // Repli sur l'index historique (chaîne brute) : les jetons créés avant
        // la normalisation sont rangés sous cet index-là. On les retrouve, et
        // on rattache la forme canonique au même jeton pour que la variante
        // d'écriture suivante n'ait plus à faire ce détour.
        let legacy = self.keyring.blind_index(tenant, typ, value);
        if legacy != bi {
            if let Some(token) = self.store.token_for_index(tenant, &legacy).await? {
                self.store.alias_index(tenant, &bi, &token).await?;
                return Ok(token);
            }
        }

        let blob = self.keyring.encrypt(value);
        self.store.create_token(tenant, typ, &bi, &blob).await
    }

    /// Rattache la forme canonique de chaque valeur déjà au coffre à son jeton.
    ///
    /// Nécessaire une fois, pour les documents indexés AVANT la normalisation :
    /// leur jeton est rangé sous l'index de la chaîne brute, qu'une question
    /// écrite autrement ne reproduit pas. Sans ce rattrapage, il faudrait
    /// réimporter les documents.
    ///
    /// Purement additif : aucune valeur n'est modifiée, aucun jeton n'est créé.
    /// Rejouable sans effet de bord.
    pub async fn reindex(&self, tenant: &str) -> Result<(usize, usize), VaultError> {
        let entries = self.store.tokens(tenant).await?;
        let total = entries.len();
        let mut aliased = 0usize;

        for (token, blob) in entries {
            // Le type vit dans le nom du jeton : « PERSON_12 » -> « PERSON ».
            let Some(typ) = token.rsplit_once('_').map(|(t, _)| t) else {
                continue;
            };
            let Some(value) = self.keyring.decrypt(&blob) else {
                continue; // blob d'une ancienne clé : on le laisse tel quel
            };
            let canonical = normalize::index_form(typ, &value);
            let bi = self.keyring.blind_index(tenant, typ, &canonical);
            if self.store.token_for_index(tenant, &bi).await?.is_none() {
                self.store.alias_index(tenant, &bi, &token).await?;
                aliased += 1;
            }
        }
        Ok((total, aliased))
    }

    /// Remplace les données sensibles par des jetons. Renvoie le texte « propre »
    /// (envoyable au LLM) et la liste des jetons créés/utilisés.
    pub async fn pseudonymize(
        &self,
        tenant: &str,
        text: &str,
        custom: &[CustomTerm],
    ) -> Result<(String, Vec<String>), VaultError> {
        // 1) Collecte de TOUTES les correspondances sur le texte d'origine
        //    (termes fournis + regex), avec leurs plages d'octets. On ne mute pas
        //    le texte pendant la détection (fini les collisions de sous-chaînes /
        //    l'ordre de remplacement sensible de l'ancien `out.replace`).
        let mut hits: Vec<Hit> = Vec::new();
        for t in custom {
            if t.value.is_empty() {
                continue;
            }
            for (start, sub) in text.match_indices(t.value.as_str()) {
                hits.push(Hit {
                    start,
                    end: start + sub.len(),
                    typ: t.typ.clone(),
                    value: t.value.clone(),
                    strict: false,
                });
            }
        }
        for (typ, rx) in PATTERNS.iter() {
            for m in rx.find_iter(text) {
                hits.push(Hit {
                    start: m.start(),
                    end: m.end(),
                    typ: (*typ).to_string(),
                    value: m.as_str().to_string(),
                    strict: true,
                });
            }
        }

        // 2) Résolution des chevauchements : les détecteurs à format strict
        //    d'abord, puis « la plus longue gagne ». Toute correspondance qui en
        //    chevauche une déjà retenue est écartée (ex. « Marie » est écarté au
        //    profit de « Marie Dupont »).
        //
        //    Pourquoi le format strict prime : le NER étiquette parfois une
        //    adresse e-mail comme LOCATION (constaté avec le modèle français de
        //    Presidio sur `marie.dupont@gmail.com`, même plage exacte que la
        //    regex). La donnée restait masquée, mais sous un type faux. Une regex
        //    d'e-mail/IBAN/carte ne se trompe pas sur la nature de ce qu'elle
        //    reconnaît, contrairement à un modèle statistique.
        hits.sort_by(|a, b| {
            b.strict
                .cmp(&a.strict)
                .then((b.end - b.start).cmp(&(a.end - a.start)))
                .then(a.start.cmp(&b.start))
        });
        let mut selected: Vec<Hit> = Vec::new();
        for h in hits {
            let overlaps = selected.iter().any(|s| h.start < s.end && s.start < h.end);
            if !overlaps {
                selected.push(h);
            }
        }

        // 3) Découpage dans l'ordre du texte : on insère chaque jeton par plage.
        selected.sort_by_key(|h| h.start);
        let mut out = String::with_capacity(text.len());
        let mut tokens = Vec::new();
        let mut seen = HashSet::new();
        let mut cursor = 0usize;
        for h in &selected {
            out.push_str(&text[cursor..h.start]);
            let tok = self.token_for(tenant, &h.typ, &h.value).await?;
            out.push('[');
            out.push_str(&tok);
            out.push(']');
            if seen.insert(tok.clone()) {
                tokens.push(tok);
            }
            cursor = h.end;
        }
        out.push_str(&text[cursor..]);

        Ok((out, tokens))
    }

    /// Remplace chaque `[TYPE_N]` par sa valeur réelle déchiffrée. Les jetons
    /// inconnus (mauvais tenant, jamais créés…) sont laissés tels quels — aucune
    /// fuite cross-tenant possible.
    pub async fn depseudonymize(&self, tenant: &str, text: &str) -> Result<String, VaultError> {
        let mut result = String::with_capacity(text.len());
        let mut last = 0usize;
        for caps in TOKEN_RE.captures_iter(text) {
            // Le groupe 0 (match complet) existe toujours pour une capture.
            let whole = match caps.get(0) {
                Some(m) => m,
                None => continue,
            };
            let token = caps.get(1).map(|g| g.as_str()).unwrap_or("");
            result.push_str(&text[last..whole.start()]);
            match self.store.blob_for_token(tenant, token).await? {
                Some(blob) => match self.keyring.decrypt(&blob) {
                    Some(value) => result.push_str(&value),
                    None => result.push_str(whole.as_str()),
                },
                None => result.push_str(whole.as_str()),
            }
            last = whole.end();
        }
        result.push_str(&text[last..]);
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::InMemoryVaultStore;

    fn vault() -> Vault {
        let keyring = Keyring::from_master(&[7u8; 32]);
        Vault::new(keyring, Arc::new(InMemoryVaultStore::new()))
    }

    #[tokio::test]
    async fn round_trip_texte_francais_accentue() {
        let v = vault();
        let terms = vec![CustomTerm {
            typ: "PERSON".into(),
            value: "Hélène Béa".into(),
        }];
        let text = "Hélène Béa a écrit à marie@example.fr, IBAN FR76 3000 1007 9412.";
        let (clean, tokens) = v.pseudonymize("_global", text, &terms).await.unwrap();

        assert!(!clean.contains("Hélène Béa"), "le nom ne doit plus apparaître");
        assert!(!clean.contains("marie@example.fr"), "l'email ne doit plus apparaître");
        assert!(clean.contains("[PERSON_1]"));
        assert!(tokens.contains(&"PERSON_1".to_string()));

        let restored = v.depseudonymize("_global", &clean).await.unwrap();
        assert_eq!(restored, text, "le round-trip doit restituer l'original exact");
    }

    /// Le cas qui a motivé la normalisation (30/10/2026).
    ///
    /// Un CV est indexé avec « MAMADOU SOUMARE ». L'utilisateur demande ensuite
    /// « qui est soumare mamadou ? ». Avant la forme canonique, les deux
    /// écritures recevaient deux jetons différents : le modèle lisait un
    /// contexte sur [PERSON_1] et une question sur [PERSON_2], et répondait que
    /// l'information ne s'y trouvait pas — alors que le bon document avait bien
    /// été retrouvé et cité en source.
    #[tokio::test]
    async fn une_question_retrouve_le_nom_du_document_quelle_que_soit_l_ecriture() {
        let v = vault();
        let nom = |valeur: &str| {
            vec![CustomTerm {
                typ: "PERSON".into(),
                value: valeur.into(),
            }]
        };

        let (cv, _) = v
            .pseudonymize("t1", "MAMADOU SOUMARE — développeur full stack", &nom("MAMADOU SOUMARE"))
            .await
            .unwrap();
        let (question, _) = v
            .pseudonymize("t1", "qui est soumare mamadou ?", &nom("soumare mamadou"))
            .await
            .unwrap();

        assert!(cv.contains("[PERSON_1]"), "le CV : {cv}");
        assert!(
            question.contains("[PERSON_1]"),
            "la question doit porter sur le MÊME jeton que le document : {question}"
        );
    }

    /// La restitution rend l'orthographe d'origine, pas la forme d'index.
    #[tokio::test]
    async fn la_forme_canonique_ne_deteint_pas_sur_la_valeur_restituee() {
        let v = vault();
        let terms = vec![CustomTerm {
            typ: "PERSON".into(),
            value: "MAMADOU SOUMARE".into(),
        }];
        let (clean, _) = v.pseudonymize("t1", "Signé MAMADOU SOUMARE", &terms).await.unwrap();
        let restored = v.depseudonymize("t1", &clean).await.unwrap();
        assert_eq!(restored, "Signé MAMADOU SOUMARE");
    }

    /// Un numéro écrit avec ou sans espaces est le même numéro.
    #[tokio::test]
    async fn un_telephone_garde_son_jeton_quelle_que_soit_sa_ponctuation() {
        let v = vault();
        let (a, _) = v.pseudonymize("t1", "tel 0611811814", &[]).await.unwrap();
        let (b, _) = v.pseudonymize("t1", "tel 06 11 81 18 14", &[]).await.unwrap();
        assert!(a.contains("[PHONE_1]"), "{a}");
        assert!(b.contains("[PHONE_1]"), "{b}");
    }

    /// Le rattrapage relie les jetons d'avant la normalisation.
    ///
    /// On simule l'existant en rangeant un jeton sous l'index de la chaîne
    /// brute, comme le faisait l'ancienne version, puis on vérifie qu'après
    /// `reindex` une autre écriture retrouve ce jeton-là.
    #[tokio::test]
    async fn le_rattrapage_relie_les_jetons_deja_crees() {
        let keyring = Keyring::from_master(&[9u8; 32]);
        let store = Arc::new(InMemoryVaultStore::new());

        // Ancien schéma : index = HMAC de la chaîne brute.
        let brut = keyring.blind_index("t1", "PERSON", "MAMADOU SOUMARE");
        let blob = keyring.encrypt("MAMADOU SOUMARE");
        let token = store.create_token("t1", "PERSON", &brut, &blob).await.unwrap();

        let v = Vault::new(keyring, store);
        let (examines, rattaches) = v.reindex("t1").await.unwrap();
        assert_eq!(examines, 1);
        assert_eq!(rattaches, 1);

        let terms = vec![CustomTerm {
            typ: "PERSON".into(),
            value: "soumare mamadou".into(),
        }];
        let (question, _) = v.pseudonymize("t1", "qui est soumare mamadou ?", &terms).await.unwrap();
        assert!(
            question.contains(&format!("[{token}]")),
            "la question doit retomber sur le jeton existant {token} : {question}"
        );
    }

    #[tokio::test]
    async fn meme_valeur_meme_jeton() {
        let v = vault();
        let (clean, _) = v
            .pseudonymize("_global", "a@b.fr puis encore a@b.fr", &[])
            .await
            .unwrap();
        assert_eq!(clean, "[EMAIL_1] puis encore [EMAIL_1]");
    }

    #[tokio::test]
    async fn chevauchement_la_plus_longue_gagne() {
        let v = vault();
        // « Marie » est inclus dans « Marie Dupont » : seul le plus long est jetonné,
        // pas de « [PERSON_x] Dupont » bancal.
        let terms = vec![
            CustomTerm { typ: "PERSON".into(), value: "Marie".into() },
            CustomTerm { typ: "PERSON".into(), value: "Marie Dupont".into() },
        ];
        let (clean, tokens) = v
            .pseudonymize("_global", "Marie Dupont arrive demain", &terms)
            .await
            .unwrap();
        assert_eq!(clean, "[PERSON_1] arrive demain");
        assert_eq!(tokens, vec!["PERSON_1".to_string()]);
    }

    /// Le NER (Presidio FR) étiquette parfois une adresse e-mail comme LOCATION,
    /// sur la plage exacte de la regex. Le format strict doit l'emporter, sinon
    /// l'e-mail sort en `[LOC_n]` — masqué, mais sous un type faux.
    #[tokio::test]
    async fn format_strict_prime_sur_le_ner() {
        let v = vault();
        let terms = vec![
            CustomTerm { typ: "LOC".into(), value: "marie.dupont@gmail.com".into() },
            // Même cas avec un terme plus long que la regex.
            CustomTerm { typ: "LOC".into(), value: "au 06 12 34 56 78".into() },
        ];
        let (clean, _) = v
            .pseudonymize(
                "_global",
                "Ecrire a marie.dupont@gmail.com ou au 06 12 34 56 78",
                &terms,
            )
            .await
            .unwrap();
        assert_eq!(clean, "Ecrire a [EMAIL_1] ou au [PHONE_1]");
    }

    #[tokio::test]
    async fn jeton_inconnu_laisse_tel_quel() {
        let v = vault();
        let out = v
            .depseudonymize("_global", "Voir [PERSON_9] svp")
            .await
            .unwrap();
        assert_eq!(out, "Voir [PERSON_9] svp");
    }

    #[tokio::test]
    async fn isolation_tenant_pas_de_restitution_croisee() {
        let v = vault();
        // Le tenant A jetonne un secret -> EMAIL_1.
        let (clean_a, _) = v.pseudonymize("A", "secret-a@x.fr", &[]).await.unwrap();
        assert_eq!(clean_a, "[EMAIL_1]");

        // Le tenant B demande à restituer le MÊME libellé de jeton : il n'a jamais
        // créé EMAIL_1 -> aucune fuite, le jeton reste tel quel.
        let out_b = v.depseudonymize("B", "[EMAIL_1]").await.unwrap();
        assert_eq!(out_b, "[EMAIL_1]");

        // A restitue correctement le sien.
        let out_a = v.depseudonymize("A", "[EMAIL_1]").await.unwrap();
        assert_eq!(out_a, "secret-a@x.fr");
    }
}
