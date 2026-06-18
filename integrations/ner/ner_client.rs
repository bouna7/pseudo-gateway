//! Client Rust de référence pour Microsoft Presidio.
//!
//! NON inclus dans le build de la passerelle pour ne pas casser votre projet
//! actuel. Pour l'activer :
//!   1. Ajoutez au Cargo.toml :  reqwest = { version = "0.12", features = ["json"] }
//!   2. Copiez ce fichier en  src/ner.rs  et ajoutez  mod ner;  dans main.rs
//!   3. Câblez analyze() dans le flux /pseudonymize (voir note en bas).

use serde::Deserialize;

/// Entité renvoyée par Presidio (/analyze). `start`/`end` sont des index d'octets
/// dans le texte d'origine ; on découpe le texte pour récupérer la valeur réelle.
#[derive(Deserialize, Debug)]
pub struct PresidioEntity {
    pub entity_type: String,
    pub start: usize,
    pub end: usize,
    pub score: f32,
}

/// Appelle Presidio et renvoie les entités détectées (PERSON, LOCATION, etc.).
pub async fn analyze(text: &str) -> Result<Vec<PresidioEntity>, reqwest::Error> {
    let client = reqwest::Client::new();
    client
        .post("http://127.0.0.1:5002/analyze")
        .json(&serde_json::json!({
            "text": text,
            "language": "en",      // "fr" si vous avez configuré le modèle français
            "score_threshold": 0.5
        }))
        .send()
        .await?
        .json::<Vec<PresidioEntity>>()
        .await
}

/// Convertit les entités Presidio en couples (TYPE, valeur), prêts à être jetonnés
/// exactement comme les `custom_terms`.
pub fn to_terms(text: &str, entities: &[PresidioEntity]) -> Vec<(String, String)> {
    entities
        .iter()
        .filter_map(|e| {
            text.get(e.start..e.end)
                .map(|v| (e.entity_type.clone(), v.to_string()))
        })
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// INTÉGRATION dans /pseudonymize :
//
// La détection devient asynchrone, donc appelez Presidio AVANT de prendre le
// verrou du coffre :
//
//   let entities = ner::analyze(&req.text).await.unwrap_or_default();
//   let ner_terms = ner::to_terms(&req.text, &entities);
//   // fusionnez ner_terms avec req.custom_terms, puis :
//   let mut vault = state.vault.lock().unwrap();
//   let (text, tokens) = vault.pseudonymize(&req.text, &all_terms);
//
// Mappez les types Presidio vers les vôtres si besoin (ex. NRP/ORGANIZATION -> ORG,
// PERSON -> PERSON, LOCATION -> LOC).
// ─────────────────────────────────────────────────────────────────────────────
