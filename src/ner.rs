//! Client pour le service NER Microsoft Presidio.
//!
//! Détecte les entités que la regex ne sait pas reconnaître (noms de personnes,
//! organisations, lieux…). Configurable par variables d'environnement :
//!   PRESIDIO_URL   (défaut http://127.0.0.1:5002)
//!   PRESIDIO_LANG  (défaut en)

use serde::Deserialize;

#[derive(Deserialize, Debug)]
pub struct PresidioEntity {
    pub entity_type: String,
    /// ATTENTION : Presidio renvoie des index en CARACTÈRES (offsets Python),
    /// pas en octets. On les convertit côté Rust (voir `char_slice`).
    pub start: usize,
    pub end: usize,
    pub score: f32,
}

fn presidio_url() -> String {
    std::env::var("PRESIDIO_URL").unwrap_or_else(|_| "http://127.0.0.1:5002".to_string())
}

fn presidio_lang() -> String {
    std::env::var("PRESIDIO_LANG").unwrap_or_else(|_| "en".to_string())
}

/// Appelle Presidio /analyze. Renvoie les entités détectées.
pub async fn analyze(text: &str) -> Result<Vec<PresidioEntity>, reqwest::Error> {
    let client = reqwest::Client::new();
    client
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
