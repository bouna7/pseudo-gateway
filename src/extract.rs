//! Extracteur JSON dont les refus sortent au **même format** que les autres
//! erreurs de l'API (`{ "error": …, "message": … }`).
//!
//! `axum::Json` répond sinon en texte brut et en anglais — acceptable pour un
//! service interne, pas pour une API publique dont les clients parsent du JSON.
//! On en profite pour expliquer le cas le plus fréquent : un corps envoyé dans
//! l'encodage Windows (cp1252) au lieu d'UTF-8, que JSON impose.

use crate::error::AppError;
use async_trait::async_trait;
use axum::extract::rejection::JsonRejection;
use axum::extract::{FromRequest, Request};

pub struct ApiJson<T>(pub T);

#[async_trait]
impl<S, T> FromRequest<S> for ApiJson<T>
where
    axum::Json<T>: FromRequest<S, Rejection = JsonRejection>,
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        match axum::Json::<T>::from_request(req, state).await {
            Ok(axum::Json(value)) => Ok(ApiJson(value)),
            Err(rejection) => Err(to_error(&rejection)),
        }
    }
}

fn to_error(rejection: &JsonRejection) -> AppError {
    let detail = rejection.body_text();
    match rejection {
        JsonRejection::MissingJsonContentType(_) => AppError::UnsupportedMediaType,
        // Corps plus gros que MAX_BODY_BYTES (ou lecture interrompue).
        JsonRejection::BytesRejection(_) => AppError::PayloadTooLarge,
        JsonRejection::JsonSyntaxError(_) if is_encoding_issue(&detail) => AppError::BadRequest(
            format!("corps JSON invalide : il doit être encodé en UTF-8 ({detail})"),
        ),
        JsonRejection::JsonSyntaxError(_) => AppError::BadRequest(format!(
            "corps JSON malformé : vérifiez les accolades, les virgules et les \
             guillemets ({detail})"
        )),
        // Le JSON est valide, mais un champ manque ou n'a pas le bon type.
        JsonRejection::JsonDataError(_) => AppError::BadRequest(explique_champ(&detail)),
        _ => AppError::BadRequest(detail),
    }
}

/// Traduit le message de `serde` en indication exploitable. Il dit par exemple
/// « missing field `text` at line 1 column 13 » : exact, mais en anglais et
/// noyé dans du vocabulaire de bibliothèque.
fn explique_champ(detail: &str) -> String {
    if let Some(champ) = entre_accents_graves(detail, "missing field ") {
        return format!("champ obligatoire manquant : « {champ} »");
    }
    if let Some((champ, attendu, recu)) = type_incorrect(detail) {
        // « attendu X, reçu Y » plutôt que « X attendu » : évite les accords
        // fautifs (« une liste attendu ») sans table de genres.
        return format!("champ « {champ} » : attendu {attendu}, reçu {recu}");
    }
    format!("champ invalide : {detail}")
}

/// Valeur citée entre accents graves qui suit `apres`.
fn entre_accents_graves(detail: &str, apres: &str) -> Option<String> {
    let reste = detail.split_once(apres)?.1;
    let reste = reste.strip_prefix('`')?;
    let (valeur, _) = reste.split_once('`')?;
    Some(valeur.to_string())
}

/// Extrait (champ, type attendu, type reçu) de « …: <champ>: invalid type:
/// <reçu> `…`, expected <attendu> at line … ».
fn type_incorrect(detail: &str) -> Option<(String, String, String)> {
    let (avant, apres) = detail.split_once(": invalid type: ")?;
    let champ = avant.rsplit(':').next()?.trim().to_string();
    let (recu, apres) = apres.split_once(", expected ")?;
    let attendu = apres.split(" at line").next()?.trim();
    let recu = recu.split(' ').next()?.trim();
    Some((champ, traduire_type(attendu), traduire_type(recu)))
}

/// Les types de `serde` tels qu'un appelant les comprend.
fn traduire_type(t: &str) -> String {
    let t = t.trim_start_matches("a ").trim_start_matches("an ");
    match t {
        "string" => "un texte",
        "integer" | "u32" | "u64" | "i64" => "un nombre entier",
        "float" | "f64" => "un nombre",
        "boolean" => "un booléen (true/false)",
        "sequence" => "une liste",
        "map" => "un objet",
        "null" | "unit value" => "une valeur vide",
        autre => return autre.to_string(),
    }
    .to_string()
}

/// `serde_json` signale un octet non-UTF-8 ainsi ; c'est le symptôme d'un corps
/// envoyé en cp1252 / latin-1 (terminal Windows, vieux client HTTP).
fn is_encoding_issue(detail: &str) -> bool {
    let d = detail.to_ascii_lowercase();
    d.contains("invalid unicode code point") || d.contains("invalid utf-8")
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::header;

    async fn reject(content_type: Option<&str>, body: Vec<u8>) -> AppError {
        let mut req = Request::builder().method("POST").uri("/");
        if let Some(ct) = content_type {
            req = req.header(header::CONTENT_TYPE, ct);
        }
        let req = req.body(Body::from(body)).unwrap();
        ApiJson::<serde_json::Value>::from_request(req, &())
            .await
            .err()
            .expect("doit être refusé")
    }

    #[tokio::test]
    async fn corps_latin1_explique_l_encodage() {
        // « é » en cp1252 (0xE9) : invalide en UTF-8.
        let mut body = br#"{"text": "caf"#.to_vec();
        body.extend_from_slice(&[0xE9, b'"', b'}']);
        let err = reject(Some("application/json"), body).await;
        let msg = err.to_string();
        assert!(matches!(err, AppError::BadRequest(_)), "{msg}");
        assert!(msg.contains("UTF-8"), "{msg}");
    }

    /// Corps attendu par l'API : un champ `text` obligatoire.
    #[derive(serde::Deserialize)]
    struct Exemple {
        #[allow(dead_code)]
        text: String,
    }

    async fn reject_typed(body: &[u8]) -> AppError {
        let req = Request::builder()
            .method("POST")
            .uri("/")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_vec()))
            .unwrap();
        ApiJson::<Exemple>::from_request(req, &())
            .await
            .err()
            .expect("doit être refusé")
    }

    /// Le message doit dire LEQUEL des trois cas : la clé, un champ, ou le JSON.
    #[tokio::test]
    async fn champ_manquant_ou_mal_type_nomme_le_champ() {
        let err = reject_typed(br#"{"texte":"a"}"#).await;
        assert_eq!(
            err.to_string(),
            "requête invalide : champ obligatoire manquant : « text »"
        );

        let err = reject_typed(br#"{"text":123}"#).await;
        assert_eq!(
            err.to_string(),
            "requête invalide : champ « text » : attendu un texte, reçu un nombre entier"
        );

        // Un JSON cassé n'est pas un problème de champ.
        let err = reject_typed(br#"{"text":"#).await;
        assert!(err.to_string().contains("malformé"), "{err}");
    }

    #[tokio::test]
    async fn json_malforme_et_content_type_manquant() {
        assert!(matches!(
            reject(Some("application/json"), b"{pas du json".to_vec()).await,
            AppError::BadRequest(_)
        ));
        assert!(matches!(
            reject(None, b"{}".to_vec()).await,
            AppError::UnsupportedMediaType
        ));
    }
}
