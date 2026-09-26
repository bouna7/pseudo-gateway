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
        JsonRejection::JsonSyntaxError(_) => AppError::BadRequest(format!("corps JSON invalide : {detail}")),
        // Champ manquant ou type incorrect.
        _ => AppError::BadRequest(detail),
    }
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
