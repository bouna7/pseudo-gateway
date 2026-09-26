//! Types d'erreur de la passerelle.
//!
//! Objectif : plus aucun `.unwrap()` / `.expect()` sur le chemin d'une requête.
//! Les handlers renvoient `Result<_, AppError>` ; `AppError` sait se transformer
//! en réponse HTTP propre (code + corps JSON `{ error, message }`).

use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;
use thiserror::Error;

/// Erreurs de la couche de persistance (store du coffre).
#[derive(Debug, Error)]
pub enum VaultError {
    /// Un `Mutex` interne a été empoisonné par un panic d'un autre thread.
    #[error("verrou du coffre empoisonné")]
    Poisoned,
    /// Erreur remontée par le backend de stockage (Redis, Postgres…).
    #[error("erreur du store : {0}")]
    Store(String),
}

/// Erreur applicative, convertible en réponse HTTP.
#[derive(Debug, Error)]
pub enum AppError {
    /// Requête mal formée (valeur invalide côté appelant).
    #[error("requête invalide : {0}")]
    BadRequest(String),
    /// Clé d'API manquante ou invalide (endpoint protégé).
    #[error("clé d'API manquante ou invalide")]
    Unauthorized,
    /// Clé valide mais compte désactivé, ou action réservée à l'admin.
    #[error("accès refusé : {0}")]
    Forbidden(String),
    /// Ressource inexistante (compte, clé…).
    #[error("introuvable : {0}")]
    NotFound(String),
    /// Trop de requêtes sur la fenêtre courante (limite par minute / par IP).
    #[error("trop de requêtes, réessayez dans {retry_after} s")]
    RateLimited { retry_after: u64 },
    /// Quota mensuel du compte épuisé.
    #[error("quota mensuel atteint ({limit} requêtes)")]
    QuotaExceeded { limit: u64 },
    /// Fonctionnalité non activée sur cette instance (ex. inscription publique).
    #[error("fonctionnalité désactivée sur cette instance")]
    Disabled,
    /// Corps envoyé sans `Content-Type: application/json`.
    #[error("en-tête « Content-Type: application/json » attendu")]
    UnsupportedMediaType,
    /// Corps plus gros que `MAX_BODY_BYTES`.
    #[error("corps de requête trop volumineux")]
    PayloadTooLarge,
    /// Route inconnue.
    #[error("endpoint inconnu : {0}")]
    UnknownRoute(String),
    /// Bonne route, mauvaise méthode HTTP.
    #[error("méthode non autorisée sur cet endpoint : {0}")]
    MethodNotAllowed(String),
    /// Erreur interne du coffre.
    #[error(transparent)]
    Vault(#[from] VaultError),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, code) = match &self {
            AppError::BadRequest(_) => (StatusCode::BAD_REQUEST, "bad_request"),
            AppError::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            AppError::Forbidden(_) => (StatusCode::FORBIDDEN, "forbidden"),
            AppError::NotFound(_) => (StatusCode::NOT_FOUND, "not_found"),
            AppError::RateLimited { .. } => (StatusCode::TOO_MANY_REQUESTS, "rate_limited"),
            AppError::QuotaExceeded { .. } => (StatusCode::TOO_MANY_REQUESTS, "quota_exceeded"),
            AppError::Disabled => (StatusCode::NOT_FOUND, "disabled"),
            AppError::UnsupportedMediaType => {
                (StatusCode::UNSUPPORTED_MEDIA_TYPE, "unsupported_media_type")
            }
            AppError::PayloadTooLarge => (StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large"),
            AppError::UnknownRoute(_) => (StatusCode::NOT_FOUND, "not_found"),
            AppError::MethodNotAllowed(_) => (StatusCode::METHOD_NOT_ALLOWED, "method_not_allowed"),
            AppError::Vault(_) => (StatusCode::INTERNAL_SERVER_ERROR, "vault_error"),
        };
        // On logge le message technique, jamais une valeur en clair.
        tracing::warn!(status = %status.as_u16(), error = %self, "requête échouée");
        let mut resp =
            (status, Json(json!({ "error": code, "message": self.to_string() }))).into_response();
        if let AppError::RateLimited { retry_after } = &self {
            if let Ok(v) = HeaderValue::from_str(&retry_after.to_string()) {
                resp.headers_mut().insert(header::RETRY_AFTER, v);
            }
        }
        resp
    }
}
