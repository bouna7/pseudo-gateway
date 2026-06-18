//! Types d'erreur de la passerelle.
//!
//! Objectif : plus aucun `.unwrap()` / `.expect()` sur le chemin d'une requête.
//! Les handlers renvoient `Result<_, AppError>` ; `AppError` sait se transformer
//! en réponse HTTP propre (code + corps JSON `{ error, message }`).

use axum::http::StatusCode;
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
    #[allow(dead_code)] // construit par RedisVaultStore (Phase 2)
    #[error("erreur du store : {0}")]
    Store(String),
}

/// Erreur applicative, convertible en réponse HTTP.
#[derive(Debug, Error)]
pub enum AppError {
    /// Requête mal formée (valeur invalide côté appelant).
    #[allow(dead_code)] // construit par la validation d'entrée (phases suivantes)
    #[error("requête invalide : {0}")]
    BadRequest(String),
    /// Clé d'API manquante ou invalide (endpoint protégé).
    #[error("clé d'API manquante ou invalide")]
    Unauthorized,
    /// Erreur interne du coffre.
    #[error(transparent)]
    Vault(#[from] VaultError),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, code) = match &self {
            AppError::BadRequest(_) => (StatusCode::BAD_REQUEST, "bad_request"),
            AppError::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            AppError::Vault(_) => (StatusCode::INTERNAL_SERVER_ERROR, "vault_error"),
        };
        // On logge le message technique, jamais une valeur en clair.
        tracing::warn!(status = %status.as_u16(), error = %self, "requête échouée");
        (status, Json(json!({ "error": code, "message": self.to_string() }))).into_response()
    }
}
