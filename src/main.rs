//! Passerelle de pseudonymisation chiffrée.
//!
//! Deux endpoints HTTP :
//!   POST /pseudonymize   { text, custom_terms?, tenant_id? } -> { text, tokens }
//!   POST /depseudonymize { text, tenant_id? }                -> { text }
//!   GET  /health                                             -> "ok"
//!
//! Le coffre (jeton <-> valeur réelle chiffrée AES-256-GCM) est désormais derrière
//! le trait `VaultStore`. Phase 1 : `InMemoryVaultStore` (perdu au redémarrage).
//! Phase 2 : `RedisVaultStore` persistant, sélectionnable par configuration.

mod crypto;
mod error;
mod keys;
mod ner;
mod pseudonymize;
mod store;

use axum::{
    extract::State,
    response::Html,
    routing::{get, post},
    Json, Router,
};
use error::AppError;
use keys::{EnvKeyProvider, KeyProvider};
use pseudonymize::{CustomTerm, Vault};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use store::{InMemoryVaultStore, RedisVaultStore, VaultStore};

/// Espace de jetons par défaut quand l'appelant ne fournit pas de `tenant_id`
/// (rétro-compatibilité avec l'API d'origine).
const DEFAULT_TENANT: &str = "_global";

#[derive(Clone)]
struct AppState {
    vault: Arc<Vault>,
}

#[derive(Deserialize)]
struct CustomTermDto {
    #[serde(rename = "type")]
    typ: String,
    value: String,
}

#[derive(Deserialize)]
struct PseudoReq {
    text: String,
    #[serde(default)]
    custom_terms: Vec<CustomTermDto>,
    /// Espace de jetons (isolation par client/document). Optionnel.
    #[serde(default)]
    tenant_id: Option<String>,
}

#[derive(Serialize)]
struct PseudoResp {
    text: String,
    tokens: Vec<String>,
}

#[derive(Deserialize)]
struct DepseudoReq {
    text: String,
    #[serde(default)]
    tenant_id: Option<String>,
}

#[derive(Serialize)]
struct DepseudoResp {
    text: String,
}

async fn index() -> Html<&'static str> {
    Html(
        "<h1>Passerelle de pseudonymisation</h1>\
         <p>Le service fonctionne. Les endpoints sont en <b>POST</b> :</p>\
         <ul>\
           <li><code>POST /pseudonymize</code> — jetonne + chiffre</li>\
           <li><code>POST /depseudonymize</code> — restitue les valeurs réelles</li>\
           <li><code>GET /health</code> — sonde de disponibilité</li>\
         </ul>\
         <p>Testez avec <code>curl</code> ou <code>./test.sh</code> (un navigateur ne peut pas faire de POST).</p>",
    )
}

/// Sonde de disponibilité (utilisée par Dokploy / load balancer). Vérifie aussi
/// l'accès au store (PING Redis) → 503 si le backend est injoignable.
async fn health(State(st): State<AppState>) -> Result<&'static str, AppError> {
    st.vault.ping().await?;
    Ok("ok")
}

async fn pseudonymize_handler(
    State(st): State<AppState>,
    Json(req): Json<PseudoReq>,
) -> Result<Json<PseudoResp>, AppError> {
    let tenant = req.tenant_id.as_deref().unwrap_or(DEFAULT_TENANT);

    // 1) Termes fournis manuellement par l'appelant.
    let mut terms: Vec<CustomTerm> = req
        .custom_terms
        .into_iter()
        .map(|c| CustomTerm {
            typ: c.typ,
            value: c.value,
        })
        .collect();

    // 2) Détection automatique (NER) via Presidio. Best effort : si le service est
    //    indisponible, on continue avec la regex + les termes manuels.
    match ner::analyze(&req.text).await {
        Ok(entities) => {
            for (typ, value) in ner::to_terms(&req.text, &entities) {
                terms.push(CustomTerm { typ, value });
            }
        }
        Err(e) => tracing::warn!(error = %e, "NER (Presidio) indisponible — repli regex + termes manuels"),
    }

    // 3) Jetonnage + chiffrement (la synchronisation vit dans le store).
    let (text, tokens) = st.vault.pseudonymize(tenant, &req.text, &terms).await?;
    tracing::info!(%tenant, tokens = tokens.len(), "pseudonymisation effectuée");
    Ok(Json(PseudoResp { text, tokens }))
}

async fn depseudonymize_handler(
    State(st): State<AppState>,
    Json(req): Json<DepseudoReq>,
) -> Result<Json<DepseudoResp>, AppError> {
    let tenant = req.tenant_id.as_deref().unwrap_or(DEFAULT_TENANT);
    let text = st.vault.depseudonymize(tenant, &req.text).await?;
    Ok(Json(DepseudoResp { text }))
}

#[tokio::main]
async fn main() {
    // Logs structurés ; niveau pilotable par RUST_LOG (défaut info).
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    // Chargement des clés via le fournisseur (env versionné aujourd'hui, Vault/KMS demain).
    let keyring = match EnvKeyProvider.load().await {
        Ok(k) => k,
        Err(e) => {
            tracing::error!(error = %e, "chargement des clés impossible — arrêt");
            std::process::exit(1);
        }
    };

    // Choix du backend de coffre : VAULT_STORE=redis pour la persistance, sinon mémoire.
    let store: Arc<dyn VaultStore> = match std::env::var("VAULT_STORE").as_deref() {
        Ok("redis") => {
            let url = std::env::var("REDIS_URL")
                .unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());
            match RedisVaultStore::connect(&url).await {
                Ok(s) => {
                    tracing::info!(%url, "coffre Redis connecté (persistant)");
                    Arc::new(s)
                }
                Err(e) => {
                    // Fail-fast : en mode redis, on ne démarre pas sur un coffre absent.
                    tracing::error!(error = %e, %url, "connexion Redis impossible — arrêt");
                    std::process::exit(1);
                }
            }
        }
        _ => {
            tracing::warn!("coffre EN MÉMOIRE (non persistant) — VAULT_STORE=redis pour la prod");
            Arc::new(InMemoryVaultStore::new())
        }
    };

    let state = AppState {
        vault: Arc::new(Vault::new(keyring, store)),
    };

    let app = Router::new()
        .route("/", get(index))
        .route("/health", get(health))
        .route("/pseudonymize", post(pseudonymize_handler))
        .route("/depseudonymize", post(depseudonymize_handler))
        .with_state(state);

    let addr = "0.0.0.0:8080";
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("impossible de se lier au port 8080");
    tracing::info!("Passerelle de pseudonymisation prête sur http://{addr}");
    axum::serve(listener, app)
        .await
        .expect("le serveur axum s'est arrêté");
}
