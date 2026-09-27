//! État partagé, configuration HTTP et assemblage du routeur.

use crate::accounts::Accounts;
use crate::pseudonymize::Vault;
use crate::{admin, api, auth};
use axum::extract::DefaultBodyLimit;
use axum::http::{header, HeaderName, HeaderValue, Method};
use axum::middleware::from_fn_with_state;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use std::sync::Arc;
use std::time::Duration;
use tower_http::cors::{AllowOrigin, Any, CorsLayer};
use tower_http::timeout::TimeoutLayer;
use utoipa::OpenApi;

#[derive(Clone)]
pub struct AppState {
    pub vault: Arc<Vault>,
    /// Clé interne historique (`GATEWAY_API_KEY`), tenant libre.
    pub api_key: Option<Arc<String>>,
    /// Clé d'administration (`ADMIN_API_KEY`) ; active aussi les comptes.
    pub admin_key: Option<Arc<String>>,
    /// Comptes de l'API publique (présent si `ADMIN_API_KEY` est définie).
    pub accounts: Option<Arc<Accounts>>,
    /// Inscriptions libres autorisées par IP et par heure (`PUBLIC_SIGNUP=true`).
    pub signup_per_hour: Option<u64>,
    /// Lire l'IP client dans `X-Forwarded-For` (derrière Traefik / nginx).
    pub trust_proxy: bool,
}

impl AppState {
    /// Aucune clé configurée : instance de développement, sans authentification.
    pub fn open_mode(&self) -> bool {
        self.api_key.is_none() && self.accounts.is_none()
    }
}

/// Réglages de la couche HTTP.
pub struct HttpConfig {
    pub max_body_bytes: usize,
    pub request_timeout: Duration,
    /// `None` = pas d'en-têtes CORS ; `Some(vec!["*"])` = toutes origines.
    pub cors_origins: Option<Vec<String>>,
    pub docs: bool,
    /// URL publique annoncée dans la spec OpenAPI (ex. https://api.exemple.fr).
    pub public_base_url: Option<String>,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            max_body_bytes: 1024 * 1024,
            request_timeout: Duration::from_secs(30),
            cors_origins: None,
            docs: false,
            public_base_url: None,
        }
    }
}

fn cors_layer(origins: &[String]) -> CorsLayer {
    let layer = CorsLayer::new()
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PATCH,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([
            header::CONTENT_TYPE,
            header::AUTHORIZATION,
            HeaderName::from_static("x-api-key"),
            HeaderName::from_static("x-admin-key"),
        ])
        .expose_headers([header::RETRY_AFTER])
        .max_age(Duration::from_secs(3600));
    if origins.iter().any(|o| o == "*") {
        layer.allow_origin(Any)
    } else {
        let list: Vec<HeaderValue> = origins
            .iter()
            .filter_map(|o| match HeaderValue::from_str(o) {
                Ok(v) => Some(v),
                Err(_) => {
                    tracing::warn!(origin = %o, "origine CORS invalide ignorée");
                    None
                }
            })
            .collect();
        layer.allow_origin(AllowOrigin::list(list))
    }
}

pub fn router(state: AppState, cfg: &HttpConfig) -> Router {
    let counted = Router::new()
        .route("/v1/pseudonymize", post(api::pseudonymize))
        .route("/v1/depseudonymize", post(api::depseudonymize))
        // Chemins historiques, conservés pour les clients existants.
        .route("/pseudonymize", post(api::pseudonymize))
        .route("/depseudonymize", post(api::depseudonymize))
        .route_layer(from_fn_with_state(state.clone(), auth::require_api_key));

    let uncounted = Router::new()
        .route("/v1/me", get(api::me))
        .route_layer(from_fn_with_state(
            state.clone(),
            auth::require_api_key_uncounted,
        ));

    let mut app = Router::new()
        .route("/health", get(api::health))
        .route("/v1/signup", post(api::signup))
        .merge(counted)
        .merge(uncounted);

    if state.admin_key.is_some() {
        let admin_routes = Router::new()
            .route(
                "/admin/accounts",
                post(admin::create_account).get(admin::list_accounts),
            )
            .route(
                "/admin/accounts/:id",
                get(admin::get_account).patch(admin::update_account),
            )
            .route("/admin/accounts/:id/keys", post(admin::issue_key))
            .route("/admin/accounts/:id/keys/:key_id", delete(admin::revoke_key))
            .route_layer(from_fn_with_state(state.clone(), auth::require_admin));
        app = app.merge(admin_routes);
    }

    if cfg.docs {
        let mut spec = api::ApiDoc::openapi();
        spec.info.version = env!("CARGO_PKG_VERSION").to_string();
        if let Some(url) = &cfg.public_base_url {
            spec.servers = Some(vec![utoipa::openapi::Server::new(url)]);
        }
        let spec = Arc::new(spec);
        app = app
            // Ouvrir la racine dans un navigateur donnait « endpoint inconnu »,
            // ce qui laisse croire à un service cassé. Quand la documentation est
            // publiée, `/` y mène ; sinon la racine reste muette (pas de
            // divulgation sur une instance de production).
            .route(
                "/",
                get(|| async { axum::response::Redirect::temporary("/docs") }),
            )
            .route(
                "/openapi.json",
                get(move || {
                    let spec = spec.clone();
                    async move { Json((*spec).clone()) }
                }),
            )
            .route("/docs", get(api::docs));
    }

    let mut app = app
        // Route inconnue / mauvaise méthode : même format d'erreur que le reste.
        .fallback(|method: axum::http::Method, uri: axum::http::Uri| async move {
            crate::error::AppError::UnknownRoute(format!("{method} {}", uri.path()))
        })
        .method_not_allowed_fallback(|method: axum::http::Method, uri: axum::http::Uri| async move {
            crate::error::AppError::MethodNotAllowed(format!("{method} {}", uri.path()))
        })
        .with_state(state)
        .layer(DefaultBodyLimit::max(cfg.max_body_bytes))
        .layer(TimeoutLayer::new(cfg.request_timeout));
    if let Some(origins) = &cfg.cors_origins {
        // En dernier = couche la plus externe : répond aux pré-requêtes OPTIONS
        // avant l'authentification.
        app = app.layer(cors_layer(origins));
    }
    app
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::{InMemoryAccountStore, PlanDefaults};
    use crate::keys::Keyring;
    use crate::store::InMemoryVaultStore;
    use axum::body::{to_bytes, Body};
    use axum::http::{Request, StatusCode};
    use serde_json::{json, Value};
    use tower::ServiceExt;

    fn state(rate: u32) -> AppState {
        let vault = Vault::new(
            Keyring::from_master(&[7u8; 32]),
            Arc::new(InMemoryVaultStore::new()),
        );
        let accounts = Accounts::new(
            Arc::new(InMemoryAccountStore::new()),
            PlanDefaults {
                plan: "free".into(),
                rate_per_min: rate,
                monthly_quota: 0,
            },
        );
        AppState {
            vault: Arc::new(vault),
            api_key: Some(Arc::new("interne".into())),
            admin_key: Some(Arc::new("admin".into())),
            accounts: Some(Arc::new(accounts)),
            signup_per_hour: Some(2),
            trust_proxy: false,
        }
    }

    fn app(st: AppState) -> Router {
        router(
            st,
            &HttpConfig {
                cors_origins: Some(vec!["*".into()]),
                docs: true,
                ..Default::default()
            },
        )
    }

    async fn call(app: &Router, method: &str, uri: &str, auth: Option<(&str, &str)>, body: Value) -> (StatusCode, Value) {
        let mut req = Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json");
        if let Some((h, v)) = auth {
            req = req.header(h, v);
        }
        let resp = app
            .clone()
            .oneshot(req.body(Body::from(body.to_string())).unwrap())
            .await
            .unwrap();
        let status = resp.status();
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
    }

    #[tokio::test]
    async fn parcours_complet_compte_public() {
        std::env::set_var("PRESIDIO_URL", "http://127.0.0.1:1"); // NER indisponible → regex
        let app = app(state(0));

        // Sans clé → 401.
        let (s, _) = call(&app, "POST", "/v1/pseudonymize", None, json!({"text": "x"})).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED);

        // L'admin crée deux comptes.
        let (s, a) = call(&app, "POST", "/admin/accounts", Some(("x-admin-key", "admin")), json!({"name": "A"})).await;
        assert_eq!(s, StatusCode::CREATED);
        let key_a = format!("Bearer {}", a["api_key"].as_str().unwrap());
        let (_, b) = call(&app, "POST", "/admin/accounts", Some(("x-admin-key", "admin")), json!({"name": "B"})).await;
        let key_b = b["api_key"].as_str().unwrap().to_string();

        // A pseudonymise dans un sous-tenant de son compte.
        let (s, p) = call(&app, "POST", "/v1/pseudonymize", Some(("authorization", &key_a)),
            json!({"text": "Écrire à marie@exemple.fr", "tenant_id": "doc1"})).await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(p["text"], "Écrire à [EMAIL_1]");

        // A restitue ; B et la clé interne (sans le bon tenant) ne peuvent pas.
        let q = json!({"text": "[EMAIL_1]", "tenant_id": "doc1"});
        let (_, r) = call(&app, "POST", "/v1/depseudonymize", Some(("authorization", &key_a)), q.clone()).await;
        assert_eq!(r["text"], "marie@exemple.fr");
        let (_, r) = call(&app, "POST", "/v1/depseudonymize", Some(("x-api-key", &key_b)), q.clone()).await;
        assert_eq!(r["text"], "[EMAIL_1]");
        let (_, r) = call(&app, "POST", "/depseudonymize", Some(("x-api-key", "interne")), q).await;
        assert_eq!(r["text"], "[EMAIL_1]");

        // /v1/me renvoie le compte et la consommation.
        let (s, me) = call(&app, "GET", "/v1/me", Some(("authorization", &key_a)), json!({})).await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(me["account"]["id"], a["account"]["id"]);
        assert_eq!(me["usage"]["requests"], 2);
        assert!(me["account"]["keys"][0].get("hash").is_none());

        // Désactivation → 403.
        let id = a["account"]["id"].as_str().unwrap();
        let (s, _) = call(&app, "PATCH", &format!("/admin/accounts/{id}"), Some(("x-admin-key", "admin")), json!({"disabled": true})).await;
        assert_eq!(s, StatusCode::OK);
        let (s, _) = call(&app, "POST", "/v1/pseudonymize", Some(("authorization", &key_a)), json!({"text": "x"})).await;
        assert_eq!(s, StatusCode::FORBIDDEN);

        // Mauvaise clé admin → 401 ; la clé interne n'ouvre pas /admin.
        let (s, _) = call(&app, "GET", "/admin/accounts", Some(("x-admin-key", "interne")), json!({})).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED);
    }

    /// Toutes les erreurs — y compris celles du corps de requête et des routes
    /// inconnues — doivent sortir au format JSON `{ error, message }`.
    #[tokio::test]
    async fn erreurs_toujours_en_json() {
        let app = app(state(0));
        let auth = Some(("x-api-key", "interne"));

        // Corps en cp1252 (« é » = 0xE9) : message qui pointe l'encodage.
        let req = Request::builder()
            .method("POST")
            .uri("/v1/pseudonymize")
            .header("content-type", "application/json")
            .header("x-api-key", "interne")
            .body(Body::from({
                let mut b = br#"{"text": "caf"#.to_vec();
                b.extend_from_slice(&[0xE9, b'"', b'}']);
                b
            }))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["error"], "bad_request");
        assert!(body["message"].as_str().unwrap().contains("UTF-8"));

        // Champ obligatoire absent.
        let (s, e) = call(&app, "POST", "/v1/pseudonymize", auth, json!({})).await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        assert_eq!(e["error"], "bad_request");

        // Route inconnue et méthode non autorisée.
        let (s, e) = call(&app, "GET", "/v1/inconnu", auth, json!({})).await;
        assert_eq!(s, StatusCode::NOT_FOUND);
        assert_eq!(e["error"], "not_found");
        let (s, e) = call(&app, "GET", "/v1/pseudonymize", auth, json!({})).await;
        assert_eq!(s, StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(e["error"], "method_not_allowed");
    }

    #[tokio::test]
    async fn limite_par_minute_renvoie_429() {
        let app = app(state(1));
        let (_, a) = call(&app, "POST", "/admin/accounts", Some(("x-admin-key", "admin")), json!({"name": "A"})).await;
        let key = a["api_key"].as_str().unwrap().to_string();
        let (s, _) = call(&app, "POST", "/v1/depseudonymize", Some(("x-api-key", &key)), json!({"text": "x"})).await;
        assert_eq!(s, StatusCode::OK);
        let (s, e) = call(&app, "POST", "/v1/depseudonymize", Some(("x-api-key", &key)), json!({"text": "x"})).await;
        assert_eq!(s, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(e["error"], "rate_limited");
    }

    #[tokio::test]
    async fn inscription_limitee_par_ip_et_doc_publiee() {
        let app = app(state(0));
        let body = json!({"name": "Dev", "email": "dev@exemple.fr"});
        for _ in 0..2 {
            let (s, r) = call(&app, "POST", "/v1/signup", None, body.clone()).await;
            assert_eq!(s, StatusCode::CREATED);
            assert!(r["api_key"].as_str().unwrap().starts_with("pgw_"));
        }
        let (s, _) = call(&app, "POST", "/v1/signup", None, body).await;
        assert_eq!(s, StatusCode::TOO_MANY_REQUESTS);

        let (s, spec) = call(&app, "GET", "/openapi.json", None, json!({})).await;
        assert_eq!(s, StatusCode::OK);
        assert!(spec["paths"]["/v1/pseudonymize"].is_object());
    }

    /// La racine mène à la documentation quand elle est publiée, et ne dit rien
    /// du tout sinon.
    #[tokio::test]
    async fn racine_mene_a_la_doc_seulement_si_activee() {
        let (s, _) = call(&app(state(0)), "GET", "/", None, json!({})).await;
        assert_eq!(s, StatusCode::TEMPORARY_REDIRECT);

        let sans_docs = router(state(0), &HttpConfig::default());
        let (s, e) = call(&sans_docs, "GET", "/", None, json!({})).await;
        assert_eq!(s, StatusCode::NOT_FOUND);
        assert_eq!(e["error"], "not_found");
    }
}
