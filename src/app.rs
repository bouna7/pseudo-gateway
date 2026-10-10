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
    /// Code d'invitation exigé à l'inscription (`SIGNUP_INVITE_CODE`). Sans lui,
    /// l'inscription ouverte laisse n'importe qui créer des comptes.
    pub signup_invite_code: Option<Arc<String>>,
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
    /// Console d'administration sur `/admin/ui` (création de comptes et de clés).
    pub admin_ui: bool,
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
            admin_ui: false,
            public_base_url: None,
        }
    }
}

/// Origine par laquelle la requête est arrivée, reconstruite depuis les en-têtes.
/// Derrière un proxy, `X-Forwarded-Proto` dit si le visiteur est en HTTPS :
/// l'ignorer annoncerait `http://` et ferait échouer les essais depuis la page.
fn origine_demandee(headers: &axum::http::HeaderMap) -> Option<String> {
    let valeur = |nom: &str| {
        headers
            .get(nom)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.split(',').next().unwrap_or(v).trim().to_string())
            .filter(|v| !v.is_empty())
    };
    let hote = valeur("x-forwarded-host").or_else(|| valeur("host"))?;
    // Un en-tête Host falsifié ne fait qu'altérer l'exemple affiché dans la doc.
    if hote.contains('/') || hote.contains(' ') {
        return None;
    }
    let schema = valeur("x-forwarded-proto").unwrap_or_else(|| {
        if hote.starts_with("localhost") || hote.starts_with("127.0.0.1") {
            "http".into()
        } else {
            "https".into()
        }
    });
    Some(format!("{schema}://{hote}"))
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

    // Page publique d'inscription : elle ne sert à rien si l'inscription est
    // fermée, et la servir annoncerait une porte qui n'existe pas.
    if state.signup_per_hour.is_some() {
        // La page apprend ici si un code est exigé : la lui faire deviner par une
        // requête d'essai consommait une inscription du quota de l'IP.
        let page: Arc<str> = Arc::from(include_str!("signup.html").replace(
            "__CODE_EXIGE__",
            if state.signup_invite_code.is_some() {
                "oui"
            } else {
                "non"
            },
        ));
        app = app.route(
            "/signup",
            get(move || {
                let page = page.clone();
                async move { axum::response::Html(page.to_string()) }
            }),
        );
    }

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

        if cfg.admin_ui {
            // La page elle-même ne contient aucun secret : un navigateur ne peut
            // pas envoyer d'en-tête sur une simple navigation. C'est le script
            // qui réclame la clé d'administration puis appelle /admin/*, lesquels
            // restent protégés. Désactivée par défaut : son existence seule
            // signalerait qu'une console d'administration est présente.
            app = app.route(
                "/admin/ui",
                get(|| async { axum::response::Html(include_str!("console.html")) }),
            );
        }
    }

    if cfg.docs {
        let mut spec = api::ApiDoc::openapi();
        spec.info.version = env!("CARGO_PKG_VERSION").to_string();
        // Ne pas documenter une porte fermée : sur une instance sans inscription
        // libre, /v1/signup répond « fonctionnalité désactivée », ce qu'un nouvel
        // arrivant prend pour une panne.
        if state.signup_per_hour.is_none() {
            spec.paths.paths.remove("/v1/signup");
        }
        // Idem pour /admin/* : ces routes n'existent que si ADMIN_API_KEY est
        // définie, et elles ne concernent que l'exploitant de l'instance.
        if state.admin_key.is_none() {
            spec.paths.paths.retain(|path, _| !path.starts_with("/admin/"));
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
                // Le serveur annoncé est celui par lequel le visiteur est arrivé.
                // Avec une adresse figée, ouvrir la doc sur un autre domaine de la
                // même instance faisait échouer chaque essai : le navigateur
                // bloque l'appel vers une autre origine (« Failed to fetch »).
                get({
                    let repli = cfg.public_base_url.clone();
                    move |headers: axum::http::HeaderMap| {
                        let spec = spec.clone();
                        let repli = repli.clone();
                        async move {
                            let mut spec = (*spec).clone();
                            let mut serveurs: Vec<String> =
                                origine_demandee(&headers).into_iter().collect();
                            // L'URL publique reste proposée, pour les appels
                            // depuis un autre outil que cette page.
                            if let Some(url) = repli {
                                if !serveurs.contains(&url) {
                                    serveurs.push(url);
                                }
                            }
                            if !serveurs.is_empty() {
                                spec.servers = Some(
                                    serveurs
                                        .into_iter()
                                        .map(|u| utoipa::openapi::Server::new(u))
                                        .collect(),
                                );
                            }
                            Json(spec)
                        }
                    }
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
            signup_invite_code: None,
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

    /// Avec un code d'invitation, un nouvel utilisateur obtient sa clé sans
    /// passer par l'exploitant — mais pas n'importe qui.
    #[tokio::test]
    async fn inscription_protegee_par_code_invitation() {
        let mut st = state(0);
        st.signup_invite_code = Some(Arc::new("laissez-moi-entrer".into()));
        // Les essais ratés consomment la limite par IP : c'est voulu (on ne
        // devine pas un code en enchaînant), d'où la marge ici.
        st.signup_per_hour = Some(5);
        let app = app(st);
        let demande = |code: Option<&str>| {
            let mut corps = json!({"name": "Cabinet Durand", "email": "contact@exemple.fr"});
            if let Some(c) = code {
                corps["invite_code"] = json!(c);
            }
            corps
        };

        let (s, e) = call(&app, "POST", "/v1/signup", None, demande(None)).await;
        assert_eq!(s, StatusCode::FORBIDDEN, "sans code : refusé");
        assert!(e["message"].as_str().unwrap().contains("invitation"));

        let (s, _) = call(&app, "POST", "/v1/signup", None, demande(Some("au hasard"))).await;
        assert_eq!(s, StatusCode::FORBIDDEN, "mauvais code : refusé");

        let (s, r) = call(&app, "POST", "/v1/signup", None, demande(Some("laissez-moi-entrer"))).await;
        assert_eq!(s, StatusCode::CREATED);
        assert!(r["api_key"].as_str().unwrap().starts_with("pgw_"));

        // La page sait d'avance qu'un code est exigé : la lui faire deviner par
        // une requête d'essai consommerait une inscription du quota de l'IP.
        let resp = app
            .clone()
            .oneshot(Request::builder().uri("/signup").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let page = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let page = String::from_utf8(page.to_vec()).unwrap();
        assert!(page.contains(r#"data-exige="oui""#), "le champ code doit s'afficher");
        assert!(!page.contains("__CODE_EXIGE__"), "gabarit non substitué");
        let mut etat_ferme = state(0);
        etat_ferme.signup_per_hour = None;
        let ferme = router(
            etat_ferme,
            &HttpConfig {
                docs: true,
                ..Default::default()
            },
        );
        let (s, _) = call(&ferme, "GET", "/signup", None, json!({})).await;
        assert_eq!(s, StatusCode::NOT_FOUND);
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

    /// Une instance servie par deux domaines : la doc doit proposer celui par
    /// lequel on est arrivé, sinon le navigateur bloque chaque essai (appel vers
    /// une autre origine) et affiche « Failed to fetch ».
    #[tokio::test]
    async fn la_doc_vise_le_domaine_du_visiteur() {
        let app = router(
            state(0),
            &HttpConfig {
                docs: true,
                public_base_url: Some("https://adresse-publique.exemple".into()),
                ..Default::default()
            },
        );
        let spec_via = |hote: &'static str, proto: Option<&'static str>| {
            let app = app.clone();
            async move {
                let mut req = Request::builder().uri("/openapi.json").header("host", hote);
                if let Some(p) = proto {
                    req = req.header("x-forwarded-proto", p);
                }
                let resp = app.oneshot(req.body(Body::empty()).unwrap()).await.unwrap();
                let corps = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
                serde_json::from_slice::<Value>(&corps).unwrap()
            }
        };

        let spec = spec_via("autre-domaine.exemple", Some("https")).await;
        let serveurs: Vec<&str> = spec["servers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s["url"].as_str().unwrap())
            .collect();
        assert_eq!(serveurs[0], "https://autre-domaine.exemple", "le domaine visité d'abord");
        assert!(
            serveurs.contains(&"https://adresse-publique.exemple"),
            "l'URL publique reste proposée : {serveurs:?}"
        );

        // En local, pas de proxy : le schéma doit rester http.
        let spec = spec_via("localhost:8080", None).await;
        assert_eq!(spec["servers"][0]["url"], "http://localhost:8080");
    }

    /// Ce que voit un nouvel arrivant : une introduction qui dit comment obtenir
    /// une clé, les endpoints utiles en tête de menu, et aucune porte fermée
    /// documentée.
    #[tokio::test]
    async fn la_doc_guide_un_nouvel_arrivant() {
        let (_, spec) = call(&app(state(0)), "GET", "/openapi.json", None, json!({})).await;

        let intro = spec["info"]["description"].as_str().unwrap();
        assert!(intro.contains("X-Api-Key"), "comment s'authentifier");
        assert!(intro.contains("Demandez-la"), "comment obtenir une clé");
        assert!(intro.contains("/v1/pseudonymize"), "un premier appel");

        // Ordre du menu : ce qu'on vient faire d'abord, l'exploitation ensuite.
        let tags: Vec<&str> = spec["tags"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        assert_eq!(tags.first(), Some(&"pseudonymisation"));
        assert_eq!(tags.last(), Some(&"admin"));

        // Inscription ouverte dans cet état de test : elle est documentée.
        assert!(spec["paths"]["/v1/signup"].is_object());

        // Instance sans inscription ni admin : ces portes ne sont plus documentées.
        let mut st = state(0);
        st.signup_per_hour = None;
        st.admin_key = None;
        let depouille = router(
            st,
            &HttpConfig {
                docs: true,
                ..Default::default()
            },
        );
        let (_, spec) = call(&depouille, "GET", "/openapi.json", None, json!({})).await;
        assert!(spec["paths"]["/v1/signup"].is_null());
        assert!(spec["paths"]["/admin/accounts"].is_null());
        assert!(spec["paths"]["/v1/pseudonymize"].is_object());
    }

    /// La console n'est servie que si on l'a demandée, et seulement là où
    /// l'administration existe.
    #[tokio::test]
    async fn console_admin_sur_demande_seulement() {
        let (s, _) = call(&app(state(0)), "GET", "/admin/ui", None, json!({})).await;
        assert_eq!(s, StatusCode::NOT_FOUND, "désactivée par défaut");

        let avec = router(
            state(0),
            &HttpConfig {
                admin_ui: true,
                ..Default::default()
            },
        );
        let resp = avec
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/admin/ui")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let page = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let page = String::from_utf8(page.to_vec()).unwrap();
        assert!(page.contains("Console d'administration"));
        // La page est publique : elle ne doit contenir aucun secret.
        assert!(!page.contains("admin-demo"), "aucune clé en dur");

        // Sans ADMIN_API_KEY, l'administration n'existe pas : la console non plus.
        let mut st = state(0);
        st.admin_key = None;
        let sans_admin = router(
            st,
            &HttpConfig {
                admin_ui: true,
                ..Default::default()
            },
        );
        let (s, _) = call(&sans_admin, "GET", "/admin/ui", None, json!({})).await;
        assert_eq!(s, StatusCode::NOT_FOUND);
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
