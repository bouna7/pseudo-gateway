//! Endpoints publics (v1) et documentation OpenAPI.

use crate::accounts::{AccountView, NewAccount, Usage};
use crate::app::AppState;
use crate::auth::{client_ip, Principal};
use crate::error::AppError;
use crate::extract::ApiJson;
use crate::ner;
use crate::pseudonymize::CustomTerm;
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Html;
use axum::{Extension, Json};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use utoipa::openapi::security::{ApiKey, ApiKeyValue, HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::{Modify, OpenApi, ToSchema};

#[derive(Deserialize, ToSchema)]
pub struct CustomTermDto {
    /// Type du jeton produit (ex. PERSON, ORG).
    #[serde(rename = "type")]
    #[schema(example = "PERSON")]
    pub typ: String,
    #[schema(example = "Marie Dupont")]
    pub value: String,
}

#[derive(Deserialize, ToSchema)]
pub struct PseudoReq {
    /// Texte à protéger.
    #[schema(example = "Marie Dupont (marie.dupont@gmail.com) a signé.")]
    pub text: String,
    /// Termes que la détection automatique ne connaît pas.
    #[serde(default)]
    pub custom_terms: Vec<CustomTermDto>,
    /// Espace de jetons (cloisonnement par client / document). Pour une clé de
    /// compte : 1 à 64 caractères parmi `[A-Za-z0-9._-]`.
    #[serde(default)]
    pub tenant_id: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct PseudoResp {
    /// Texte avec jetons, envoyable au LLM.
    #[schema(example = "[PERSON_1] ([EMAIL_1]) a signé.")]
    pub text: String,
    pub tokens: Vec<String>,
}

#[derive(Deserialize, ToSchema)]
pub struct DepseudoReq {
    /// Texte contenant des jetons `[TYPE_N]`.
    #[schema(example = "Le client est [PERSON_1].")]
    pub text: String,
    #[serde(default)]
    pub tenant_id: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct DepseudoResp {
    pub text: String,
}

#[derive(Serialize, ToSchema)]
pub struct MeResp {
    pub account: AccountView,
    pub usage: Usage,
}

#[derive(Deserialize, ToSchema)]
pub struct SignupReq {
    #[schema(example = "Acme SAS")]
    pub name: String,
    #[schema(example = "dev@acme.fr")]
    pub email: String,
}

#[derive(Serialize, ToSchema)]
pub struct AccountWithKey {
    pub account: AccountView,
    /// Clé d'API en clair : affichée **une seule fois**, à conserver.
    pub api_key: String,
}

#[derive(Serialize, ToSchema)]
pub struct ErrorBody {
    #[schema(example = "unauthorized")]
    pub error: String,
    pub message: String,
}

/// Sonde de disponibilité (vérifie aussi l'accès au store).
#[utoipa::path(get, path = "/health", tag = "système",
    responses((status = 200, description = "Service disponible", body = String),
              (status = 500, description = "Store injoignable", body = ErrorBody)))]
pub async fn health(State(st): State<AppState>) -> Result<&'static str, AppError> {
    st.vault.ping().await?;
    Ok("ok")
}

/// Remplace les données sensibles par des jetons réversibles.
#[utoipa::path(post, path = "/v1/pseudonymize", tag = "pseudonymisation",
    request_body = PseudoReq,
    security(("api_key" = []), ("bearer" = [])),
    responses((status = 200, body = PseudoResp),
              (status = 400, body = ErrorBody), (status = 401, body = ErrorBody),
              (status = 403, body = ErrorBody), (status = 429, body = ErrorBody)))]
pub async fn pseudonymize(
    State(st): State<AppState>,
    Extension(principal): Extension<Principal>,
    ApiJson(req): ApiJson<PseudoReq>,
) -> Result<Json<PseudoResp>, AppError> {
    let tenant = principal.tenant(req.tenant_id.as_deref())?;

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
        Err(e) => {
            tracing::warn!(error = %e, "NER (Presidio) indisponible — repli regex + termes manuels")
        }
    }

    // 3) Jetonnage + chiffrement (la synchronisation vit dans le store).
    let (text, tokens) = st.vault.pseudonymize(&tenant, &req.text, &terms).await?;
    tracing::info!(%tenant, tokens = tokens.len(), "pseudonymisation effectuée");
    Ok(Json(PseudoResp { text, tokens }))
}

/// Restitue les vraies valeurs des jetons d'un texte.
#[utoipa::path(post, path = "/v1/depseudonymize", tag = "pseudonymisation",
    request_body = DepseudoReq,
    security(("api_key" = []), ("bearer" = [])),
    responses((status = 200, body = DepseudoResp),
              (status = 400, body = ErrorBody), (status = 401, body = ErrorBody),
              (status = 403, body = ErrorBody), (status = 429, body = ErrorBody)))]
pub async fn depseudonymize(
    State(st): State<AppState>,
    Extension(principal): Extension<Principal>,
    ApiJson(req): ApiJson<DepseudoReq>,
) -> Result<Json<DepseudoResp>, AppError> {
    let tenant = principal.tenant(req.tenant_id.as_deref())?;
    let text = st.vault.depseudonymize(&tenant, &req.text).await?;
    Ok(Json(DepseudoResp { text }))
}

/// Compte associé à la clé et consommation du mois (non décompté du quota).
#[utoipa::path(get, path = "/v1/me", tag = "compte",
    security(("api_key" = []), ("bearer" = [])),
    responses((status = 200, body = MeResp),
              (status = 401, body = ErrorBody), (status = 403, body = ErrorBody)))]
pub async fn me(
    State(st): State<AppState>,
    Extension(principal): Extension<Principal>,
) -> Result<Json<MeResp>, AppError> {
    let (Principal::Account(account), Some(accounts)) = (&principal, &st.accounts) else {
        return Err(AppError::Forbidden(
            "réservé aux clés de compte (pgw_…)".into(),
        ));
    };
    Ok(Json(MeResp {
        account: account.view(),
        usage: accounts.usage(account).await?,
    }))
}

/// Inscription libre : crée un compte avec les limites par défaut et renvoie sa
/// clé. Disponible seulement si l'instance a `PUBLIC_SIGNUP=true`.
#[utoipa::path(post, path = "/v1/signup", tag = "compte",
    request_body = SignupReq,
    responses((status = 201, body = AccountWithKey),
              (status = 400, body = ErrorBody), (status = 404, description = "Inscription désactivée", body = ErrorBody),
              (status = 429, body = ErrorBody)))]
pub async fn signup(
    State(st): State<AppState>,
    peer: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    ApiJson(req): ApiJson<SignupReq>,
) -> Result<(StatusCode, Json<AccountWithKey>), AppError> {
    let (Some(limit), Some(accounts)) = (st.signup_per_hour, &st.accounts) else {
        return Err(AppError::Disabled);
    };
    let ip = client_ip(&headers, peer.map(|c| c.0), st.trust_proxy);
    accounts.throttle(&format!("su:{ip}"), limit, 3600).await?;
    let (account, api_key) = accounts
        .create(NewAccount {
            name: req.name,
            email: Some(req.email),
            plan: None,
            rate_per_min: None,
            monthly_quota: None,
        })
        .await?;
    tracing::info!(account = %account.id, "inscription publique");
    Ok((
        StatusCode::CREATED,
        Json(AccountWithKey {
            account: account.view(),
            api_key,
        }),
    ))
}

/// Page de documentation interactive (Scalar), lit `/openapi.json`.
pub async fn docs() -> Html<&'static str> {
    Html(
        r#"<!doctype html>
<html lang="fr"><head><meta charset="utf-8"><title>pseudo-gateway API</title>
<meta name="viewport" content="width=device-width, initial-scale=1"></head>
<body><script id="api-reference" data-url="openapi.json"></script>
<script src="https://cdn.jsdelivr.net/npm/@scalar/api-reference@1"></script></body></html>"#,
    )
}

struct SecuritySchemes;

impl Modify for SecuritySchemes {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi.components.get_or_insert_with(Default::default);
        components.add_security_scheme(
            "api_key",
            SecurityScheme::ApiKey(ApiKey::Header(ApiKeyValue::new("X-Api-Key"))),
        );
        components.add_security_scheme(
            "bearer",
            SecurityScheme::Http(HttpBuilder::new().scheme(HttpAuthScheme::Bearer).build()),
        );
        components.add_security_scheme(
            "admin_key",
            SecurityScheme::ApiKey(ApiKey::Header(ApiKeyValue::new("X-Admin-Key"))),
        );
    }
}

#[derive(OpenApi)]
#[openapi(
    info(
        title = "pseudo-gateway",
        // Première chose que lit un nouvel arrivant : elle doit répondre « à quoi
        // ça sert », « comment j'obtiens une clé » et « montre-moi un exemple »,
        // sans supposer qu'on connaisse déjà la pseudonymisation.
        description = r#"
Protège les données personnelles **avant** qu'elles ne partent vers une IA
(OpenAI, Anthropic…), et les restitue au retour.

Le principe est celui d'un vestiaire : vous déposez les données sensibles, vous
recevez des jetons numérotés, l'IA travaille sur le texte avec les jetons, et
vous récupérez les vraies valeurs à la sortie. L'IA ne voit jamais qui sont les
personnes ; les valeurs réelles restent chiffrées (AES-256-GCM) de notre côté.

```text
"Marie Dupont (marie@exemple.fr) a signé."   ← votre texte
            ↓  POST /v1/pseudonymize
"[PERSON_1] ([EMAIL_1]) a signé."            ← ce que vous envoyez à l'IA
            ↓  réponse de l'IA, contenant les mêmes jetons
"J'ai répondu à [PERSON_1] sur [EMAIL_1]."
            ↓  POST /v1/depseudonymize
"J'ai répondu à Marie Dupont sur marie@exemple.fr."
```

## Obtenir une clé

Les deux endpoints exigent une clé d'API, à placer dans l'en-tête
`X-Api-Key` (ou `Authorization: Bearer …`). **Demandez-la à l'exploitant de
cette instance** : les clés sont créées à la main, il n'y a pas d'inscription
automatique. Une clé ressemble à `pgw_…` et n'est affichée qu'une seule fois.

## Premier appel

```bash
curl -X POST https://exemple/v1/pseudonymize \
  -H "X-Api-Key: pgw_votre_cle" \
  -H "Content-Type: application/json" \
  -d '{"text": "Marie Dupont (marie@exemple.fr) a signé."}'
```

Sont détectés automatiquement : e-mails, téléphones, IBAN, cartes bancaires,
ainsi que noms, villes et organisations. Un terme que la détection ignore peut
être fourni dans `custom_terms`.

## À savoir

- **Une même valeur reçoit toujours le même jeton** : `[PERSON_1]` désigne la
  même personne d'un appel à l'autre, ce qui permet à l'IA de garder le fil.
- **Cloisonnement** : vos jetons ne sont lisibles qu'avec votre clé. Le champ
  facultatif `tenant_id` cloisonne davantage, par dossier ou par client.
- **Limites** : au-delà de votre quota, la réponse est un `429` avec un en-tête
  `Retry-After`. `GET /v1/me` indique votre consommation du mois.
- **Encodage** : le corps doit être en UTF-8, comme l'exige le format JSON.
- Ce n'est **pas** une confidentialité totale : le texte non sensible part quand
  même vers l'IA, et un document très contextuel peut parfois permettre de
  deviner de qui l'on parle.
"#
    ),
    // L'ordre des tags est celui du menu : ce qu'on vient faire d'abord, les
    // routes d'exploitation à la fin.
    tags(
        (name = "pseudonymisation", description = "Masquer puis restituer les données sensibles."),
        (name = "compte", description = "Votre compte et votre consommation."),
        (name = "système", description = "Disponibilité du service."),
        (name = "admin", description = "Gestion des comptes et des clés (réservé à l'exploitant).")
    ),
    paths(
        health, pseudonymize, depseudonymize, me, signup,
        crate::admin::create_account, crate::admin::list_accounts, crate::admin::get_account,
        crate::admin::update_account, crate::admin::issue_key, crate::admin::revoke_key,
    ),
    components(schemas(crate::accounts::AccountPatch)),
    modifiers(&SecuritySchemes)
)]
pub struct ApiDoc;
