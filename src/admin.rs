//! Administration des comptes de l'API publique (`/admin/*`, clé `ADMIN_API_KEY`).

use crate::accounts::{AccountPatch, AccountView, NewAccount};
use crate::api::{AccountWithKey, ErrorBody, MeResp};
use crate::app::AppState;
use crate::error::AppError;
use crate::extract::ApiJson;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use std::sync::Arc;
use utoipa::ToSchema;

#[derive(Deserialize, ToSchema)]
pub struct CreateAccountReq {
    #[schema(example = "Acme SAS")]
    pub name: String,
    pub email: Option<String>,
    /// Libellé de l'offre (défaut `DEFAULT_PLAN`).
    pub plan: Option<String>,
    /// Requêtes par minute (défaut `DEFAULT_RATE_PER_MIN`, 0 = illimité).
    pub rate_per_min: Option<u32>,
    /// Requêtes par mois (défaut `DEFAULT_MONTHLY_QUOTA`, 0 = illimité).
    pub monthly_quota: Option<u64>,
}

fn accounts(st: &AppState) -> Result<&Arc<crate::accounts::Accounts>, AppError> {
    st.accounts.as_ref().ok_or(AppError::Disabled)
}

/// Crée un compte et sa première clé d'API.
#[utoipa::path(post, path = "/admin/accounts", tag = "admin",
    request_body = CreateAccountReq, security(("admin_key" = [])),
    responses((status = 201, body = AccountWithKey), (status = 400, body = ErrorBody), (status = 401, body = ErrorBody)))]
pub async fn create_account(
    State(st): State<AppState>,
    ApiJson(req): ApiJson<CreateAccountReq>,
) -> Result<(StatusCode, Json<AccountWithKey>), AppError> {
    let (account, api_key) = accounts(&st)?
        .create(NewAccount {
            name: req.name,
            email: req.email,
            plan: req.plan,
            rate_per_min: req.rate_per_min,
            monthly_quota: req.monthly_quota,
        })
        .await?;
    tracing::info!(account = %account.id, "compte créé (admin)");
    Ok((
        StatusCode::CREATED,
        Json(AccountWithKey {
            account: account.view(),
            api_key,
        }),
    ))
}

/// Liste des comptes.
#[utoipa::path(get, path = "/admin/accounts", tag = "admin", security(("admin_key" = [])),
    responses((status = 200, body = Vec<AccountView>), (status = 401, body = ErrorBody)))]
pub async fn list_accounts(State(st): State<AppState>) -> Result<Json<Vec<AccountView>>, AppError> {
    let all = accounts(&st)?.list().await?;
    Ok(Json(all.iter().map(|a| a.view()).collect()))
}

/// Détail d'un compte et consommation du mois.
#[utoipa::path(get, path = "/admin/accounts/{id}", tag = "admin", security(("admin_key" = [])),
    params(("id" = String, Path, description = "Identifiant du compte")),
    responses((status = 200, body = MeResp), (status = 404, body = ErrorBody)))]
pub async fn get_account(
    State(st): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<MeResp>, AppError> {
    let svc = accounts(&st)?;
    let account = svc.get(&id).await?;
    Ok(Json(MeResp {
        usage: svc.usage(&account).await?,
        account: account.view(),
    }))
}

/// Modifie un compte (offre, limites, désactivation).
#[utoipa::path(patch, path = "/admin/accounts/{id}", tag = "admin", security(("admin_key" = [])),
    params(("id" = String, Path, description = "Identifiant du compte")),
    request_body = AccountPatch,
    responses((status = 200, body = AccountView), (status = 404, body = ErrorBody)))]
pub async fn update_account(
    State(st): State<AppState>,
    Path(id): Path<String>,
    ApiJson(patch): ApiJson<AccountPatch>,
) -> Result<Json<AccountView>, AppError> {
    let account = accounts(&st)?.update(&id, patch).await?;
    tracing::info!(account = %account.id, disabled = account.disabled, "compte modifié (admin)");
    Ok(Json(account.view()))
}

/// Émet une clé supplémentaire (rotation).
#[utoipa::path(post, path = "/admin/accounts/{id}/keys", tag = "admin", security(("admin_key" = [])),
    params(("id" = String, Path, description = "Identifiant du compte")),
    responses((status = 201, body = AccountWithKey), (status = 404, body = ErrorBody)))]
pub async fn issue_key(
    State(st): State<AppState>,
    Path(id): Path<String>,
) -> Result<(StatusCode, Json<AccountWithKey>), AppError> {
    let (account, api_key) = accounts(&st)?.issue_key(&id).await?;
    tracing::info!(account = %account.id, "clé émise (admin)");
    Ok((
        StatusCode::CREATED,
        Json(AccountWithKey {
            account: account.view(),
            api_key,
        }),
    ))
}

/// Révoque une clé (effet immédiat).
#[utoipa::path(delete, path = "/admin/accounts/{id}/keys/{key_id}", tag = "admin", security(("admin_key" = [])),
    params(("id" = String, Path, description = "Identifiant du compte"),
           ("key_id" = String, Path, description = "Identifiant de la clé")),
    responses((status = 200, body = AccountView), (status = 404, body = ErrorBody)))]
pub async fn revoke_key(
    State(st): State<AppState>,
    Path((id, key_id)): Path<(String, String)>,
) -> Result<Json<AccountView>, AppError> {
    let account = accounts(&st)?.revoke_key(&id, &key_id).await?;
    tracing::info!(account = %account.id, %key_id, "clé révoquée (admin)");
    Ok(Json(account.view()))
}
