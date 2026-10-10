//! Administration des comptes de l'API publique (`/admin/*`, clé `ADMIN_API_KEY`).

use crate::accounts::{AccountPatch, AccountView, NewAccount};
use crate::api::{AccountWithKey, ErrorBody, MeResp};
use crate::app::AppState;
use crate::error::AppError;
use crate::extract::ApiJson;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
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

#[derive(Deserialize, ToSchema)]
pub struct CreateInvitationReq {
    /// À quoi sert cette invitation, pour s'y retrouver (ex. « Cabinet Durand »).
    #[schema(example = "Cabinet Durand")]
    pub label: String,
    /// Nombre d'inscriptions autorisées (0 = illimité).
    #[serde(default = "une_fois")]
    pub max_uses: u64,
    /// Durée de validité en jours (0 = sans expiration).
    #[serde(default)]
    pub valid_days: u64,
}

/// Une invitation ne sert qu'une fois par défaut : c'est le cas courant, un lien
/// pour une personne. L'exploitant élargit s'il le souhaite.
fn une_fois() -> u64 {
    1
}

#[derive(Serialize, ToSchema)]
pub struct InvitationCreated {
    #[serde(flatten)]
    pub invitation: crate::accounts::Invitation,
    /// Lien prêt à envoyer : le code y est déjà, l'invité n'a rien à saisir.
    #[schema(example = "https://votre-domaine.exemple/signup?invite=inv_…")]
    pub link: String,
}

/// Crée une invitation à s'inscrire et renvoie son lien.
#[utoipa::path(post, path = "/admin/invitations", tag = "admin",
    request_body = CreateInvitationReq, security(("admin_key" = [])),
    responses((status = 201, body = InvitationCreated), (status = 401, body = ErrorBody)))]
pub async fn create_invitation(
    State(st): State<AppState>,
    headers: axum::http::HeaderMap,
    ApiJson(req): ApiJson<CreateInvitationReq>,
) -> Result<(StatusCode, Json<InvitationCreated>), AppError> {
    let invitation = accounts(&st)?
        .create_invitation(req.label, req.max_uses, req.valid_days)
        .await?;
    let base = crate::app::origine_demandee(&headers)
        .or_else(|| st.public_base_url.as_deref().map(str::to_string))
        .unwrap_or_default();
    tracing::info!(code = %invitation.code, max_uses = invitation.max_uses, "invitation créée");
    let link = format!("{base}/signup?invite={}", invitation.code);
    Ok((
        StatusCode::CREATED,
        Json(InvitationCreated { invitation, link }),
    ))
}

/// Liste les invitations avec leur consommation.
#[utoipa::path(get, path = "/admin/invitations", tag = "admin", security(("admin_key" = [])),
    responses((status = 200, body = Vec<crate::accounts::InvitationView>), (status = 401, body = ErrorBody)))]
pub async fn list_invitations(
    State(st): State<AppState>,
) -> Result<Json<Vec<crate::accounts::InvitationView>>, AppError> {
    Ok(Json(accounts(&st)?.list_invitations().await?))
}

/// Révoque une invitation (effet immédiat).
#[utoipa::path(delete, path = "/admin/invitations/{code}", tag = "admin", security(("admin_key" = [])),
    params(("code" = String, Path, description = "Code de l'invitation")),
    responses((status = 204, description = "Révoquée"), (status = 404, body = ErrorBody)))]
pub async fn revoke_invitation(
    State(st): State<AppState>,
    Path(code): Path<String>,
) -> Result<StatusCode, AppError> {
    accounts(&st)?.delete_invitation(&code).await?;
    tracing::info!(%code, "invitation révoquée");
    Ok(StatusCode::NO_CONTENT)
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
