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

/// Comptes rendus d'une ré-indexation.
#[derive(Serialize, ToSchema)]
pub struct ReindexResp {
    /// Jetons examinés pour ce tenant.
    pub examines: usize,
    /// Jetons auxquels une forme canonique vient d'être rattachée.
    pub rattaches: usize,
}

/// Rattache la forme canonique de chaque valeur déjà stockée à son jeton.
///
/// À lancer UNE FOIS par tenant après la mise en service de la normalisation
/// (30/10/2026). Les documents indexés avant celle-ci ont leurs jetons rangés
/// sous l'index de la chaîne brute : une question écrivant le même nom
/// autrement ne les retrouvait pas, et le modèle répondait que l'information
/// n'était pas dans le contexte. Sans ce rattrapage il faudrait réimporter
/// tous les documents.
///
/// Additif et rejouable : aucune valeur modifiée, aucun jeton créé.
#[utoipa::path(post, path = "/admin/reindex/{tenant}", tag = "admin",
    security(("admin_key" = [])),
    responses((status = 200, body = ReindexResp), (status = 401, body = ErrorBody)))]
pub async fn reindex(
    State(st): State<AppState>,
    Path(tenant): Path<String>,
) -> Result<Json<ReindexResp>, AppError> {
    let (examines, rattaches) = st.vault.reindex(&tenant).await?;
    tracing::info!(%tenant, examines, rattaches, "ré-indexation des formes canoniques");
    Ok(Json(ReindexResp {
        examines,
        rattaches,
    }))
}

/// Un espace de jetons du compte, et ce qu'il faut envoyer pour le viser.
#[derive(Serialize, ToSchema)]
pub struct EspaceView {
    /// Nom interne complet : `acc_…` ou `acc_…:<sous-espace>`.
    #[schema(example = "acc_ba3a0848af0f418a:delta-weaver")]
    pub espace: String,
    /// Valeur à passer en `tenant_id` pour viser cet espace. Absente pour
    /// l'espace nu du compte, qui correspond à un appel **sans** `tenant_id`.
    #[schema(example = "delta-weaver")]
    pub tenant_id: Option<String>,
    /// Nombre de jetons rangés là.
    pub jetons: usize,
}

/// Espaces de jetons d'un compte, avec leur taille.
///
/// Le nom d'un sous-espace est choisi par l'appelant au moment du masquage et
/// n'était consultable nulle part : il fallait le lire dans les journaux. D'où
/// des restitutions lancées sur l'espace nu du compte, qui rendent les jetons
/// intacts alors que les données sont bien là, dans un sous-espace.
#[utoipa::path(get, path = "/admin/accounts/{id}/espaces", tag = "admin",
    security(("admin_key" = [])),
    params(("id" = String, Path, description = "Identifiant du compte")),
    responses((status = 200, body = Vec<EspaceView>), (status = 404, body = ErrorBody)))]
pub async fn list_espaces(
    State(st): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Vec<EspaceView>>, AppError> {
    let account = accounts(&st)?.get(&id).await?;
    let prefix = format!("{}:", account.id);
    let espaces = st.vault.espaces(&account.id).await?;
    Ok(Json(
        espaces
            .into_iter()
            .map(|(espace, jetons)| EspaceView {
                tenant_id: espace.strip_prefix(&prefix).map(str::to_string),
                espace,
                jetons,
            })
            .collect(),
    ))
}

#[derive(Deserialize, ToSchema)]
pub struct SondeReq {
    /// Sous-espace visé, tel qu'il serait passé en `tenant_id`. Absent = espace
    /// nu du compte.
    #[schema(example = "delta-weaver")]
    pub tenant_id: Option<String>,
    /// Nom du jeton, avec ou sans crochets.
    #[schema(example = "PERSON_1")]
    pub token: String,
}

#[derive(Serialize, ToSchema)]
pub struct SondeResp {
    /// Espace effectivement interrogé.
    pub espace: String,
    pub token: String,
    /// `restituable`, `absent`, ou `cle_manquante`.
    pub etat: &'static str,
    /// Phrase prête à afficher.
    pub message: String,
}

/// Dit si un jeton serait restitué dans un espace donné, **sans rendre la valeur**.
///
/// Vu de l'API publique, « jeton inconnu ici » et « jeton chiffré sous une clé
/// absente » se ressemblent : les deux laissent le jeton intact et l'inscrivent
/// dans `unresolved`. Cette sonde les distingue, et reste sûre pour
/// l'administration — la clé `pga_…` ne doit pas devenir un moyen de lire les
/// données personnelles, donc seul le sort du jeton est rendu.
#[utoipa::path(post, path = "/admin/accounts/{id}/sonde", tag = "admin",
    request_body = SondeReq, security(("admin_key" = [])),
    params(("id" = String, Path, description = "Identifiant du compte")),
    responses((status = 200, body = SondeResp), (status = 400, body = ErrorBody),
              (status = 404, body = ErrorBody)))]
pub async fn sonder(
    State(st): State<AppState>,
    Path(id): Path<String>,
    ApiJson(req): ApiJson<SondeReq>,
) -> Result<Json<SondeResp>, AppError> {
    let account = accounts(&st)?.get(&id).await?;
    let espace = account.tenant(req.tenant_id.as_deref())?;
    // Le jeton se copie souvent depuis un texte, crochets compris.
    let token = req.token.trim().trim_start_matches('[').trim_end_matches(']');
    if token.is_empty() {
        return Err(AppError::BadRequest(
            "token : nom du jeton attendu, par exemple « PERSON_1 »".into(),
        ));
    }
    let (etat, message) = match st.vault.sonder(&espace, token).await? {
        crate::pseudonymize::Sonde::Restituable => (
            "restituable",
            format!("« {token} » est présent dans {espace} et sa valeur est lisible."),
        ),
        crate::pseudonymize::Sonde::Absent => (
            "absent",
            format!(
                "aucun jeton « {token} » dans {espace}. Le masquage a eu lieu \
                 dans un autre espace : vérifiez le `tenant_id` de l'appel."
            ),
        ),
        crate::pseudonymize::Sonde::CleManquante => (
            "cle_manquante",
            format!(
                "« {token} » est présent dans {espace} mais chiffré sous une clé \
                 absente de l'environnement. Remettez l'ancienne PSEUDO_KEY_<id> \
                 en place : la restitution le laisse intact tant qu'elle manque."
            ),
        ),
    };
    Ok(Json(SondeResp {
        espace,
        token: token.to_string(),
        etat,
        message,
    }))
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

#[derive(Serialize, ToSchema)]
pub struct AdminKeyRotated {
    /// Nouvelle clé d'administration, affichée **une seule fois**.
    pub admin_key: String,
}

/// Remplace la clé d'administration, sans toucher aux comptes ni aux jetons.
///
/// Sans effet si l'instance impose `ADMIN_API_KEY` par configuration : c'est
/// alors elle qui fait foi, et elle se change chez l'hébergeur.
#[utoipa::path(post, path = "/admin/key", tag = "admin", security(("admin_key" = [])),
    responses((status = 201, body = AdminKeyRotated), (status = 401, body = ErrorBody)))]
pub async fn rotate_admin_key(
    State(st): State<AppState>,
) -> Result<(StatusCode, Json<AdminKeyRotated>), AppError> {
    if st.admin_key.is_some() {
        return Err(AppError::BadRequest(
            "cette instance utilise la clé définie dans ADMIN_API_KEY : changez-la \
             chez votre hébergeur, puis redéployez"
                .into(),
        ));
    }
    let admin_key = accounts(&st)?.rotate_admin_key().await?;
    tracing::info!("clé d'administration remplacée depuis la console");
    Ok((StatusCode::CREATED, Json(AdminKeyRotated { admin_key })))
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
