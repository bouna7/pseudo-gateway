//! Authentification des appels.
//!
//! Trois sortes d'appelants :
//!   - **interne** : `GATEWAY_API_KEY` (ex. files_service). Clé « maîtresse » : le
//!     `tenant_id` de la requête est utilisé tel quel (comportement historique) ;
//!   - **compte** : clé `pgw_…` émise pour un utilisateur de l'API publique. Le
//!     tenant est imposé par le compte, et les limites/quotas s'appliquent ;
//!   - **admin** : `ADMIN_API_KEY`, uniquement pour `/admin/*`.
//!
//! La clé se présente dans `X-Api-Key: <clé>` ou `Authorization: Bearer <clé>`.
//! Si ni `GATEWAY_API_KEY` ni `ADMIN_API_KEY` ne sont définies, l'instance est en
//! mode ouvert (dev) : tout appel est traité comme interne.

use crate::accounts::Account;
use crate::app::AppState;
use crate::error::AppError;
use axum::extract::{Request, State};
use axum::http::{header, HeaderMap};
use axum::middleware::Next;
use axum::response::Response;
use sha2::{Digest, Sha256};
use std::net::{IpAddr, SocketAddr};
use subtle::ConstantTimeEq;

/// Espace de jetons par défaut d'un appel interne sans `tenant_id`
/// (rétro-compatibilité avec l'API d'origine).
pub const DEFAULT_TENANT: &str = "_global";

/// Identité résolue d'un appel, déposée dans les extensions de la requête.
#[derive(Clone)]
pub enum Principal {
    Internal,
    Account(Box<Account>),
}

impl Principal {
    /// Tenant effectif de la requête.
    pub fn tenant(&self, requested: Option<&str>) -> Result<String, AppError> {
        match self {
            Principal::Internal => Ok(requested.unwrap_or(DEFAULT_TENANT).to_string()),
            Principal::Account(a) => a.tenant(requested),
        }
    }
}

/// Clé présentée par l'appelant : `X-Api-Key`, sinon `Authorization: Bearer`.
fn presented_key<'a>(headers: &'a HeaderMap, header_name: &str) -> Option<&'a str> {
    let direct = headers
        .get(header_name)
        .and_then(|v| v.to_str().ok())
        .map(str::trim);
    let bearer = || {
        headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(str::trim)
    };
    direct.or_else(bearer).filter(|k| !k.is_empty())
}

/// Égalité en temps constant (on compare les empreintes : longueur égale).
fn ct_eq(a: &str, b: &str) -> bool {
    Sha256::digest(a.as_bytes())
        .ct_eq(&Sha256::digest(b.as_bytes()))
        .into()
}

/// Dit ce qui manque, sans révéler si une clé vaut ailleurs : on ne commente que
/// la **forme** de ce que l'appelant a lui-même envoyé.
fn explique_cle_api(presentee: Option<&str>) -> AppError {
    AppError::Unauthorized(match presentee {
        None => "clé d'API manquante : ajoutez l'en-tête « X-Api-Key: votre-cle » \
                 (ou « Authorization: Bearer votre-cle »)"
            .to_string(),
        Some(k) if k.starts_with(crate::accounts::KEY_PREFIX) => {
            "clé d'API inconnue ou révoquée : demandez-en une nouvelle à l'exploitant \
             de cette instance"
                .to_string()
        }
        Some(_) => "clé d'API invalide : une clé de compte commence par « pgw_ ». \
                    La clé d'administration n'ouvre que les routes /admin."
            .to_string(),
    })
}

async fn resolve(st: &AppState, headers: &HeaderMap, count: bool) -> Result<Principal, AppError> {
    if st.open_mode() {
        return Ok(Principal::Internal);
    }
    let key = presented_key(headers, "x-api-key").ok_or_else(|| explique_cle_api(None))?;
    if let Some(expected) = &st.api_key {
        if ct_eq(key, expected) {
            return Ok(Principal::Internal);
        }
    }
    if let Some(accounts) = &st.accounts {
        if let Some(account) = accounts.authenticate(key).await? {
            if account.disabled {
                return Err(AppError::Forbidden("compte désactivé".into()));
            }
            if count {
                accounts.enforce_limits(&account).await?;
            }
            return Ok(Principal::Account(Box::new(account)));
        }
    }
    Err(explique_cle_api(Some(key)))
}

/// Garde des endpoints de pseudonymisation : authentifie et décompte la requête.
pub async fn require_api_key(
    State(st): State<AppState>,
    mut req: Request,
    next: Next,
) -> Result<Response, AppError> {
    let principal = resolve(&st, req.headers(), true).await?;
    req.extensions_mut().insert(principal);
    Ok(next.run(req).await)
}

/// Garde des endpoints d'information (`/v1/me`) : authentifie sans décompter.
pub async fn require_api_key_uncounted(
    State(st): State<AppState>,
    mut req: Request,
    next: Next,
) -> Result<Response, AppError> {
    let principal = resolve(&st, req.headers(), false).await?;
    req.extensions_mut().insert(principal);
    Ok(next.run(req).await)
}

/// Garde de `/admin/*` : exige `ADMIN_API_KEY` (`X-Admin-Key` ou `Bearer`).
pub async fn require_admin(
    State(st): State<AppState>,
    req: Request,
    next: Next,
) -> Result<Response, AppError> {
    let expected = st.admin_key.as_ref().ok_or(AppError::Disabled)?;
    match presented_key(req.headers(), "x-admin-key") {
        Some(k) if ct_eq(k, expected) => Ok(next.run(req).await),
        // Piège courant : la clé est bien là, mais dans l'en-tête des endpoints /v1.
        None if req.headers().contains_key("x-api-key") => Err(AppError::Unauthorized(
            "ces routes attendent l'en-tête « X-Admin-Key » ; l'en-tête « X-Api-Key » \
             fourni ne les ouvre pas"
                .into(),
        )),
        None => Err(AppError::Unauthorized(
            "clé d'administration manquante : ajoutez l'en-tête « X-Admin-Key: votre-cle »".into(),
        )),
        // Confusion courante : la clé de compte posée sur une route d'administration.
        Some(k) if k.starts_with(crate::accounts::KEY_PREFIX) => Err(AppError::Unauthorized(
            "ces routes attendent la clé d'administration (en-tête « X-Admin-Key »), \
             pas une clé de compte « pgw_ »"
                .into(),
        )),
        Some(_) => Err(AppError::Unauthorized(
            "clé d'administration invalide (en-tête « X-Admin-Key »)".into(),
        )),
    }
}

/// Adresse du client. Derrière un reverse proxy (`TRUST_PROXY=true`), on prend la
/// **dernière** entrée de `X-Forwarded-For` : c'est celle ajoutée par le proxy ;
/// les précédentes sont fournies par le client et donc falsifiables.
pub fn client_ip(headers: &HeaderMap, peer: Option<SocketAddr>, trust_proxy: bool) -> String {
    if trust_proxy {
        let forwarded = headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.rsplit(',').next())
            .and_then(|ip| ip.trim().parse::<IpAddr>().ok());
        if let Some(ip) = forwarded {
            return ip.to_string();
        }
    }
    peer.map_or_else(|| "unknown".to_string(), |p| p.ip().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn cle_depuis_x_api_key_ou_bearer() {
        let mut h = HeaderMap::new();
        assert_eq!(presented_key(&h, "x-api-key"), None);
        h.insert(header::AUTHORIZATION, HeaderValue::from_static("Bearer abc"));
        assert_eq!(presented_key(&h, "x-api-key"), Some("abc"));
        h.insert("x-api-key", HeaderValue::from_static("xyz"));
        assert_eq!(presented_key(&h, "x-api-key"), Some("xyz"));
    }

    #[test]
    fn ip_client_derriere_proxy() {
        let peer: SocketAddr = "10.0.0.2:5000".parse().unwrap();
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", HeaderValue::from_static("6.6.6.6, 1.2.3.4"));
        assert_eq!(client_ip(&h, Some(peer), true), "1.2.3.4");
        assert_eq!(client_ip(&h, Some(peer), false), "10.0.0.2");
    }
}
