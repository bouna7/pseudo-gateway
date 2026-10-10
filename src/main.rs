//! Passerelle de pseudonymisation chiffrée.
//!
//! Endpoints HTTP (voir `/docs` si `ENABLE_DOCS=true`) :
//!   POST /v1/pseudonymize   { text, custom_terms?, tenant_id? } -> { text, tokens }
//!   POST /v1/depseudonymize { text, tenant_id? }                -> { text }
//!   GET  /v1/me                                                 -> compte + consommation
//!   POST /v1/signup         { name, email }                     -> compte + clé (si PUBLIC_SIGNUP)
//!   /admin/*                gestion des comptes et clés        (si ADMIN_API_KEY)
//!   GET  /health                                                -> "ok"
//!
//! `/pseudonymize` et `/depseudonymize` (sans `/v1`) restent servis pour les
//! clients historiques.
//!
//! Le coffre (jeton <-> valeur réelle chiffrée AES-256-GCM) est derrière le trait
//! `VaultStore` : `InMemoryVaultStore` (dev) ou `RedisVaultStore` (persistant).

mod accounts;
mod admin;
mod api;
mod app;
mod auth;
mod crypto;
mod error;
mod extract;
mod keys;
mod ner;
mod pseudonymize;
mod store;

use accounts::{AccountStore, Accounts, InMemoryAccountStore, PlanDefaults, RedisAccountStore};
use app::{AppState, HttpConfig};
use keys::{EnvKeyProvider, KeyProvider};
use pseudonymize::Vault;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use store::{InMemoryVaultStore, RedisVaultStore, VaultStore};

/// Variable d'environnement non vide (un `${VAR:-}` de compose injecte "").
fn env_opt(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn env_parse<T: std::str::FromStr>(name: &str, default: T) -> T {
    match env_opt(name) {
        None => default,
        Some(v) => v.parse().unwrap_or_else(|_| {
            tracing::warn!(%name, value = %v, "valeur invalide — valeur par défaut utilisée");
            default
        }),
    }
}

fn env_flag(name: &str) -> bool {
    env_opt(name).is_some_and(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
}

/// Refuse de démarrer sans aucune clé : `/depseudonymize` restitue des données
/// réelles, une instance ouverte est donc une fuite, pas un mode dégradé. Un
/// avertissement dans les logs ne suffit pas — il passe inaperçu à un déploiement
/// où l'on a simplement oublié les variables d'environnement.
///
/// Renvoie `Ok(true)` quand l'instance démarre délibérément sans protection.
fn auth_guard(
    has_gateway_key: bool,
    has_admin_key: bool,
    allow_insecure: bool,
) -> Result<bool, &'static str> {
    if has_gateway_key || has_admin_key {
        return Ok(false);
    }
    if allow_insecure {
        return Ok(true);
    }
    Err("aucune clé d'authentification. Définissez GATEWAY_API_KEY (vos propres \
         services) et/ou ADMIN_API_KEY (API publique : comptes, clés, quotas). \
         Pour un usage LOCAL sans protection, ALLOW_INSECURE=true. \
         Générer des secrets : pseudo-gateway gen-keys")
}

fn fail(msg: &str, err: impl std::fmt::Display) -> ! {
    tracing::error!(error = %err, "{msg} — arrêt");
    std::process::exit(1);
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    tracing::info!("arrêt demandé — fin des requêtes en cours");
}

const HELP: &str = "\
pseudo-gateway — passerelle de pseudonymisation chiffrée

USAGE :
  pseudo-gateway            démarre le serveur (configuration : variables d'env ou .env)
  pseudo-gateway gen-keys   affiche des secrets neufs, prêts à coller dans .env
  pseudo-gateway --version  affiche la version

Variables principales : PSEUDO_KEY_1, PSEUDO_INDEX_KEY, VAULT_STORE, REDIS_URL,
GATEWAY_API_KEY, ADMIN_API_KEY, PUBLIC_SIGNUP, CORS_ALLOWED_ORIGINS, ENABLE_DOCS,
PORT, BIND_ADDR, PRESIDIO_URL (voir .env.example).";

/// Sous-commandes hors serveur. Renvoie `true` si le processus doit s'arrêter.
fn run_command() -> bool {
    match std::env::args().nth(1).as_deref() {
        None => false,
        Some("gen-keys") => {
            // Sortie ASCII : redirigeable telle quelle vers .env, y compris sous PowerShell 5.1.
            println!("# pseudo-gateway gen-keys - secrets a garder hors de git");
            println!("PSEUDO_KEY_1={}", accounts::random_hex(32));
            println!("PSEUDO_CURRENT_KEY_ID=1");
            println!("PSEUDO_INDEX_KEY={}", accounts::random_hex(32));
            println!("GATEWAY_API_KEY={}", accounts::random_hex(24));
            println!("ADMIN_API_KEY={}", accounts::random_hex(24));
            true
        }
        Some("--version" | "-V" | "version") => {
            println!("pseudo-gateway {}", env!("CARGO_PKG_VERSION"));
            true
        }
        Some("--help" | "-h" | "help") => {
            println!("{HELP}");
            true
        }
        Some(other) => {
            eprintln!("commande inconnue : {other}\n\n{HELP}");
            std::process::exit(2);
        }
    }
}

/// Options de configuration du service. Une variable absente des fichiers
/// compose n'atteint jamais le conteneur, même définie côté hébergeur : le test
/// `composes_transmettent_les_options` vérifie qu'aucune n'est oubliée.
const OPTIONS: &[&str] = &[
    "PSEUDO_KEY_1",
    "PSEUDO_CURRENT_KEY_ID",
    "PSEUDO_INDEX_KEY",
    "MASTER_KEY",
    "GATEWAY_API_KEY",
    "ADMIN_API_KEY",
    "PUBLIC_SIGNUP",
    "SIGNUP_PER_IP_PER_HOUR",
    "SIGNUP_INVITE_CODE",
    "SIGNUP_REQUIRE_INVITE",
    "DEFAULT_PLAN",
    "DEFAULT_RATE_PER_MIN",
    "DEFAULT_MONTHLY_QUOTA",
    "TRUST_PROXY",
    "CORS_ALLOWED_ORIGINS",
    "ENABLE_DOCS",
    "ENABLE_ADMIN_UI",
    "PUBLIC_BASE_URL",
    "MAX_BODY_BYTES",
    "REQUEST_TIMEOUT_SECS",
    "VAULT_STORE",
    "REDIS_URL",
    "PRESIDIO_URL",
    "PRESIDIO_LANG",
    "PRESIDIO_TIMEOUT_MS",
];

/// Volontairement hors des composes : `ALLOW_INSECURE` lève la garde qui refuse
/// de démarrer sans clé, `BIND_ADDR` et `PORT` sont imposés par la pile.
const HORS_COMPOSE: &[&str] = &["ALLOW_INSECURE", "BIND_ADDR", "PORT"];

#[cfg(test)]
mod tests {
    use super::{auth_guard, HORS_COMPOSE, OPTIONS};

    /// Une option ajoutée au code mais oubliée dans un compose est ignorée en
    /// silence : c'est ce qui est arrivé à ENABLE_ADMIN_UI, défini côté Dokploy
    /// et jamais transmis au conteneur.
    #[test]
    fn composes_transmettent_les_options() {
        let fichiers = [
            ("docker-compose.yml", include_str!("../docker-compose.yml")),
            (
                "docker-compose.images.yml",
                include_str!("../docker-compose.images.yml"),
            ),
        ];
        for (nom, contenu) in fichiers {
            // Les commentaires expliquent justement les exclusions : seules les
            // lignes actives disent ce qui est réellement transmis.
            let actives: String = contenu
                .lines()
                .filter(|l| !l.trim_start().starts_with('#'))
                .collect::<Vec<_>>()
                .join("\n");
            for option in OPTIONS {
                assert!(
                    actives.contains(option),
                    "{option} absente de {nom} : définie côté hébergeur, elle \
                     n'atteindrait jamais le conteneur"
                );
            }
            for option in HORS_COMPOSE {
                assert!(
                    !actives.contains(option),
                    "{option} ne doit pas être transmise par {nom}"
                );
            }
        }
    }

    /// Chaque option doit aussi être documentée pour l'exploitant.
    #[test]
    fn options_documentees_dans_env_example() {
        let exemple = include_str!("../.env.example");
        for option in OPTIONS.iter().chain(HORS_COMPOSE) {
            assert!(exemple.contains(option), "{option} absente de .env.example");
        }
    }

    #[test]
    fn refuse_de_demarrer_sans_cle() {
        // Une clé suffit : interne, ou admin (API publique).
        assert_eq!(auth_guard(true, false, false), Ok(false));
        assert_eq!(auth_guard(false, true, false), Ok(false));
        // Aucune clé : refus, sauf accord explicite (et l'avertissement suit).
        assert!(auth_guard(false, false, false).is_err());
        assert_eq!(auth_guard(false, false, true), Ok(true));
    }
}

#[tokio::main]
async fn main() {
    if run_command() {
        return;
    }

    // Installation hors Docker : un fichier .env à côté du binaire suffit.
    let dotenv = dotenvy::dotenv().ok();

    // Logs structurés ; niveau pilotable par RUST_LOG (défaut info).
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    if let Some(path) = dotenv {
        tracing::info!(path = %path.display(), "configuration chargée depuis .env");
    }

    // Chargement des clés via le fournisseur (env versionné aujourd'hui, Vault/KMS demain).
    let keyring = EnvKeyProvider
        .load()
        .await
        .unwrap_or_else(|e| fail("chargement des clés impossible", e));

    // Choix du backend : VAULT_STORE=redis pour la persistance, sinon mémoire.
    // Les comptes de l'API publique suivent le même backend.
    let (store, account_store): (Arc<dyn VaultStore>, Arc<dyn AccountStore>) =
        match env_opt("VAULT_STORE").as_deref() {
            Some("redis") => {
                let url = env_opt("REDIS_URL").unwrap_or_else(|| "redis://127.0.0.1:6379".into());
                // Fail-fast : en mode redis, on ne démarre pas sur un coffre absent.
                let vault = RedisVaultStore::connect(&url)
                    .await
                    .unwrap_or_else(|e| fail("connexion Redis impossible", e));
                let accts = RedisAccountStore::connect(&url)
                    .await
                    .unwrap_or_else(|e| fail("connexion Redis impossible", e));
                tracing::info!(%url, "coffre Redis connecté (persistant)");
                (Arc::new(vault), Arc::new(accts))
            }
            _ => {
                tracing::warn!("coffre EN MÉMOIRE (non persistant) — VAULT_STORE=redis pour la prod");
                (Arc::new(InMemoryVaultStore::new()), Arc::new(InMemoryAccountStore::new()))
            }
        };

    // Clé interne historique (files_service…).
    let api_key = env_opt("GATEWAY_API_KEY").map(Arc::new);
    // Clé d'administration : active l'API publique (comptes + clés par utilisateur).
    let admin_key = env_opt("ADMIN_API_KEY").map(Arc::new);
    let accounts = admin_key.as_ref().map(|_| {
        let defaults = PlanDefaults::from_env();
        tracing::info!(
            plan = %defaults.plan,
            rate_per_min = defaults.rate_per_min,
            monthly_quota = defaults.monthly_quota,
            "API publique activée (comptes + /admin)"
        );
        Arc::new(Accounts::new(account_store, defaults))
    });

    let signup_per_hour = match (env_flag("PUBLIC_SIGNUP"), accounts.is_some()) {
        (true, true) => {
            let n = env_parse("SIGNUP_PER_IP_PER_HOUR", 5u64);
            tracing::info!(per_ip_per_hour = n, "inscription publique ouverte (/v1/signup)");
            Some(n)
        }
        (true, false) => {
            tracing::warn!("PUBLIC_SIGNUP ignoré : ADMIN_API_KEY requise pour gérer les comptes");
            None
        }
        _ => None,
    };

    if api_key.is_some() {
        tracing::info!("clé d'API interne activée (X-Api-Key / Bearer)");
    }
    match auth_guard(api_key.is_some(), admin_key.is_some(), env_flag("ALLOW_INSECURE")) {
        Ok(true) => tracing::warn!(
            "ALLOW_INSECURE=true — endpoints NON protégés : /depseudonymize rend \
             des données réelles à quiconque atteint ce port"
        ),
        Ok(false) => {}
        Err(msg) => fail("démarrage refusé", msg),
    }

    let trust_proxy = env_flag("TRUST_PROXY");
    let state = AppState {
        vault: Arc::new(Vault::new(keyring, store)),
        api_key,
        admin_key,
        accounts,
        signup_per_hour,
        signup_invite_code: env_opt("SIGNUP_INVITE_CODE").map(Arc::new),
        // Par defaut une invitation est exigee : ouvrir l'inscription a tout
        // venant doit etre un choix explicite.
        signup_require_invite: !matches!(env_opt("SIGNUP_REQUIRE_INVITE").as_deref(), Some("false" | "0" | "no" | "off")),
        public_base_url: env_opt("PUBLIC_BASE_URL"),
        trust_proxy,
    };

    let http = HttpConfig {
        max_body_bytes: env_parse("MAX_BODY_BYTES", 1024 * 1024),
        request_timeout: Duration::from_secs(env_parse("REQUEST_TIMEOUT_SECS", 30)),
        cors_origins: env_opt("CORS_ALLOWED_ORIGINS").map(|v| {
            v.split(',')
                .map(|o| o.trim().to_string())
                .filter(|o| !o.is_empty())
                .collect()
        }),
        docs: env_flag("ENABLE_DOCS"),
        admin_ui: env_flag("ENABLE_ADMIN_UI"),
        public_base_url: env_opt("PUBLIC_BASE_URL"),
    };
    if let Some(origins) = &http.cors_origins {
        tracing::info!(?origins, "CORS activé");
    }
    if http.docs {
        tracing::info!("documentation publiée sur /docs et /openapi.json");
    }
    if http.admin_ui {
        tracing::info!("console d'administration publiée sur /admin/ui");
    }

    let app = app::router(state, &http);

    let host = env_opt("BIND_ADDR").unwrap_or_else(|| "0.0.0.0".into());
    let port: u16 = env_parse("PORT", 8080);
    let addr = format!("{host}:{port}");
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .unwrap_or_else(|e| fail(&format!("impossible d'écouter sur {addr}"), e));
    tracing::info!(version = env!("CARGO_PKG_VERSION"), "Passerelle de pseudonymisation prête sur http://{addr}");
    if let Err(e) = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    {
        fail("le serveur s'est arrêté", e);
    }
}
