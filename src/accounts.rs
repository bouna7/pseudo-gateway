//! Comptes et clés d'API de l'API publique.
//!
//! Chaque utilisateur externe possède un **compte** et une ou plusieurs **clés
//! d'API**. Principes :
//!   - la clé en clair n'est montrée **qu'une fois** (à la création) ; on ne stocke
//!     que son SHA-256 (clé aléatoire de 192 bits → pas besoin de sel ni de KDF lent) ;
//!   - chaque compte a son propre espace de jetons (`acc_<id>[:<sous-tenant>]`),
//!     imposé côté serveur : un compte ne peut jamais lire les jetons d'un autre ;
//!   - limite par minute + quota mensuel, comptés dans le store (Redis en prod,
//!     donc partagés entre plusieurs instances de la passerelle).
//!
//! Persistance derrière le trait [`AccountStore`] (mémoire / Redis), comme le coffre.

use crate::error::{AppError, VaultError};
use async_trait::async_trait;
use rand::RngCore;
use redis::aio::ConnectionManager;
use redis::{AsyncCommands, Script};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use utoipa::ToSchema;

/// Préfixe des clés d'API émises (repérable dans un scanner de secrets).
pub const KEY_PREFIX: &str = "pgw_";

// ─── Modèle ─────────────────────────────────────────────────────────────────

/// Clé d'API telle que stockée : jamais le clair, seulement son empreinte.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredKey {
    pub key_id: String,
    pub hash: String,
    pub created_at: u64,
}

/// Compte tel que stocké.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Account {
    pub id: String,
    pub name: String,
    pub email: Option<String>,
    pub plan: String,
    /// Requêtes autorisées par minute (0 = illimité).
    pub rate_per_min: u32,
    /// Requêtes autorisées par mois calendaire UTC (0 = illimité).
    pub monthly_quota: u64,
    pub disabled: bool,
    pub created_at: u64,
    pub keys: Vec<StoredKey>,
}

impl Account {
    /// Espace de jetons imposé à ce compte. Le `tenant_id` fourni par l'appelant
    /// ne sert qu'à cloisonner **à l'intérieur** du compte.
    pub fn tenant(&self, sub: Option<&str>) -> Result<String, AppError> {
        match sub {
            None => Ok(self.id.clone()),
            Some(s) => {
                validate_sub_tenant(s)?;
                Ok(format!("{}:{s}", self.id))
            }
        }
    }

    pub fn view(&self) -> AccountView {
        AccountView {
            id: self.id.clone(),
            name: self.name.clone(),
            email: self.email.clone(),
            plan: self.plan.clone(),
            rate_per_min: self.rate_per_min,
            monthly_quota: self.monthly_quota,
            disabled: self.disabled,
            created_at: self.created_at,
            keys: self
                .keys
                .iter()
                .map(|k| KeyView {
                    key_id: k.key_id.clone(),
                    created_at: k.created_at,
                })
                .collect(),
        }
    }
}

/// Vue publique d'un compte (sans les empreintes de clés).
#[derive(Serialize, ToSchema)]
pub struct AccountView {
    pub id: String,
    pub name: String,
    pub email: Option<String>,
    pub plan: String,
    /// Requêtes par minute (0 = illimité).
    pub rate_per_min: u32,
    /// Requêtes par mois UTC (0 = illimité).
    pub monthly_quota: u64,
    pub disabled: bool,
    /// Horodatage Unix (secondes).
    pub created_at: u64,
    pub keys: Vec<KeyView>,
}

#[derive(Serialize, ToSchema)]
pub struct KeyView {
    /// Identifiant non secret de la clé (sert à la révoquer).
    pub key_id: String,
    pub created_at: u64,
}

/// Consommation du mois en cours.
#[derive(Serialize, ToSchema)]
pub struct Usage {
    /// Mois UTC au format AAAA-MM.
    pub month: String,
    pub requests: u64,
    /// 0 = illimité.
    pub monthly_quota: u64,
}

/// Invitation à s'inscrire : un code que l'exploitant crée et distribue, au lieu
/// d'un code unique figé dans la configuration, qu'il fallait redéployer pour
/// changer et qui ne pouvait être ni limité ni révoqué.
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct Invitation {
    /// Code à présenter à l'inscription (il voyage dans le lien d'invitation).
    pub code: String,
    /// À quoi elle sert, pour s'y retrouver dans la liste.
    pub label: String,
    /// Nombre d'inscriptions autorisées (0 = illimité).
    pub max_uses: u64,
    /// Horodatage Unix d'expiration (0 = sans limite de date).
    pub expires_at: u64,
    pub created_at: u64,
}

impl Invitation {
    pub fn expiree(&self, maintenant: u64) -> bool {
        self.expires_at != 0 && maintenant >= self.expires_at
    }
}

/// Invitation + état de consommation, pour l'affichage dans la console.
#[derive(Serialize, ToSchema)]
pub struct InvitationView {
    #[serde(flatten)]
    pub invitation: Invitation,
    pub uses: u64,
    pub expired: bool,
}

/// Paramètres d'un nouveau compte (admin ou inscription).
pub struct NewAccount {
    pub name: String,
    pub email: Option<String>,
    pub plan: Option<String>,
    pub rate_per_min: Option<u32>,
    pub monthly_quota: Option<u64>,
}

/// Modification partielle d'un compte (admin).
#[derive(Deserialize, ToSchema, Default)]
pub struct AccountPatch {
    pub name: Option<String>,
    pub plan: Option<String>,
    pub rate_per_min: Option<u32>,
    pub monthly_quota: Option<u64>,
    pub disabled: Option<bool>,
}

/// Limites appliquées aux comptes quand elles ne sont pas précisées.
#[derive(Clone, Debug)]
pub struct PlanDefaults {
    pub plan: String,
    pub rate_per_min: u32,
    pub monthly_quota: u64,
}

impl PlanDefaults {
    pub fn from_env() -> Self {
        Self {
            plan: env_or("DEFAULT_PLAN", "free".to_string()),
            rate_per_min: env_or("DEFAULT_RATE_PER_MIN", 60),
            monthly_quota: env_or("DEFAULT_MONTHLY_QUOTA", 10_000),
        }
    }
}

fn env_or<T: std::str::FromStr>(name: &str, default: T) -> T {
    std::env::var(name)
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(default)
}

// ─── Validation ─────────────────────────────────────────────────────────────

/// Sous-tenant d'un compte : court et sans caractère spécial (il entre dans les
/// clés Redis, dont le hash tag `{…}`).
fn validate_sub_tenant(s: &str) -> Result<(), AppError> {
    let ok = !s.is_empty()
        && s.len() <= 64
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b));
    if ok {
        Ok(())
    } else {
        Err(AppError::BadRequest(
            "tenant_id : 1 à 64 caractères parmi [A-Za-z0-9._-]".into(),
        ))
    }
}

fn validate_name(name: &str) -> Result<String, AppError> {
    let n = name.trim();
    if n.is_empty() || n.chars().count() > 100 {
        return Err(AppError::BadRequest("name : 1 à 100 caractères".into()));
    }
    Ok(n.to_string())
}

fn validate_email(email: Option<String>) -> Result<Option<String>, AppError> {
    match email.map(|e| e.trim().to_string()).filter(|e| !e.is_empty()) {
        None => Ok(None),
        Some(e) => {
            let valid = e.len() <= 254
                && !e.chars().any(char::is_whitespace)
                && e.split_once('@')
                    .is_some_and(|(l, d)| !l.is_empty() && d.contains('.'));
            if valid {
                Ok(Some(e))
            } else {
                Err(AppError::BadRequest("email invalide".into()))
            }
        }
    }
}

// ─── Utilitaires ────────────────────────────────────────────────────────────

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn random_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    rand::thread_rng().fill_bytes(&mut buf);
    hex::encode(buf)
}

/// Empreinte stockée d'une clé d'API.
pub fn hash_key(key: &str) -> String {
    hex::encode(Sha256::digest(key.as_bytes()))
}

/// Génère une clé : (clair à remettre à l'utilisateur, enregistrement stocké).
fn generate_key() -> (String, StoredKey) {
    let plain = format!("{KEY_PREFIX}{}", random_hex(24));
    let hash = hash_key(&plain);
    let stored = StoredKey {
        key_id: hash[..12].to_string(),
        hash,
        created_at: now_secs(),
    };
    (plain, stored)
}

/// Mois UTC `AAAA-MM` d'un horodatage Unix (algorithme civil de H. Hinnant,
/// évite une dépendance de dates pour ce seul besoin).
pub fn month_of(secs: u64) -> String {
    let z = (secs / 86_400) as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}")
}

// ─── Service ────────────────────────────────────────────────────────────────

pub struct Accounts {
    store: Arc<dyn AccountStore>,
    defaults: PlanDefaults,
}

impl Accounts {
    pub fn new(store: Arc<dyn AccountStore>, defaults: PlanDefaults) -> Self {
        Self { store, defaults }
    }

    /// Crée un compte et sa première clé. La clé en clair n'est renvoyée qu'ici.
    pub async fn create(&self, new: NewAccount) -> Result<(Account, String), AppError> {
        let (plain, key) = generate_key();
        let account = Account {
            id: format!("acc_{}", random_hex(8)),
            name: validate_name(&new.name)?,
            email: validate_email(new.email)?,
            plan: new.plan.unwrap_or_else(|| self.defaults.plan.clone()),
            rate_per_min: new.rate_per_min.unwrap_or(self.defaults.rate_per_min),
            monthly_quota: new.monthly_quota.unwrap_or(self.defaults.monthly_quota),
            disabled: false,
            created_at: now_secs(),
            keys: vec![key.clone()],
        };
        self.store.put(&account).await?;
        self.store.bind_key(&key.hash, &account.id).await?;
        Ok((account, plain))
    }

    pub async fn get(&self, id: &str) -> Result<Account, AppError> {
        self.store
            .get(id)
            .await?
            .ok_or_else(|| AppError::NotFound(format!("compte {id}")))
    }

    pub async fn list(&self) -> Result<Vec<Account>, AppError> {
        let mut all = self.store.list().await?;
        all.sort_by_key(|a| a.created_at);
        Ok(all)
    }

    pub async fn update(&self, id: &str, patch: AccountPatch) -> Result<Account, AppError> {
        let mut a = self.get(id).await?;
        if let Some(n) = patch.name {
            a.name = validate_name(&n)?;
        }
        if let Some(p) = patch.plan {
            a.plan = p;
        }
        if let Some(r) = patch.rate_per_min {
            a.rate_per_min = r;
        }
        if let Some(q) = patch.monthly_quota {
            a.monthly_quota = q;
        }
        if let Some(d) = patch.disabled {
            a.disabled = d;
        }
        self.store.put(&a).await?;
        Ok(a)
    }

    /// Ajoute une clé au compte (rotation côté client : créer, basculer, révoquer l'ancienne).
    pub async fn issue_key(&self, id: &str) -> Result<(Account, String), AppError> {
        let mut a = self.get(id).await?;
        let (plain, key) = generate_key();
        a.keys.push(key.clone());
        self.store.put(&a).await?;
        self.store.bind_key(&key.hash, &a.id).await?;
        Ok((a, plain))
    }

    pub async fn revoke_key(&self, id: &str, key_id: &str) -> Result<Account, AppError> {
        let mut a = self.get(id).await?;
        let pos = a
            .keys
            .iter()
            .position(|k| k.key_id == key_id)
            .ok_or_else(|| AppError::NotFound(format!("clé {key_id}")))?;
        let removed = a.keys.remove(pos);
        // Délier d'abord : même si l'écriture du compte échoue ensuite, la clé est morte.
        self.store.unbind_key(&removed.hash).await?;
        self.store.put(&a).await?;
        Ok(a)
    }

    /// Compte correspondant à une clé en clair, ou `None` si inconnue.
    pub async fn authenticate(&self, key: &str) -> Result<Option<Account>, AppError> {
        if !key.starts_with(KEY_PREFIX) {
            return Ok(None);
        }
        let hash = hash_key(key);
        let Some(id) = self.store.account_id_for_key(&hash).await? else {
            return Ok(None);
        };
        let account = self.store.get(&id).await?;
        // Double vérification : la clé doit toujours figurer dans le compte.
        Ok(account.filter(|a| a.keys.iter().any(|k| k.hash == hash)))
    }

    /// Décompte la requête et refuse si la limite par minute ou le quota est dépassé.
    ///
    /// Une requête refusée n'est PAS décomptée : sinon un client bloqué qui
    /// réessaie en boucle ferait grimper son compteur, et resterait bloqué même
    /// après une hausse de son quota (constaté en test : 4 requêtes comptées
    /// pour 2 servies). Minute d'abord, mois ensuite : si le mois refuse, seule
    /// une case de la minute courante est perdue, jamais du quota mensuel.
    pub async fn enforce_limits(&self, a: &Account) -> Result<(), AppError> {
        let now = now_secs();
        let minute_ok = self
            .store
            .try_hit(
                &format!("rl:{}:{}", a.id, now / 60),
                u64::from(a.rate_per_min),
                61,
            )
            .await?;
        if !minute_ok {
            return Err(AppError::RateLimited {
                retry_after: 60 - now % 60,
            });
        }
        let month_ok = self
            .store
            .try_hit(
                &format!("q:{}:{}", a.id, month_of(now)),
                a.monthly_quota,
                32 * 86_400,
            )
            .await?;
        if !month_ok {
            return Err(AppError::QuotaExceeded {
                limit: a.monthly_quota,
            });
        }
        Ok(())
    }

    pub async fn usage(&self, a: &Account) -> Result<Usage, AppError> {
        let month = month_of(now_secs());
        let requests = self.store.peek(&format!("q:{}:{month}", a.id)).await?;
        Ok(Usage {
            month,
            requests,
            monthly_quota: a.monthly_quota,
        })
    }

    // ── Invitations ──────────────────────────────────────────────────────

    /// Crée une invitation ; le code est tiré au sort, assez long pour ne pas
    /// se deviner puisqu'il voyage dans un lien.
    pub async fn create_invitation(
        &self,
        label: String,
        max_uses: u64,
        valide_jours: u64,
    ) -> Result<Invitation, AppError> {
        let maintenant = now_secs();
        let invitation = Invitation {
            code: format!("inv_{}", random_hex(12)),
            label: validate_name(&label)?,
            max_uses,
            expires_at: if valide_jours == 0 {
                0
            } else {
                maintenant + valide_jours * 86_400
            },
            created_at: maintenant,
        };
        self.store.put_invitation(&invitation).await?;
        Ok(invitation)
    }

    pub async fn list_invitations(&self) -> Result<Vec<InvitationView>, AppError> {
        let maintenant = now_secs();
        let mut invitations = self.store.list_invitations().await?;
        invitations.sort_by_key(|i| i.created_at);
        let mut vues = Vec::with_capacity(invitations.len());
        for invitation in invitations {
            let uses = self.store.peek(&format!("inv:{}", invitation.code)).await?;
            vues.push(InvitationView {
                expired: invitation.expiree(maintenant),
                uses,
                invitation,
            });
        }
        Ok(vues)
    }

    pub async fn delete_invitation(&self, code: &str) -> Result<(), AppError> {
        if self.store.get_invitation(code).await?.is_none() {
            return Err(AppError::NotFound(format!("invitation {code}")));
        }
        self.store.delete_invitation(code).await?;
        Ok(())
    }

    /// Consomme une utilisation. Le décompte est atomique : deux inscriptions
    /// simultanées ne peuvent pas dépasser ensemble le nombre autorisé.
    pub async fn consume_invitation(&self, code: &str) -> Result<bool, AppError> {
        let Some(invitation) = self.store.get_invitation(code).await? else {
            return Ok(false);
        };
        let maintenant = now_secs();
        if invitation.expiree(maintenant) {
            return Ok(false);
        }
        // Durée de vie du compteur : jusqu'à l'expiration, sinon large.
        let ttl = if invitation.expires_at == 0 {
            365 * 86_400
        } else {
            invitation.expires_at.saturating_sub(maintenant) + 60
        };
        self.store
            .try_hit(&format!("inv:{code}"), invitation.max_uses, ttl)
            .await
            .map_err(AppError::from)
    }

    /// Limite générique par fenêtre fixe (ex. inscriptions par IP et par heure).
    pub async fn throttle(&self, bucket: &str, limit: u64, window_secs: u64) -> Result<(), AppError> {
        let now = now_secs();
        let ok = self
            .store
            .try_hit(&format!("{bucket}:{}", now / window_secs), limit, window_secs + 1)
            .await?;
        if !ok {
            return Err(AppError::RateLimited {
                retry_after: window_secs - now % window_secs,
            });
        }
        Ok(())
    }
}

// ─── Persistance ────────────────────────────────────────────────────────────

#[async_trait]
pub trait AccountStore: Send + Sync {
    async fn get(&self, id: &str) -> Result<Option<Account>, VaultError>;
    /// Crée ou remplace le compte.
    async fn put(&self, account: &Account) -> Result<(), VaultError>;
    async fn list(&self) -> Result<Vec<Account>, VaultError>;
    /// Invitations : mêmes opérations, dans leur propre espace de clés.
    async fn put_invitation(&self, invitation: &Invitation) -> Result<(), VaultError>;
    async fn get_invitation(&self, code: &str) -> Result<Option<Invitation>, VaultError>;
    async fn list_invitations(&self) -> Result<Vec<Invitation>, VaultError>;
    async fn delete_invitation(&self, code: &str) -> Result<(), VaultError>;
    async fn bind_key(&self, hash: &str, account_id: &str) -> Result<(), VaultError>;
    async fn unbind_key(&self, hash: &str) -> Result<(), VaultError>;
    async fn account_id_for_key(&self, hash: &str) -> Result<Option<String>, VaultError>;
    /// Incrémente le compteur **seulement s'il est sous `limit`** (0 = illimité),
    /// de façon atomique, et dit si la requête est acceptée. Le compteur est
    /// créé avec une durée de vie `ttl_secs`.
    async fn try_hit(&self, counter: &str, limit: u64, ttl_secs: u64) -> Result<bool, VaultError>;
    /// Valeur actuelle d'un compteur (0 s'il n'existe pas).
    async fn peek(&self, counter: &str) -> Result<u64, VaultError>;
}

#[derive(Default)]
pub struct InMemoryAccountStore {
    inner: Mutex<MemInner>,
}

#[derive(Default)]
struct MemInner {
    accounts: HashMap<String, Account>,
    keys: HashMap<String, String>,
    invitations: HashMap<String, Invitation>,
    counters: HashMap<String, (u64, Instant)>,
}

impl InMemoryAccountStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, MemInner>, VaultError> {
        self.inner.lock().map_err(|_| VaultError::Poisoned)
    }
}

#[async_trait]
impl AccountStore for InMemoryAccountStore {
    async fn get(&self, id: &str) -> Result<Option<Account>, VaultError> {
        Ok(self.lock()?.accounts.get(id).cloned())
    }

    async fn put(&self, account: &Account) -> Result<(), VaultError> {
        self.lock()?
            .accounts
            .insert(account.id.clone(), account.clone());
        Ok(())
    }

    async fn list(&self) -> Result<Vec<Account>, VaultError> {
        Ok(self.lock()?.accounts.values().cloned().collect())
    }

    async fn put_invitation(&self, invitation: &Invitation) -> Result<(), VaultError> {
        self.lock()?
            .invitations
            .insert(invitation.code.clone(), invitation.clone());
        Ok(())
    }

    async fn get_invitation(&self, code: &str) -> Result<Option<Invitation>, VaultError> {
        Ok(self.lock()?.invitations.get(code).cloned())
    }

    async fn list_invitations(&self) -> Result<Vec<Invitation>, VaultError> {
        Ok(self.lock()?.invitations.values().cloned().collect())
    }

    async fn delete_invitation(&self, code: &str) -> Result<(), VaultError> {
        self.lock()?.invitations.remove(code);
        Ok(())
    }

    async fn bind_key(&self, hash: &str, account_id: &str) -> Result<(), VaultError> {
        self.lock()?
            .keys
            .insert(hash.to_owned(), account_id.to_owned());
        Ok(())
    }

    async fn unbind_key(&self, hash: &str) -> Result<(), VaultError> {
        self.lock()?.keys.remove(hash);
        Ok(())
    }

    async fn account_id_for_key(&self, hash: &str) -> Result<Option<String>, VaultError> {
        Ok(self.lock()?.keys.get(hash).cloned())
    }

    async fn try_hit(&self, counter: &str, limit: u64, ttl_secs: u64) -> Result<bool, VaultError> {
        let mut g = self.lock()?;
        let now = Instant::now();
        // Purge paresseuse pour ne pas grossir indéfiniment.
        if g.counters.len() > 50_000 {
            g.counters.retain(|_, (_, exp)| *exp > now);
        }
        let entry = g
            .counters
            .entry(counter.to_owned())
            .or_insert((0, now + Duration::from_secs(ttl_secs)));
        if entry.1 <= now {
            *entry = (0, now + Duration::from_secs(ttl_secs));
        }
        if limit > 0 && entry.0 >= limit {
            return Ok(false);
        }
        entry.0 += 1;
        Ok(true)
    }

    async fn peek(&self, counter: &str) -> Result<u64, VaultError> {
        let g = self.lock()?;
        Ok(g.counters
            .get(counter)
            .filter(|(_, exp)| *exp > Instant::now())
            .map_or(0, |(n, _)| *n))
    }
}

/// Vérification + INCR + EXPIRE atomiques : on n'incrémente que sous la limite
/// (ARGV[2], 0 = illimité), et la durée de vie n'est posée qu'à la création.
/// Renvoie 1 si la requête est acceptée, 0 sinon.
const TRY_HIT_LUA: &str = r#"
local limit = tonumber(ARGV[2])
if limit > 0 and tonumber(redis.call('GET', KEYS[1]) or '0') >= limit then
  return 0
end
if redis.call('INCR', KEYS[1]) == 1 then
  redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return 1
"#;

/// Comptes dans Redis, sous le préfixe `pga:` (distinct du coffre `pg:{…}`).
pub struct RedisAccountStore {
    conn: ConnectionManager,
    try_hit: Script,
}

impl RedisAccountStore {
    pub async fn connect(url: &str) -> Result<Self, VaultError> {
        let client = redis::Client::open(url).map_err(store_err)?;
        let conn = ConnectionManager::new(client).await.map_err(store_err)?;
        Ok(Self {
            conn,
            try_hit: Script::new(TRY_HIT_LUA),
        })
    }
}

fn store_err(e: impl std::fmt::Display) -> VaultError {
    VaultError::Store(e.to_string())
}

#[async_trait]
impl AccountStore for RedisAccountStore {
    async fn get(&self, id: &str) -> Result<Option<Account>, VaultError> {
        let mut c = self.conn.clone();
        let raw: Option<String> = c.get(format!("pga:acct:{id}")).await.map_err(store_err)?;
        raw.map(|s| serde_json::from_str(&s).map_err(store_err))
            .transpose()
    }

    async fn put(&self, account: &Account) -> Result<(), VaultError> {
        let json = serde_json::to_string(account).map_err(store_err)?;
        let mut c = self.conn.clone();
        redis::pipe()
            .atomic()
            .set(format!("pga:acct:{}", account.id), json)
            .sadd("pga:accounts", &account.id)
            .query_async::<()>(&mut c)
            .await
            .map_err(store_err)
    }

    async fn list(&self) -> Result<Vec<Account>, VaultError> {
        let mut c = self.conn.clone();
        let ids: HashSet<String> = c.smembers("pga:accounts").await.map_err(store_err)?;
        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            if let Some(a) = self.get(&id).await? {
                out.push(a);
            }
        }
        Ok(out)
    }

    async fn put_invitation(&self, invitation: &Invitation) -> Result<(), VaultError> {
        let json = serde_json::to_string(invitation).map_err(store_err)?;
        let mut c = self.conn.clone();
        redis::pipe()
            .atomic()
            .set(format!("pga:inv:{}", invitation.code), json)
            .sadd("pga:invitations", &invitation.code)
            .query_async::<()>(&mut c)
            .await
            .map_err(store_err)
    }

    async fn get_invitation(&self, code: &str) -> Result<Option<Invitation>, VaultError> {
        let mut c = self.conn.clone();
        let raw: Option<String> = c.get(format!("pga:inv:{code}")).await.map_err(store_err)?;
        raw.map(|s| serde_json::from_str(&s).map_err(store_err))
            .transpose()
    }

    async fn list_invitations(&self) -> Result<Vec<Invitation>, VaultError> {
        let mut c = self.conn.clone();
        let codes: HashSet<String> = c.smembers("pga:invitations").await.map_err(store_err)?;
        let mut out = Vec::with_capacity(codes.len());
        for code in codes {
            if let Some(i) = self.get_invitation(&code).await? {
                out.push(i);
            }
        }
        Ok(out)
    }

    async fn delete_invitation(&self, code: &str) -> Result<(), VaultError> {
        let mut c = self.conn.clone();
        redis::pipe()
            .atomic()
            .del(format!("pga:inv:{code}"))
            .srem("pga:invitations", code)
            // Le compteur d'utilisations suit l'invitation : un code recréé plus
            // tard ne doit pas hériter des consommations de l'ancien.
            .del(format!("pga:c:inv:{code}"))
            .query_async::<()>(&mut c)
            .await
            .map_err(store_err)
    }

    async fn bind_key(&self, hash: &str, account_id: &str) -> Result<(), VaultError> {
        let mut c = self.conn.clone();
        c.set::<_, _, ()>(format!("pga:key:{hash}"), account_id)
            .await
            .map_err(store_err)
    }

    async fn unbind_key(&self, hash: &str) -> Result<(), VaultError> {
        let mut c = self.conn.clone();
        c.del::<_, ()>(format!("pga:key:{hash}"))
            .await
            .map_err(store_err)
    }

    async fn account_id_for_key(&self, hash: &str) -> Result<Option<String>, VaultError> {
        let mut c = self.conn.clone();
        c.get(format!("pga:key:{hash}")).await.map_err(store_err)
    }

    async fn try_hit(&self, counter: &str, limit: u64, ttl_secs: u64) -> Result<bool, VaultError> {
        let mut c = self.conn.clone();
        let accepted: u8 = self
            .try_hit
            .key(format!("pga:c:{counter}"))
            .arg(ttl_secs)
            .arg(limit)
            .invoke_async(&mut c)
            .await
            .map_err(store_err)?;
        Ok(accepted == 1)
    }

    async fn peek(&self, counter: &str) -> Result<u64, VaultError> {
        let mut c = self.conn.clone();
        let n: Option<u64> = c.get(format!("pga:c:{counter}")).await.map_err(store_err)?;
        Ok(n.unwrap_or(0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn service(rate: u32, quota: u64) -> Accounts {
        Accounts::new(
            Arc::new(InMemoryAccountStore::new()),
            PlanDefaults {
                plan: "test".into(),
                rate_per_min: rate,
                monthly_quota: quota,
            },
        )
    }

    fn new(name: &str) -> NewAccount {
        NewAccount {
            name: name.into(),
            email: Some("a@b.fr".into()),
            plan: None,
            rate_per_min: None,
            monthly_quota: None,
        }
    }

    #[test]
    fn mois_utc() {
        assert_eq!(month_of(0), "1970-01");
        assert_eq!(month_of(1_709_251_199), "2024-02"); // 29/02/2024 23:59:59
        assert_eq!(month_of(1_709_251_200), "2024-03");
    }

    #[tokio::test]
    async fn cle_creee_authentifie_puis_revoquee() {
        let s = service(0, 0);
        let (a, key) = s.create(new("Acme")).await.unwrap();
        assert!(key.starts_with(KEY_PREFIX));
        assert_eq!(s.authenticate(&key).await.unwrap().unwrap().id, a.id);
        assert!(s.authenticate("pgw_faux").await.unwrap().is_none());

        let key_id = a.keys[0].key_id.clone();
        s.revoke_key(&a.id, &key_id).await.unwrap();
        assert!(s.authenticate(&key).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn tenant_impose_par_le_compte() {
        let s = service(0, 0);
        let (a, _) = s.create(new("A")).await.unwrap();
        assert_eq!(a.tenant(None).unwrap(), a.id);
        assert_eq!(a.tenant(Some("doc-1")).unwrap(), format!("{}:doc-1", a.id));
        // Impossible de s'échapper vers un autre espace.
        assert!(a.tenant(Some("}:x")).is_err());
        assert!(a.tenant(Some("")).is_err());
    }

    #[tokio::test]
    async fn limite_par_minute_puis_quota() {
        let s = service(2, 0);
        let (a, _) = s.create(new("A")).await.unwrap();
        s.enforce_limits(&a).await.unwrap();
        s.enforce_limits(&a).await.unwrap();
        assert!(matches!(
            s.enforce_limits(&a).await,
            Err(AppError::RateLimited { .. })
        ));

        let s = service(0, 1);
        let (a, _) = s.create(new("B")).await.unwrap();
        s.enforce_limits(&a).await.unwrap();
        assert!(matches!(
            s.enforce_limits(&a).await,
            Err(AppError::QuotaExceeded { limit: 1 })
        ));
        // Seule la requête servie est comptée.
        assert_eq!(s.usage(&a).await.unwrap().requests, 1);
    }

    /// Même garantie côté Redis (script Lua) — nécessite un Redis joignable.
    /// Lancer : `REDIS_URL=redis://127.0.0.1:6379 cargo test -- --ignored`
    #[tokio::test]
    #[ignore = "nécessite un Redis (cf. docker-compose) ; lancer avec --ignored"]
    async fn redis_try_hit_ne_compte_pas_les_refus() {
        let url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into());
        let store = RedisAccountStore::connect(&url).await.expect("connexion Redis");
        let counter = format!("test:try_hit:{}", random_hex(6));
        assert!(store.try_hit(&counter, 2, 60).await.unwrap());
        assert!(store.try_hit(&counter, 2, 60).await.unwrap());
        for _ in 0..5 {
            assert!(!store.try_hit(&counter, 2, 60).await.unwrap());
        }
        assert_eq!(store.peek(&counter).await.unwrap(), 2);
        // Limite relevée : accepté aussitôt.
        assert!(store.try_hit(&counter, 3, 60).await.unwrap());
        // 0 = illimité.
        assert!(store.try_hit(&counter, 0, 60).await.unwrap());
        assert_eq!(store.peek(&counter).await.unwrap(), 4);
    }

    /// Scénario constaté en test manuel : un client bloqué réessaie en boucle,
    /// puis l'admin relève son quota. Il doit être débloqué aussitôt — ce qui
    /// suppose que les refus n'aient pas gonflé son compteur.
    #[tokio::test]
    async fn refus_non_decomptes_hausse_de_quota_debloque() {
        let s = service(0, 2);
        let (mut a, _) = s.create(new("A")).await.unwrap();
        s.enforce_limits(&a).await.unwrap();
        s.enforce_limits(&a).await.unwrap();
        for _ in 0..10 {
            assert!(matches!(
                s.enforce_limits(&a).await,
                Err(AppError::QuotaExceeded { .. })
            ));
        }
        assert_eq!(s.usage(&a).await.unwrap().requests, 2);

        a = s
            .update(
                &a.id,
                AccountPatch {
                    monthly_quota: Some(3),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        s.enforce_limits(&a).await.unwrap();
        assert_eq!(s.usage(&a).await.unwrap().requests, 3);
    }

    #[tokio::test]
    async fn validation_des_entrees() {
        let s = service(0, 0);
        assert!(s.create(new("")).await.is_err());
        let mut bad = new("A");
        bad.email = Some("pas-un-email".into());
        assert!(s.create(bad).await.is_err());
    }
}
