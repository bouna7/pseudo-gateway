//! Persistance du coffre, derrière un trait pour pouvoir changer de backend.
//!
//! Le store ne voit JAMAIS le clair : il ne manipule que des octets déjà chiffrés
//! (`blob`) et des **index aveugles** (`bi` = HMAC de la valeur, cf. [`crate::keys`]).
//!
//! Trois données par tenant :
//!   - index aveugle  -> jeton          (déduplication : même valeur => même jeton)
//!   - jeton          -> blob chiffré    (restitution)
//!   - (type)         -> compteur        (numérotation des jetons)
//!
//! Phase 1 : implémentation `InMemoryVaultStore` (dev/tests). Phase 2 : `RedisVaultStore`.

use crate::error::VaultError;
use async_trait::async_trait;
use redis::aio::ConnectionManager;
use redis::{AsyncCommands, Script};
use std::collections::HashMap;
use std::sync::Mutex;

/// Contrat de persistance du coffre. Toutes les méthodes sont scopées par `tenant`.
#[async_trait]
pub trait VaultStore: Send + Sync {
    /// Jeton déjà associé à cet index aveugle, ou `None` si la valeur est nouvelle.
    async fn token_for_index(&self, tenant: &str, bi: &str) -> Result<Option<String>, VaultError>;

    /// Crée un jeton pour `bi` **si absent**, de façon atomique (gère la course
    /// concurrente). Renvoie le jeton effectif — le nouveau, ou l'existant si un
    /// autre appel l'a créé entre-temps (auquel cas `blob` est simplement ignoré).
    async fn create_token(
        &self,
        tenant: &str,
        typ: &str,
        bi: &str,
        blob: &[u8],
    ) -> Result<String, VaultError>;

    /// Blob chiffré associé à un jeton, ou `None` si inconnu (pour ce tenant).
    async fn blob_for_token(&self, tenant: &str, token: &str)
        -> Result<Option<Vec<u8>>, VaultError>;

    /// Fait pointer un index aveugle de PLUS vers un jeton existant.
    ///
    /// Sert à rattacher la forme canonique d'une valeur au jeton qu'elle avait
    /// déjà sous son ancien index (écriture brute). Purement additif : aucun
    /// jeton n'est créé, aucun index existant n'est écrasé par un autre jeton.
    async fn alias_index(&self, tenant: &str, bi: &str, token: &str) -> Result<(), VaultError>;

    /// Tous les couples (jeton, blob chiffré) d'un tenant.
    ///
    /// Uniquement pour la ré-indexation administrative : le store ne sait
    /// toujours pas lire le clair, c'est l'appelant qui déchiffre avec la clé.
    async fn tokens(&self, tenant: &str) -> Result<Vec<(String, Vec<u8>)>, VaultError>;

    /// Sonde de disponibilité du backend (utilisée par `GET /health`).
    /// Par défaut : toujours disponible (cas du store en mémoire).
    async fn ping(&self) -> Result<(), VaultError> {
        Ok(())
    }
}

/// Coffre en mémoire (perdu au redémarrage) — pour le développement et les tests.
/// Toute la cohérence est garantie sous un unique `Mutex` (aucun `await` n'est tenu
/// pendant qu'il est verrouillé).
#[derive(Default)]
pub struct InMemoryVaultStore {
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    /// (tenant, blind_index) -> jeton
    index: HashMap<(String, String), String>,
    /// (tenant, jeton) -> blob chiffré
    tokens: HashMap<(String, String), Vec<u8>>,
    /// (tenant, type) -> dernier numéro attribué
    counters: HashMap<(String, String), u32>,
}

impl InMemoryVaultStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl VaultStore for InMemoryVaultStore {
    async fn token_for_index(&self, tenant: &str, bi: &str) -> Result<Option<String>, VaultError> {
        let guard = self.inner.lock().map_err(|_| VaultError::Poisoned)?;
        Ok(guard.index.get(&(tenant.to_owned(), bi.to_owned())).cloned())
    }

    async fn create_token(
        &self,
        tenant: &str,
        typ: &str,
        bi: &str,
        blob: &[u8],
    ) -> Result<String, VaultError> {
        let mut guard = self.inner.lock().map_err(|_| VaultError::Poisoned)?;
        let index_key = (tenant.to_owned(), bi.to_owned());
        // Re-vérification sous verrou : si un autre appel a créé le jeton entre le
        // `token_for_index` et ici, on renvoie le sien (pas de doublon).
        if let Some(existing) = guard.index.get(&index_key) {
            return Ok(existing.clone());
        }
        let counter_key = (tenant.to_owned(), typ.to_owned());
        let n = {
            let c = guard.counters.entry(counter_key).or_insert(0);
            *c += 1;
            *c
        };
        let token = format!("{typ}_{n}");
        guard
            .tokens
            .insert((tenant.to_owned(), token.clone()), blob.to_vec());
        guard.index.insert(index_key, token.clone());
        Ok(token)
    }

    async fn blob_for_token(
        &self,
        tenant: &str,
        token: &str,
    ) -> Result<Option<Vec<u8>>, VaultError> {
        let guard = self.inner.lock().map_err(|_| VaultError::Poisoned)?;
        Ok(guard
            .tokens
            .get(&(tenant.to_owned(), token.to_owned()))
            .cloned())
    }

    async fn alias_index(&self, tenant: &str, bi: &str, token: &str) -> Result<(), VaultError> {
        let mut guard = self.inner.lock().map_err(|_| VaultError::Poisoned)?;
        guard
            .index
            .entry((tenant.to_owned(), bi.to_owned()))
            .or_insert_with(|| token.to_owned());
        Ok(())
    }

    async fn tokens(&self, tenant: &str) -> Result<Vec<(String, Vec<u8>)>, VaultError> {
        let guard = self.inner.lock().map_err(|_| VaultError::Poisoned)?;
        Ok(guard
            .tokens
            .iter()
            .filter(|((t, _), _)| t == tenant)
            .map(|((_, tok), blob)| (tok.clone(), blob.clone()))
            .collect())
    }
}

/// Création atomique d'un jeton, côté serveur Redis (évite toute course entre
/// deux requêtes concurrentes sur la même valeur).
///
///   KEYS[1] = clé index aveugle (…:bi:<bi>)   KEYS[2] = clé compteur (…:cnt:<type>)
///   ARGV[1] = type   ARGV[2] = blob chiffré   ARGV[3] = préfixe des clés jeton (…:tok:)
///
/// Si l'index existe déjà → renvoie le jeton existant (le blob est ignoré).
/// Sinon → INCR du compteur, construit `TYPE_N`, écrit index + blob, renvoie le jeton.
const CREATE_TOKEN_LUA: &str = r#"
local existing = redis.call('GET', KEYS[1])
if existing then
  return existing
end
local n = redis.call('INCR', KEYS[2])
local token = ARGV[1] .. '_' .. n
redis.call('SET', KEYS[1], token)
redis.call('SET', ARGV[3] .. token, ARGV[2])
return token
"#;

/// Coffre persistant adossé à Redis. Le jeton créé survit aux redémarrages du
/// service (et de Redis si la persistance AOF/RDB est activée — cf. docker-compose).
///
/// Toutes les clés d'un tenant partagent un *hash tag* `{<tenant>}` → elles tombent
/// dans le même slot, ce qui rend le script Lua multi-clés valide même en Redis Cluster.
pub struct RedisVaultStore {
    conn: ConnectionManager,
    create: Script,
}

impl RedisVaultStore {
    /// Ouvre la connexion (pool multiplexé auto-reconnectant) vers `url`.
    pub async fn connect(url: &str) -> Result<Self, VaultError> {
        let client = redis::Client::open(url).map_err(|e| VaultError::Store(e.to_string()))?;
        let conn = ConnectionManager::new(client)
            .await
            .map_err(|e| VaultError::Store(e.to_string()))?;
        Ok(Self {
            conn,
            create: Script::new(CREATE_TOKEN_LUA),
        })
    }

    /// Préfixe namespacé par tenant, avec hash tag Redis Cluster : `pg:{<tenant>}`.
    fn ns(tenant: &str) -> String {
        format!("pg:{{{tenant}}}")
    }
}

#[async_trait]
impl VaultStore for RedisVaultStore {
    async fn token_for_index(&self, tenant: &str, bi: &str) -> Result<Option<String>, VaultError> {
        let key = format!("{}:bi:{}", Self::ns(tenant), bi);
        let mut conn = self.conn.clone();
        let token: Option<String> = conn
            .get(key)
            .await
            .map_err(|e| VaultError::Store(e.to_string()))?;
        Ok(token)
    }

    async fn create_token(
        &self,
        tenant: &str,
        typ: &str,
        bi: &str,
        blob: &[u8],
    ) -> Result<String, VaultError> {
        let ns = Self::ns(tenant);
        let bi_key = format!("{ns}:bi:{bi}");
        let cnt_key = format!("{ns}:cnt:{typ}");
        let tok_prefix = format!("{ns}:tok:");
        let mut conn = self.conn.clone();
        let token: String = self
            .create
            .key(bi_key)
            .key(cnt_key)
            .arg(typ)
            .arg(blob)
            .arg(tok_prefix)
            .invoke_async(&mut conn)
            .await
            .map_err(|e| VaultError::Store(e.to_string()))?;
        Ok(token)
    }

    async fn blob_for_token(
        &self,
        tenant: &str,
        token: &str,
    ) -> Result<Option<Vec<u8>>, VaultError> {
        let key = format!("{}:tok:{}", Self::ns(tenant), token);
        let mut conn = self.conn.clone();
        let blob: Option<Vec<u8>> = conn
            .get(key)
            .await
            .map_err(|e| VaultError::Store(e.to_string()))?;
        Ok(blob)
    }

    async fn alias_index(&self, tenant: &str, bi: &str, token: &str) -> Result<(), VaultError> {
        let key = format!("{}:bi:{}", Self::ns(tenant), bi);
        let mut conn = self.conn.clone();
        // NX : si cet index pointe déjà quelque part, on ne le détourne pas.
        // Deux valeurs distinctes qui tomberaient sur la même forme canonique
        // garderaient ainsi chacune le jeton qu'elles ont toujours eu.
        let _: bool = redis::cmd("SET")
            .arg(&key)
            .arg(token)
            .arg("NX")
            .query_async(&mut conn)
            .await
            .map_err(|e| VaultError::Store(e.to_string()))?;
        Ok(())
    }

    async fn tokens(&self, tenant: &str) -> Result<Vec<(String, Vec<u8>)>, VaultError> {
        let prefix = format!("{}:tok:", Self::ns(tenant));
        let pattern = format!("{prefix}*");
        let mut conn = self.conn.clone();

        // SCAN plutôt que KEYS : KEYS bloque Redis le temps du parcours, ce qui
        // suspend toutes les pseudonymisations en cours. Curseur explicite
        // plutôt que l'itérateur de la bibliothèque : l'API du curseur est
        // stable d'une version de `redis` à l'autre.
        let mut keys: Vec<String> = Vec::new();
        let mut cursor: u64 = 0;
        loop {
            let (next, batch): (u64, Vec<String>) = redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg(&pattern)
                .arg("COUNT")
                .arg(500)
                .query_async(&mut conn)
                .await
                .map_err(|e| VaultError::Store(e.to_string()))?;
            keys.extend(batch);
            if next == 0 {
                break;
            }
            cursor = next;
        }

        let mut out = Vec::with_capacity(keys.len());
        for key in keys {
            let blob: Option<Vec<u8>> = conn
                .get(&key)
                .await
                .map_err(|e| VaultError::Store(e.to_string()))?;
            if let Some(blob) = blob {
                out.push((key[prefix.len()..].to_string(), blob));
            }
        }
        Ok(out)
    }

    async fn ping(&self) -> Result<(), VaultError> {
        let mut conn = self.conn.clone();
        let _: String = redis::cmd("PING")
            .query_async(&mut conn)
            .await
            .map_err(|e| VaultError::Store(e.to_string()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-trip Redis — nécessite un Redis joignable.
    /// Lancer : `REDIS_URL=redis://127.0.0.1:6379 cargo test -- --ignored`
    #[tokio::test]
    #[ignore = "nécessite un Redis (cf. docker-compose) ; lancer avec --ignored"]
    async fn redis_round_trip() {
        let url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into());
        let store = RedisVaultStore::connect(&url).await.expect("connexion Redis");

        let bi = "bi_test_phase2";
        let tok = store
            .create_token("tenantA", "EMAIL", bi, b"secret@x.fr")
            .await
            .expect("create");
        // Idempotence : même index → même jeton.
        let tok2 = store
            .create_token("tenantA", "EMAIL", bi, b"autre")
            .await
            .expect("create idempotent");
        assert_eq!(tok, tok2);
        // Lookup index + blob.
        assert_eq!(store.token_for_index("tenantA", bi).await.unwrap(), Some(tok.clone()));
        assert_eq!(
            store.blob_for_token("tenantA", &tok).await.unwrap().as_deref(),
            Some(&b"secret@x.fr"[..])
        );
    }
}
