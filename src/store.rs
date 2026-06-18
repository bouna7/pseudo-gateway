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
}
