//! Trousseau de clés (chiffrement versionné + blind index) et **KeyProvider**.
//!
//! - **Chiffrement** : chaque blob est `key_id(4, big-endian) || nonce(12) || ciphertext`.
//!   Le `key_id` rend le blob auto-descriptif → la rotation ajoute de nouvelles
//!   versions de clé sans rendre les anciens blobs indéchiffrables.
//! - **Blind index** : `HMAC-SHA256(index_key, tenant \0 type \0 valeur)`. Déduplique
//!   sans stocker la valeur en clair ; le `tenant` empêche la corrélation entre tenants.
//!   La clé d'index doit rester **stable** au travers des rotations (sinon la
//!   déduplication casse), donc elle est séparée des clés de chiffrement.
//!
//! Le [`KeyProvider`] charge le trousseau. Aujourd'hui [`EnvKeyProvider`] (clés
//! versionnées dans l'environnement) ; un `VaultKeyProvider` (HashiCorp Vault / KMS)
//! implémentera le même trait sans rien changer ailleurs.

use crate::crypto::Cipher;
use async_trait::async_trait;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::{BTreeMap, HashMap};
use thiserror::Error;

type HmacSha256 = Hmac<Sha256>;

/// Erreurs de chargement / format de clé.
#[derive(Debug, Error)]
pub enum KeyError {
    #[error("{var} : clé non hexadécimale (attendu 64 caractères parmi 0-9 a-f)")]
    NotHex { var: String },
    /// Confusion fréquente : « 32 octets » s'écrit avec **64** caractères hex.
    /// `openssl rand -hex 64` en produit 128 — d'où ce message qui donne les deux
    /// unités et la commande qui ne peut pas se tromper.
    #[error(
        "{var} : clé de {bytes} octets, attendu 32 — soit 64 caractères \
         hexadécimaux, {chars} fournis. Générer : pseudo-gateway gen-keys"
    )]
    WrongLength {
        var: String,
        bytes: usize,
        chars: usize,
    },
    #[error("configuration de clé invalide : {0}")]
    Invalid(String),
}

/// Trousseau : plusieurs versions de clé de chiffrement (pour la rotation) +
/// une clé d'index stable.
pub struct Keyring {
    current_id: u32,
    ciphers: HashMap<u32, Cipher>,
    index_key: [u8; 32],
}

impl Keyring {
    /// Construit un trousseau explicite (utilisé par les fournisseurs de clés).
    pub fn new(ciphers: HashMap<u32, Cipher>, current_id: u32, index_key: [u8; 32]) -> Self {
        Keyring {
            current_id,
            ciphers,
            index_key,
        }
    }

    /// Trousseau à clé unique (id 1) issu d'une clé maître ; `index_key` dérivée
    /// de la clé maître (domaine séparé). Pratique pour le dev / la rétro-compat.
    pub fn from_master(master: &[u8; 32]) -> Self {
        let mut ciphers = HashMap::new();
        ciphers.insert(1u32, Cipher::new(master));
        Keyring {
            current_id: 1,
            ciphers,
            index_key: derive_index_key(master),
        }
    }

    /// Chiffre avec la clé courante. Renvoie `key_id || nonce || ciphertext`.
    pub fn encrypt(&self, plaintext: &str) -> Vec<u8> {
        let body = self
            .ciphers
            .get(&self.current_id)
            .expect("la clé courante existe toujours dans le trousseau")
            .encrypt(plaintext);
        let mut out = self.current_id.to_be_bytes().to_vec();
        out.extend_from_slice(&body);
        out
    }

    /// Déchiffre un blob `key_id || nonce || ciphertext`. `None` si la version de
    /// clé est inconnue (clé retirée) ou si l'authentification GCM échoue.
    pub fn decrypt(&self, blob: &[u8]) -> Option<String> {
        if blob.len() < 4 {
            return None;
        }
        let (id_bytes, rest) = blob.split_at(4);
        let id = u32::from_be_bytes([id_bytes[0], id_bytes[1], id_bytes[2], id_bytes[3]]);
        self.ciphers.get(&id)?.decrypt(rest)
    }

    /// Index aveugle d'une valeur, scopé par tenant + type (déduplication sans clair).
    pub fn blind_index(&self, tenant: &str, typ: &str, value: &str) -> String {
        let mut mac = HmacSha256::new_from_slice(&self.index_key)
            .expect("HMAC accepte une clé de 32 octets");
        mac.update(tenant.as_bytes());
        mac.update(&[0]);
        mac.update(typ.as_bytes());
        mac.update(&[0]);
        mac.update(value.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }
}

/// Dérive une clé d'index dédiée à partir d'une clé de chiffrement (domaine séparé).
fn derive_index_key(anchor: &[u8; 32]) -> [u8; 32] {
    let mut mac =
        HmacSha256::new_from_slice(anchor).expect("HMAC accepte une clé de 32 octets");
    mac.update(b"pseudo-gateway/blind-index/v1");
    let out = mac.finalize().into_bytes();
    let mut key = [0u8; 32];
    key.copy_from_slice(&out[..32]);
    key
}

// ─── Fournisseur de clés ──────────────────────────────────────────────────────

/// Source du trousseau de clés. Abstraction pour brancher plus tard un KMS / Vault.
#[async_trait]
pub trait KeyProvider: Send + Sync {
    async fn load(&self) -> Result<Keyring, KeyError>;
}

/// Charge les clés depuis l'environnement.
///
/// **Mode versionné (prod)** : une ou plusieurs `PSEUDO_KEY_<id>` (32 octets hex).
///   - `PSEUDO_CURRENT_KEY_ID` : version utilisée pour chiffrer (défaut = la plus grande).
///   - Les autres versions restent chargées pour déchiffrer les anciens blobs.
///   - `PSEUDO_INDEX_KEY` (hex) : clé d'index **stable** ; si absente, dérivée de la
///     plus petite `PSEUDO_KEY_<id>` (rester stable tant que cette clé existe).
///
/// **Repli (dev / rétro-compat)** : `MASTER_KEY` unique ; à défaut, clé éphémère.
pub struct EnvKeyProvider;

#[async_trait]
impl KeyProvider for EnvKeyProvider {
    async fn load(&self) -> Result<Keyring, KeyError> {
        load_from_env()
    }
}

/// `var` nomme la variable d'environnement fautive : sans elle, l'exploitant
/// doit deviner laquelle des trois clés est en cause.
fn parse_hex32(var: &str, hex_str: &str) -> Result<[u8; 32], KeyError> {
    let hex_str = hex_str.trim();
    let bytes = hex::decode(hex_str).map_err(|_| KeyError::NotHex {
        var: var.to_string(),
    })?;
    if bytes.len() != 32 {
        return Err(KeyError::WrongLength {
            var: var.to_string(),
            bytes: bytes.len(),
            chars: hex_str.len(),
        });
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

/// Lit une variable d'environnement en traitant « absente » ET « vide / espaces »
/// de la même façon (None). Évite qu'un `${VAR:-}` de docker-compose, qui injecte
/// une chaîne vide, soit pris pour une valeur fournie.
fn env_opt(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn load_from_env() -> Result<Keyring, KeyError> {
    // BTreeMap : ordonné par id (utile pour « plus petite » / « plus grande » version).
    let mut raw: BTreeMap<u32, [u8; 32]> = BTreeMap::new();
    for (name, value) in std::env::vars() {
        if let Some(suffix) = name.strip_prefix("PSEUDO_KEY_") {
            if let Ok(id) = suffix.parse::<u32>() {
                if value.trim().is_empty() {
                    continue; // variable injectée vide (ex. ${PSEUDO_KEY_2:-}) → ignorée
                }
                raw.insert(id, parse_hex32(&name, &value)?);
            }
        }
    }

    if !raw.is_empty() {
        // Version courante = explicite, sinon la plus grande disponible.
        let current_id = match env_opt("PSEUDO_CURRENT_KEY_ID") {
            Some(s) => s
                .parse::<u32>()
                .map_err(|_| KeyError::Invalid("PSEUDO_CURRENT_KEY_ID non numérique".into()))?,
            None => *raw.keys().next_back().expect("raw non vide"),
        };
        if !raw.contains_key(&current_id) {
            return Err(KeyError::Invalid(format!(
                "PSEUDO_CURRENT_KEY_ID={current_id} sans PSEUDO_KEY_{current_id}"
            )));
        }

        let index_key = match env_opt("PSEUDO_INDEX_KEY") {
            Some(h) => parse_hex32("PSEUDO_INDEX_KEY", &h)?,
            None => {
                let anchor_id = *raw.keys().next().expect("raw non vide");
                tracing::warn!(
                    "PSEUDO_INDEX_KEY absente — dérivée de PSEUDO_KEY_{anchor_id} \
                     (stable tant que cette clé reste présente)"
                );
                derive_index_key(raw.values().next().expect("raw non vide"))
            }
        };

        let ciphers: HashMap<u32, Cipher> =
            raw.iter().map(|(id, k)| (*id, Cipher::new(k))).collect();
        tracing::info!(
            versions = ciphers.len(),
            %current_id,
            "trousseau versionné chargé (rotation supportée)"
        );
        return Ok(Keyring::new(ciphers, current_id, index_key));
    }

    // Repli : clé unique MASTER_KEY, ou clé de DEV éphémère.
    match env_opt("MASTER_KEY") {
        Some(h) => Ok(Keyring::from_master(&parse_hex32("MASTER_KEY", &h)?)),
        None => {
            tracing::warn!(
                "aucune clé configurée (PSEUDO_KEY_* / MASTER_KEY) — clé de DEV éphémère, NON sûre"
            );
            use rand::RngCore;
            let mut k = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut k);
            Ok(Keyring::from_master(&k))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blind_index_deterministe_et_scope_par_tenant() {
        let kr = Keyring::from_master(&[1u8; 32]);
        let a1 = kr.blind_index("t1", "PERSON", "Marie");
        let a2 = kr.blind_index("t1", "PERSON", "Marie");
        let b = kr.blind_index("t2", "PERSON", "Marie");
        assert_eq!(a1, a2, "même (tenant, type, valeur) => même index");
        assert_ne!(a1, b, "tenant différent => index différent (pas de corrélation)");
    }

    #[test]
    fn chiffrement_round_trip_avec_unicode() {
        let kr = Keyring::from_master(&[2u8; 32]);
        let blob = kr.encrypt("Hélène €");
        assert_eq!(kr.decrypt(&blob).as_deref(), Some("Hélène €"));
        assert!(kr.decrypt(b"xx").is_none(), "blob trop court => None");
        assert_eq!(&blob[..4], &1u32.to_be_bytes(), "key_id en tête du blob");
    }

    #[test]
    fn rotation_les_anciens_blobs_restent_dechiffrables() {
        let index_key = [9u8; 32];

        // État initial : une seule clé (id 1).
        let mut c1 = HashMap::new();
        c1.insert(1u32, Cipher::new(&[1u8; 32]));
        let kr1 = Keyring::new(c1, 1, index_key);
        let blob_v1 = kr1.encrypt("secret-v1");
        assert_eq!(&blob_v1[..4], &1u32.to_be_bytes());

        // Rotation : on ajoute la clé 2 et on la rend courante (la clé 1 reste chargée).
        let mut c2 = HashMap::new();
        c2.insert(1u32, Cipher::new(&[1u8; 32]));
        c2.insert(2u32, Cipher::new(&[2u8; 32]));
        let kr2 = Keyring::new(c2, 2, index_key);

        // Ancien blob (chiffré v1) toujours déchiffrable.
        assert_eq!(kr2.decrypt(&blob_v1).as_deref(), Some("secret-v1"));
        // Nouveau chiffrement utilise la clé 2.
        let blob_v2 = kr2.encrypt("secret-v2");
        assert_eq!(&blob_v2[..4], &2u32.to_be_bytes());
        assert_eq!(kr2.decrypt(&blob_v2).as_deref(), Some("secret-v2"));
        // L'index reste stable au travers de la rotation (déduplication intacte).
        assert_eq!(
            kr1.blind_index("t", "EMAIL", "a@b.fr"),
            kr2.blind_index("t", "EMAIL", "a@b.fr")
        );

        // Un trousseau SANS la clé 2 ne peut pas déchiffrer un blob v2.
        let mut only1 = HashMap::new();
        only1.insert(1u32, Cipher::new(&[1u8; 32]));
        let kr_only1 = Keyring::new(only1, 1, index_key);
        assert!(kr_only1.decrypt(&blob_v2).is_none());
    }

    #[test]
    fn parse_hex32_valide_et_invalide() {
        assert!(parse_hex32("PSEUDO_KEY_1", &"ab".repeat(32)).is_ok());
        assert!(matches!(parse_hex32("PSEUDO_KEY_1", "zz"), Err(KeyError::NotHex { .. })));
                // Le cas vecu : `openssl rand -hex 64` donne 128 caracteres, soit 64 octets.
        let err = parse_hex32("PSEUDO_KEY_1", &"ab".repeat(64)).unwrap_err().to_string();
        assert!(err.contains("PSEUDO_KEY_1"), "{err}");
        assert!(err.contains("64 caractères hexadécimaux"), "{err}");
        assert!(err.contains("128 fournis"), "{err}");
        assert!(err.contains("gen-keys"), "{err}");
    }
}
