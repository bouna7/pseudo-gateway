//! Trousseau de clés : chiffrement des valeurs + index aveugle de déduplication.
//!
//! - **Chiffrement** : chaque blob est `key_id(4, big-endian) || nonce(12) || ciphertext`.
//!   Le `key_id` rend le blob auto-descriptif → la rotation de clé (Phase 4) pourra
//!   ajouter de nouvelles versions sans rendre les anciens blobs indéchiffrables.
//! - **Blind index** : `HMAC-SHA256(index_key, tenant \0 type \0 valeur)`. Permet de
//!   dédupliquer (même valeur => même jeton) **sans stocker la valeur en clair**, et
//!   le `tenant` dans l'entrée empêche toute corrélation entre tenants.
//!
//! Phase 1 : une seule clé (id 1) issue de `MASTER_KEY` ; `index_key` dérivée de la
//! clé maître par HMAC (domaine séparé). Phase 4 remplacera ça par un `KeyProvider`
//! (Vault/KMS) avec vraie rotation et `index_key` stable indépendante.

use crate::crypto::Cipher;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::HashMap;

type HmacSha256 = Hmac<Sha256>;

pub struct Keyring {
    current_id: u32,
    ciphers: HashMap<u32, Cipher>,
    index_key: [u8; 32],
}

impl Keyring {
    /// Construit le trousseau à partir d'une clé maître 32 octets (clé courante = id 1).
    pub fn from_master(master: &[u8; 32]) -> Self {
        let mut ciphers = HashMap::new();
        ciphers.insert(1u32, Cipher::new(master));
        Keyring {
            current_id: 1,
            ciphers,
            index_key: derive_index_key(master),
        }
    }

    /// Chiffre une valeur avec la clé courante. Renvoie `key_id || nonce || ciphertext`.
    pub fn encrypt(&self, plaintext: &str) -> Vec<u8> {
        // `current_id` pointe toujours sur un cipher présent (invariant du constructeur).
        let body = self
            .ciphers
            .get(&self.current_id)
            .expect("la clé courante existe toujours dans le trousseau")
            .encrypt(plaintext);
        let mut out = self.current_id.to_be_bytes().to_vec();
        out.extend_from_slice(&body);
        out
    }

    /// Déchiffre un blob `key_id || nonce || ciphertext`. `None` si la clé est
    /// inconnue ou si l'authentification GCM échoue (intégrité compromise).
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
        // HMAC accepte une clé de n'importe quelle taille → `new_from_slice` est infaillible ici.
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

/// Dérive une clé d'index dédiée à partir de la clé maître (domaine séparé) pour ne
/// pas réutiliser la clé de chiffrement comme clé HMAC.
fn derive_index_key(master: &[u8; 32]) -> [u8; 32] {
    let mut mac =
        HmacSha256::new_from_slice(master).expect("HMAC accepte une clé de 32 octets");
    mac.update(b"pseudo-gateway/blind-index/v1");
    let out = mac.finalize().into_bytes();
    let mut key = [0u8; 32];
    key.copy_from_slice(&out[..32]);
    key
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
}
