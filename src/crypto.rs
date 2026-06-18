//! Couche de chiffrement AES-256-GCM (AEAD).
//!
//! Chaque valeur sensible est chiffrée individuellement avec un nonce de 96 bits
//! généré aléatoirement. Le blob stocké est : nonce(12 octets) || ciphertext.
//! Le nonce ne doit JAMAIS être réutilisé avec la même clé : on en tire un neuf
//! à chaque appel à `encrypt`.

use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Key};

pub struct Cipher {
    inner: Aes256Gcm,
}

impl Cipher {
    pub fn new(key_bytes: &[u8; 32]) -> Self {
        let key = Key::<Aes256Gcm>::from_slice(key_bytes);
        Cipher {
            inner: Aes256Gcm::new(key),
        }
    }

    /// Chiffre `plaintext` et renvoie `nonce(12) || ciphertext`.
    pub fn encrypt(&self, plaintext: &str) -> Vec<u8> {
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // 96 bits, unique
        let ct = self
            .inner
            .encrypt(&nonce, plaintext.as_bytes())
            .expect("échec du chiffrement");
        let mut out = nonce.to_vec();
        out.extend_from_slice(&ct);
        out
    }

    /// Déchiffre un blob `nonce(12) || ciphertext`. Renvoie `None` si le blob
    /// est trop court ou si l'authentification GCM échoue (intégrité compromise).
    pub fn decrypt(&self, blob: &[u8]) -> Option<String> {
        if blob.len() < 12 {
            return None;
        }
        let (n, ct) = blob.split_at(12);
        let nonce = GenericArray::from_slice(n);
        let pt = self.inner.decrypt(nonce, ct).ok()?;
        String::from_utf8(pt).ok()
    }
}
