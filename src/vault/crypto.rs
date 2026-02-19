use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use argon2::Argon2;
use rand::Rng;
use zeroize::Zeroize;

use crate::error::{Error, Result};

/// Salt length in bytes for Argon2id.
pub const SALT_LEN: usize = 16;

/// Nonce length in bytes for AES-256-GCM.
const NONCE_LEN: usize = 12;

/// Derive a 256-bit key from a password and salt using Argon2id.
pub fn derive_key(password: &[u8], salt: &[u8]) -> Result<[u8; 32]> {
    let argon2 = Argon2::default();

    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password, salt, &mut key)
        .map_err(|e| Error::Crypto(format!("argon2 hash: {e}")))?;

    Ok(key)
}

/// Encrypt plaintext with AES-256-GCM.
///
/// Returns `nonce (12 bytes) || ciphertext || auth tag (16 bytes)`.
pub fn encrypt(plaintext: &[u8], key: &[u8; 32]) -> Result<Vec<u8>> {
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|e| Error::Crypto(format!("aes init: {e}")))?;

    let nonce_bytes: [u8; NONCE_LEN] = rand::rng().random();
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| Error::Crypto(format!("aes encrypt: {e}")))?;

    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt data produced by [`encrypt`].
///
/// Expects `nonce (12 bytes) || ciphertext || auth tag (16 bytes)`.
pub fn decrypt(data: &[u8], key: &[u8; 32]) -> Result<Vec<u8>> {
    if data.len() < NONCE_LEN + 16 {
        return Err(Error::InvalidFormat);
    }

    let (nonce_bytes, ciphertext) = data.split_at(NONCE_LEN);
    let nonce = Nonce::from_slice(nonce_bytes);

    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|e| Error::Crypto(format!("aes init: {e}")))?;

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| Error::BadPassword)?;

    Ok(plaintext)
}

/// Generate a random salt for Argon2id.
pub fn generate_salt() -> [u8; SALT_LEN] {
    rand::rng().random()
}

/// Zeroize a key buffer. Call this when you're done with a derived key.
pub fn zeroize_key(key: &mut [u8; 32]) {
    key.zeroize();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_encrypt_decrypt() {
        let password = b"test-password-123";
        let salt = generate_salt();
        let key = derive_key(password, &salt).unwrap();

        let plaintext = b"hello, rahsia!";
        let encrypted = encrypt(plaintext, &key).unwrap();

        assert_ne!(&encrypted, plaintext);

        let decrypted = decrypt(&encrypted, &key).unwrap();
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn wrong_password_fails() {
        let salt = generate_salt();
        let key1 = derive_key(b"correct-password", &salt).unwrap();
        let key2 = derive_key(b"wrong-password", &salt).unwrap();

        let encrypted = encrypt(b"secret data", &key1).unwrap();
        let result = decrypt(&encrypted, &key2);

        assert!(result.is_err());
    }

    #[test]
    fn truncated_data_fails() {
        let result = decrypt(&[0u8; 10], &[0u8; 32]);
        assert!(result.is_err());
    }

    #[test]
    fn different_salt_produces_different_key() {
        let password = b"same-password";
        let key1 = derive_key(password, &generate_salt()).unwrap();
        let key2 = derive_key(password, &generate_salt()).unwrap();
        assert_ne!(key1, key2);
    }
}
