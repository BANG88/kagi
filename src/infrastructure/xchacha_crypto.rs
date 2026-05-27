use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, AeadCore, KeyInit, OsRng, Payload},
};

use crate::domain::crypto::encryptor::Encryptor;
use crate::domain::error::DomainError;

pub const XCHACHA20_POLY1305: &str = "XCHACHA20-POLY1305";

pub struct XChaChaEncryptor {
    cipher: XChaCha20Poly1305,
}

impl XChaChaEncryptor {
    pub fn new(key: &[u8; 32]) -> Self {
        Self {
            cipher: XChaCha20Poly1305::new(key.into()),
        }
    }
}

impl Encryptor for XChaChaEncryptor {
    fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, DomainError> {
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ciphertext = self
            .cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|e| DomainError::EncryptFailed(e.to_string()))?;
        let mut result = nonce.to_vec();
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    fn decrypt(&self, data: &[u8], aad: &[u8]) -> Result<Vec<u8>, DomainError> {
        if data.len() < 40 {
            return Err(DomainError::DecryptFailed("data too short".into()));
        }
        let nonce = XNonce::from_slice(&data[..24]);
        let ciphertext = &data[24..];
        self.cipher
            .decrypt(
                nonce,
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|e| DomainError::DecryptFailed(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip_with_aad() {
        let key = [42u8; 32];
        let encryptor = XChaChaEncryptor::new(&key);
        let encrypted = encryptor
            .encrypt(b"hello secrets", b"kagi:v1:development")
            .unwrap();
        assert_ne!(encrypted, b"hello secrets".to_vec());
        let decrypted = encryptor
            .decrypt(&encrypted, b"kagi:v1:development")
            .unwrap();
        assert_eq!(decrypted, b"hello secrets");
    }

    #[test]
    fn test_decrypt_wrong_aad_fails() {
        let key = [42u8; 32];
        let encryptor = XChaChaEncryptor::new(&key);
        let encrypted = encryptor
            .encrypt(b"hello secrets", b"kagi:v1:development")
            .unwrap();
        let result = encryptor.decrypt(&encrypted, b"kagi:v1:production");
        assert!(result.is_err());
    }
}
