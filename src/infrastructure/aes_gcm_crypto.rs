use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use crate::domain::crypto::encryptor::Encryptor;
use crate::domain::error::DomainError;

pub struct AesGcmEncryptor {
    cipher: Aes256Gcm,
}

impl AesGcmEncryptor {
    pub fn new(key: &[u8; 32]) -> Self {
        let key = aes_gcm::Key::<Aes256Gcm>::from_slice(key);
        Self {
            cipher: Aes256Gcm::new(key),
        }
    }
}

impl Encryptor for AesGcmEncryptor {
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, DomainError> {
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = self
            .cipher
            .encrypt(&nonce, plaintext)
            .map_err(|e| DomainError::EncryptFailed(e.to_string()))?;
        let mut result = nonce.to_vec();
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, DomainError> {
        if data.len() < 12 {
            return Err(DomainError::DecryptFailed("data too short".into()));
        }
        let nonce = Nonce::from_slice(&data[..12]);
        let ciphertext = &data[12..];
        self.cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| DomainError::DecryptFailed(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip() {
        let key = [42u8; 32];
        let encryptor = AesGcmEncryptor::new(&key);
        let plaintext = b"hello secrets";
        let encrypted = encryptor.encrypt(plaintext).unwrap();
        assert_ne!(encrypted, plaintext.to_vec());
        let decrypted = encryptor.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext.to_vec());
    }

    #[test]
    fn test_decrypt_short_fails() {
        let key = [42u8; 32];
        let encryptor = AesGcmEncryptor::new(&key);
        let result = encryptor.decrypt(b"short");
        assert!(result.is_err());
    }
}
