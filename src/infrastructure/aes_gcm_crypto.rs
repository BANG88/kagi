use crate::domain::crypto::encryptor::Encryptor;
use crate::domain::error::DomainError;

pub struct AesGcmEncryptor;

impl Encryptor for AesGcmEncryptor {
    fn encrypt(&self, _plaintext: &[u8]) -> Result<Vec<u8>, DomainError> {
        todo!()
    }

    fn decrypt(&self, _ciphertext: &[u8]) -> Result<Vec<u8>, DomainError> {
        todo!()
    }
}
