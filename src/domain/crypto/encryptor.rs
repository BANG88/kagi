use crate::domain::error::DomainError;

pub trait Encryptor: Send + Sync {
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, DomainError>;
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, DomainError>;
}

#[cfg(test)]
pub mod mock {
    use super::*;

    pub struct XorEncryptor {
        key: u8,
    }

    impl XorEncryptor {
        pub fn new(key: u8) -> Self {
            Self { key }
        }
    }

    impl Encryptor for XorEncryptor {
        fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, DomainError> {
            Ok(plaintext.iter().map(|b| b ^ self.key).collect())
        }

        fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, DomainError> {
            self.encrypt(ciphertext)
        }
    }
}
