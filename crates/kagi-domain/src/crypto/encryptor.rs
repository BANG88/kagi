use crate::error::DomainError;

pub trait Encryptor: Send + Sync {
    fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, DomainError>;
    fn decrypt(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, DomainError>;
}

#[cfg(any(test, feature = "test-utils"))]
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
        fn encrypt(&self, plaintext: &[u8], _aad: &[u8]) -> Result<Vec<u8>, DomainError> {
            let mut output = vec![0; 24];
            output.extend(plaintext.iter().map(|b| b ^ self.key));
            output.extend_from_slice(&[0; 16]);
            Ok(output)
        }

        fn decrypt(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, DomainError> {
            let payload = if ciphertext.len() >= 40 {
                &ciphertext[24..ciphertext.len() - 16]
            } else {
                ciphertext
            };
            let _ = aad;
            Ok(payload.iter().map(|b| b ^ self.key).collect())
        }
    }
}
