use std::path::PathBuf;
use crate::domain::error::DomainError;

pub struct KeyManager {
    _base_path: PathBuf,
}

impl KeyManager {
    pub fn new(base_path: PathBuf) -> Self {
        Self { _base_path: base_path }
    }

    pub fn load(&self) -> Result<Vec<u8>, DomainError> {
        todo!()
    }

    pub fn generate_and_save(&self) -> Result<Vec<u8>, DomainError> {
        todo!()
    }
}
