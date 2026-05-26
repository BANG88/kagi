use crate::domain::crypto::encryptor::Encryptor;
use crate::domain::entity::service::Service;
use crate::domain::error::DomainError;
use crate::domain::repository::secret_repo::SecretRepository;
use std::path::PathBuf;

pub struct FileStore {
    _base_path: PathBuf,
    _encryptor: Box<dyn Encryptor>,
}

impl FileStore {
    pub fn new(base_path: PathBuf, encryptor: Box<dyn Encryptor>) -> Self {
        Self {
            _base_path: base_path,
            _encryptor: encryptor,
        }
    }
}

impl SecretRepository for FileStore {
    fn load(&self, _service_name: &str) -> Result<Service, DomainError> {
        todo!()
    }

    fn save(&self, _service: &Service) -> Result<(), DomainError> {
        todo!()
    }

    fn list_services(&self) -> Result<Vec<String>, DomainError> {
        todo!()
    }
}
