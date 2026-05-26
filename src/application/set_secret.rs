use crate::domain::entity::secret::Secret;
use crate::domain::entity::service::Service;
use crate::domain::error::DomainError;
use crate::domain::repository::secret_repo::SecretRepository;

pub struct SetSecretService<R: SecretRepository> {
    repo: R,
}

impl<R: SecretRepository> SetSecretService<R> {
    pub fn new(repo: R) -> Self {
        Self { repo }
    }

    pub fn execute(&self, service_name: &str, key: &str, value: &str) -> Result<(), DomainError> {
        let mut service = match self.repo.load(service_name) {
            Ok(s) => s,
            Err(DomainError::ServiceNotFound(_)) => Service::new(service_name),
            Err(e) => return Err(e),
        };
        service.set_secret(Secret::new(key, value));
        self.repo.save(&service)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::crypto::encryptor::mock::XorEncryptor;
    use crate::infrastructure::fs_store::FileStore;
    use tempfile::TempDir;

    fn create_service(dir: &TempDir) -> SetSecretService<FileStore> {
        let base = dir.path().join(".kagi");
        std::fs::create_dir(&base).unwrap();
        let config = serde_json::json!({"version": "1", "services": {}});
        std::fs::write(base.join(crate::domain::config::KAGI_CONFIG_FILE), serde_json::to_string(&config).unwrap()).unwrap();
        let store = FileStore::new(base, Box::new(XorEncryptor::new(0xAB)));
        SetSecretService::new(store)
    }

    #[test]
    fn test_set_new_secret() {
        let dir = TempDir::new().unwrap();
        let svc = create_service(&dir);
        svc.execute("api", "KEY", "val").unwrap();
    }

    #[test]
    fn test_set_existing_service() {
        let dir = TempDir::new().unwrap();
        let svc = create_service(&dir);
        svc.execute("api", "A", "1").unwrap();
        svc.execute("api", "B", "2").unwrap();
    }
}
