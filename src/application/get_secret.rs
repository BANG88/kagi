use crate::domain::error::DomainError;
use crate::domain::repository::secret_repo::SecretRepository;

pub struct GetSecretService<R: SecretRepository> {
    repo: R,
}

impl<R: SecretRepository> GetSecretService<R> {
    pub fn new(repo: R) -> Self {
        Self { repo }
    }

    pub fn execute(&self, service_name: &str, key: &str) -> Result<String, DomainError> {
        let service = self.repo.load(service_name)?;
        let secret = service
            .get_secret(key)
            .ok_or_else(|| DomainError::SecretNotFound(key.into()))?;
        Ok(secret.value.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::crypto::encryptor::mock::XorEncryptor;
    use crate::domain::entity::secret::Secret;
    use crate::domain::entity::service::Service;
    use crate::infrastructure::fs_store::FileStore;
    use tempfile::TempDir;

    fn setup(dir: &TempDir) -> GetSecretService<FileStore> {
        let base = dir.path().join(".kagi");
        std::fs::create_dir(&base).unwrap();
        let config = serde_json::json!({"version": "1", "services": {}});
        std::fs::write(base.join(crate::domain::config::KAGI_CONFIG_FILE), serde_json::to_string(&config).unwrap()).unwrap();
        let store = FileStore::new(base, Box::new(XorEncryptor::new(0xAB)));
        let mut svc = Service::new("api");
        svc.set_secret(Secret::new("KEY", "secret_value"));
        store.save(&svc).unwrap();
        GetSecretService::new(store)
    }

    #[test]
    fn test_get_existing_secret() {
        let dir = TempDir::new().unwrap();
        let svc = setup(&dir);
        let value = svc.execute("api", "KEY").unwrap();
        assert_eq!(value, "secret_value");
    }

    #[test]
    fn test_get_missing_secret() {
        let dir = TempDir::new().unwrap();
        let svc = setup(&dir);
        let result = svc.execute("api", "MISSING");
        assert!(matches!(result, Err(DomainError::SecretNotFound(_))));
    }
}
