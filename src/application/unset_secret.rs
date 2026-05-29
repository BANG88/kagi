use crate::domain::entity::service::Service;
use crate::domain::error::DomainError;
use crate::domain::repository::secret_repo::SecretRepository;

pub struct UnsetSecretService<R: SecretRepository> {
    repo: R,
}

impl<R: SecretRepository> UnsetSecretService<R> {
    pub fn new(repo: R) -> Self {
        Self { repo }
    }

    pub fn execute(&self, scope: &str, key: &str) -> Result<bool, DomainError> {
        let mut service = match self.repo.load(scope) {
            Ok(s) => s,
            Err(DomainError::ServiceNotFound(_)) => Service::new(scope),
            Err(e) => return Err(e),
        };
        let existed = service.delete_secret(key);
        if existed {
            self.repo.save(&service)?;
        }
        Ok(existed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::crypto::encryptor::mock::XorEncryptor;
    use crate::domain::entity::secret::Secret;
    use crate::infrastructure::fs_store::FileStore;
    use tempfile::TempDir;

    fn create_service(dir: &TempDir) -> UnsetSecretService<FileStore> {
        let base = dir.path().join(".kagi");
        std::fs::create_dir(&base).unwrap();
        let config = serde_json::json!({"version": "2", "project_id": "kgp_test", "services": {}});
        std::fs::write(
            base.join(crate::domain::config::KAGI_CONFIG_FILE),
            serde_json::to_string(&config).unwrap(),
        )
        .unwrap();
        let store = FileStore::new(base, Box::new(XorEncryptor::new(0xAB)));
        UnsetSecretService::new(store)
    }

    #[test]
    fn test_unset_existing_secret() {
        let dir = TempDir::new().unwrap();
        let svc = create_service(&dir);
        svc.repo
            .save(&{
                let mut s = Service::new("api");
                s.set_secret(Secret::new("KEY", "val"));
                s
            })
            .unwrap();
        let existed = svc.execute("api", "KEY").unwrap();
        assert!(existed);
        let loaded = svc.repo.load("api").unwrap();
        assert!(loaded.get_secret("KEY").is_none());
    }

    #[test]
    fn test_unset_missing_secret() {
        let dir = TempDir::new().unwrap();
        let svc = create_service(&dir);
        svc.repo.save(&Service::new("api")).unwrap();
        let existed = svc.execute("api", "MISSING").unwrap();
        assert!(!existed);
    }

    #[test]
    fn test_unset_missing_service() {
        let dir = TempDir::new().unwrap();
        let svc = create_service(&dir);
        let existed = svc.execute("api", "KEY").unwrap();
        assert!(!existed);
    }
}
