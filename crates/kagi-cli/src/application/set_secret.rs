use kagi_domain::entity::secret::Secret;
use kagi_domain::entity::service::Service;
use kagi_domain::error::DomainError;
use kagi_domain::repository::secret_repo::SecretRepository;

pub struct SetSecretService<R: SecretRepository> {
    repo: R,
}

impl<R: SecretRepository> SetSecretService<R> {
    pub fn new(repo: R) -> Self {
        Self { repo }
    }

    pub fn execute(
        &self,
        service_name: &str,
        key: &str,
        value: &str,
        description: Option<&str>,
    ) -> Result<(), DomainError> {
        let mut service = match self.repo.load(service_name) {
            Ok(s) => s,
            Err(DomainError::ServiceNotFound(_)) => Service::new(service_name),
            Err(e) => return Err(e),
        };
        let secret = if let Some(desc) = description {
            Secret::with_description(key, value, desc)
        } else {
            Secret::new(key, value)
        };
        service.set_secret(secret);
        self.repo.save(&service)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kagi_domain::crypto::encryptor::mock::XorEncryptor;
    use kagi_store::fs_store::FileStore;
    use tempfile::TempDir;

    fn create_service(dir: &TempDir) -> SetSecretService<FileStore> {
        let base = dir.path().join(".kagi");
        std::fs::create_dir(&base).unwrap();
        let config = serde_json::json!({"version": "2", "project_id": "kgp_test", "services": {}});
        std::fs::write(
            base.join(kagi_domain::config::KAGI_CONFIG_FILE),
            serde_json::to_string(&config).unwrap(),
        )
        .unwrap();
        let store = FileStore::new(base, Box::new(XorEncryptor::new(0xAB)));
        SetSecretService::new(store)
    }

    #[test]
    fn test_set_new_secret() {
        let dir = TempDir::new().unwrap();
        let svc = create_service(&dir);
        svc.execute("api", "KEY", "val", None).unwrap();
    }

    #[test]
    fn test_set_existing_service() {
        let dir = TempDir::new().unwrap();
        let svc = create_service(&dir);
        svc.execute("api", "A", "1", None).unwrap();
        svc.execute("api", "B", "2", None).unwrap();
    }

    #[test]
    fn test_set_secret_with_description() {
        let dir = TempDir::new().unwrap();
        let svc = create_service(&dir);
        svc.execute("api", "KEY", "val", Some("a description"))
            .unwrap();
        let loaded = svc.repo.load("api").unwrap();
        let secret = loaded.get_secret("KEY").unwrap();
        assert_eq!(secret.value, "val");
        assert_eq!(secret.description, Some("a description".into()));
    }
}
