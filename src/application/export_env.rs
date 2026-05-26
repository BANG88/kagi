use crate::domain::error::DomainError;
use crate::domain::repository::secret_repo::SecretRepository;

pub struct ExportEnvService<R: SecretRepository> {
    repo: R,
}

impl<R: SecretRepository> ExportEnvService<R> {
    pub fn new(repo: R) -> Self {
        Self { repo }
    }

    pub fn execute(&self, service_name: &str) -> Result<String, DomainError> {
        let service = self.repo.load(service_name)?;
        let mut lines: Vec<_> = service
            .secrets
            .values()
            .map(|s| format!("{}={}", s.key, s.value))
            .collect();
        lines.sort();
        Ok(lines.join("\n"))
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

    fn setup(dir: &TempDir) -> ExportEnvService<FileStore> {
        let base = dir.path().join(".kagi");
        std::fs::create_dir(&base).unwrap();
        let config = serde_json::json!({"version": "1", "services": {}});
        std::fs::write(
            base.join(crate::domain::config::KAGI_CONFIG_FILE),
            serde_json::to_string(&config).unwrap(),
        )
        .unwrap();
        let store = FileStore::new(base, Box::new(XorEncryptor::new(0xAB)));
        let mut svc = Service::new("api");
        svc.set_secret(Secret::new("KEY", "val"));
        store.save(&svc).unwrap();
        ExportEnvService::new(store)
    }

    #[test]
    fn test_export() {
        let dir = TempDir::new().unwrap();
        let svc = setup(&dir);
        let output = svc.execute("api").unwrap();
        assert_eq!(output, "KEY=val");
    }
}
