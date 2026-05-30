use kagi_domain::error::DomainError;
use kagi_domain::repository::secret_repo::SecretRepository;

pub struct ExportEnvService<R: SecretRepository> {
    repo: R,
}

impl<R: SecretRepository> ExportEnvService<R> {
    pub fn new(repo: R) -> Self {
        Self { repo }
    }

    pub fn execute(&self, service_name: &str) -> Result<String, DomainError> {
        let service = self.repo.load(service_name)?;
        let mut secrets: Vec<_> = service.secrets.values().collect();
        secrets.sort_by(|a, b| a.key.cmp(&b.key));
        let mut lines = Vec::new();
        for s in secrets {
            if let Some(desc) = &s.description {
                lines.push(format!("# {}", desc));
            }
            lines.push(format!("{}={}", s.key, s.value));
        }
        Ok(lines.join("\n"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kagi_domain::crypto::encryptor::mock::XorEncryptor;
    use kagi_domain::entity::secret::Secret;
    use kagi_domain::entity::service::Service;
    use kagi_store::fs_store::FileStore;
    use tempfile::TempDir;

    fn setup(dir: &TempDir) -> ExportEnvService<FileStore> {
        let base = dir.path().join(".kagi");
        std::fs::create_dir(&base).unwrap();
        let config = serde_json::json!({"version": "2", "project_id": "kgp_test", "services": {}});
        std::fs::write(
            base.join(kagi_domain::config::KAGI_CONFIG_FILE),
            serde_json::to_string(&config).unwrap(),
        )
        .unwrap();
        let store = FileStore::new(base, Box::new(XorEncryptor::new(0xAB)));
        let mut svc = Service::new("api");
        svc.set_secret(Secret::new("KEY", "val"));
        svc.set_secret(Secret::with_description(
            "DESC_KEY",
            "val2",
            "A description",
        ));
        store.save(&svc).unwrap();
        ExportEnvService::new(store)
    }

    #[test]
    fn test_export() {
        let dir = TempDir::new().unwrap();
        let svc = setup(&dir);
        let output = svc.execute("api").unwrap();
        assert_eq!(output, "# A description\nDESC_KEY=val2\nKEY=val");
    }
}
