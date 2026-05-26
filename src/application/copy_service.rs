use crate::domain::entity::secret::Secret;
use crate::domain::entity::service::Service;
use crate::domain::error::DomainError;
use crate::domain::repository::secret_repo::SecretRepository;

pub struct CopyReport {
    pub copied: Vec<String>,
    pub skipped: Vec<String>,
}

pub struct CopyService<R: SecretRepository> {
    repo: R,
}

impl<R: SecretRepository> CopyService<R> {
    pub fn new(repo: R) -> Self {
        Self { repo }
    }

    pub fn execute(&self, source_name: &str, target_name: &str, only_missing: bool) -> Result<CopyReport, DomainError> {
        let source = self.repo.load(source_name)?;
        let mut target = match self.repo.load(target_name) {
            Ok(s) => s,
            Err(DomainError::ServiceNotFound(_)) => Service::new(target_name),
            Err(e) => return Err(e),
        };

        let mut copied = Vec::new();
        let mut skipped = Vec::new();

        for (key, secret) in &source.secrets {
            if target.secrets.contains_key(key) {
                if only_missing {
                    skipped.push(key.clone());
                    continue;
                }
            }
            target.set_secret(Secret::new(&secret.key, &secret.value));
            copied.push(key.clone());
        }

        self.repo.save(&target)?;
        Ok(CopyReport { copied, skipped })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::crypto::encryptor::mock::XorEncryptor;
    use crate::infrastructure::fs_store::FileStore;
    use tempfile::TempDir;

    fn setup(dir: &TempDir) -> CopyService<FileStore> {
        let base = dir.path().join(".kagi");
        std::fs::create_dir(&base).unwrap();
        let config = serde_json::json!({"version": "1", "services": {}});
        std::fs::write(base.join("config.json"), serde_json::to_string(&config).unwrap()).unwrap();
        let store = FileStore::new(base, Box::new(XorEncryptor::new(0xAB)));
        CopyService::new(store)
    }

    fn seed_service(store: &FileStore, name: &str, secrets: &[(&str, &str)]) {
        let mut svc = Service::new(name);
        for (k, v) in secrets {
            svc.set_secret(Secret::new(*k, *v));
        }
        store.save(&svc).unwrap();
    }

    #[test]
    fn test_copy_all_overwrites() {
        let dir = TempDir::new().unwrap();
        let store = FileStore::new(dir.path().join(".kagi"), Box::new(XorEncryptor::new(0xAB)));
        let base = dir.path().join(".kagi");
        std::fs::create_dir(&base).unwrap();
        let config = serde_json::json!({"version": "1", "services": {}});
        std::fs::write(base.join("config.json"), serde_json::to_string(&config).unwrap()).unwrap();

        seed_service(&store, "dev", &[("A", "1"), ("B", "2")]);
        seed_service(&store, "test", &[("B", "old"), ("C", "3")]);

        let copy_svc = CopyService::new(store);
        let report = copy_svc.execute("dev", "test", false).unwrap();

        let mut copied = report.copied;
        copied.sort();
        assert_eq!(copied, vec!["A", "B"]);
        assert!(report.skipped.is_empty());

        let test = copy_svc.repo.load("test").unwrap();
        assert_eq!(test.get_secret("A").unwrap().value, "1");
        assert_eq!(test.get_secret("B").unwrap().value, "2");
        assert_eq!(test.get_secret("C").unwrap().value, "3");
    }

    #[test]
    fn test_copy_only_missing() {
        let dir = TempDir::new().unwrap();
        let store = FileStore::new(dir.path().join(".kagi"), Box::new(XorEncryptor::new(0xAB)));
        let base = dir.path().join(".kagi");
        std::fs::create_dir(&base).unwrap();
        let config = serde_json::json!({"version": "1", "services": {}});
        std::fs::write(base.join("config.json"), serde_json::to_string(&config).unwrap()).unwrap();

        seed_service(&store, "dev", &[("A", "1"), ("B", "2")]);
        seed_service(&store, "test", &[("B", "old"), ("C", "3")]);

        let copy_svc = CopyService::new(store);
        let report = copy_svc.execute("dev", "test", true).unwrap();

        assert_eq!(report.copied, vec!["A"]);
        assert_eq!(report.skipped, vec!["B"]);

        let test = copy_svc.repo.load("test").unwrap();
        assert_eq!(test.get_secret("A").unwrap().value, "1");
        assert_eq!(test.get_secret("B").unwrap().value, "old");
        assert_eq!(test.get_secret("C").unwrap().value, "3");
    }

    #[test]
    fn test_copy_creates_target_if_missing() {
        let dir = TempDir::new().unwrap();
        let store = FileStore::new(dir.path().join(".kagi"), Box::new(XorEncryptor::new(0xAB)));
        let base = dir.path().join(".kagi");
        std::fs::create_dir(&base).unwrap();
        let config = serde_json::json!({"version": "1", "services": {}});
        std::fs::write(base.join("config.json"), serde_json::to_string(&config).unwrap()).unwrap();

        seed_service(&store, "dev", &[("X", "10")]);

        let copy_svc = CopyService::new(store);
        let report = copy_svc.execute("dev", "prod", true).unwrap();

        assert_eq!(report.copied, vec!["X"]);
        assert!(report.skipped.is_empty());

        let prod = copy_svc.repo.load("prod").unwrap();
        assert_eq!(prod.get_secret("X").unwrap().value, "10");
    }
}
