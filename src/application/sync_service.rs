use std::collections::HashMap;
use crate::domain::entity::secret::Secret;
use crate::domain::entity::service::Service;
use crate::domain::env_example_parser::parse_env_example;
use crate::domain::error::DomainError;
use crate::domain::repository::secret_repo::SecretRepository;

pub struct EnvSyncReport {
    pub added: Vec<String>,
    pub commented: Vec<String>,
    pub skipped: Vec<String>,
}

pub struct SyncReport {
    pub env_reports: HashMap<String, EnvSyncReport>,
}

pub struct SyncService<R: SecretRepository> {
    repo: R,
}

impl<R: SecretRepository> SyncService<R> {
    pub fn new(repo: R) -> Self {
        Self { repo }
    }

    pub fn execute(&self, example_path: &str, target_envs: &[String]) -> Result<SyncReport, DomainError> {
        let content = std::fs::read_to_string(example_path)?;
        let entries = parse_env_example(&content);

        if entries.is_empty() {
            return Err(DomainError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(".env.example at {} contains no valid entries", example_path),
            )));
        }

        let mut env_reports = HashMap::new();

        for env_name in target_envs {
            let mut service = match self.repo.load(env_name) {
                Ok(s) => s,
                Err(DomainError::ServiceNotFound(_)) => Service::new(env_name),
                Err(e) => return Err(e),
            };

            let mut added = Vec::new();
            let mut commented = Vec::new();
            let mut skipped = Vec::new();

            for entry in &entries {
                if service.secrets.contains_key(&entry.key) {
                    skipped.push(entry.key.clone());
                    continue;
                }
                if entry.is_commented {
                    service.set_secret(Secret::new(&entry.key, ""));
                    commented.push(entry.key.clone());
                } else {
                    service.set_secret(Secret::new(&entry.key, &entry.value));
                    added.push(entry.key.clone());
                }
            }

            self.repo.save(&service)?;
            env_reports.insert(
                env_name.clone(),
                EnvSyncReport { added, commented, skipped },
            );
        }

        Ok(SyncReport { env_reports })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::crypto::encryptor::mock::XorEncryptor;
    use crate::infrastructure::fs_store::FileStore;
    use tempfile::TempDir;

    fn setup(dir: &TempDir) -> SyncService<FileStore> {
        let base = dir.path().join(".kagi");
        std::fs::create_dir(&base).unwrap();
        let config = crate::domain::config::KagiConfig::new("1");
        std::fs::write(base.join("config.json"), serde_json::to_string(&config).unwrap()).unwrap();
        let store = FileStore::new(base, Box::new(XorEncryptor::new(0xAB)));
        SyncService::new(store)
    }

    #[test]
    fn test_sync_adds_missing_keys() {
        let dir = TempDir::new().unwrap();
        let svc = setup(&dir);
        let example = dir.path().join(".env.example");
        std::fs::write(&example, "API_KEY=secret\nDEBUG=true\n").unwrap();

        let report = svc.execute(example.to_str().unwrap(), &["dev".into()]).unwrap();
        let dev = report.env_reports.get("dev").unwrap();
        assert_eq!(dev.added, vec!["API_KEY", "DEBUG"]);
        assert!(dev.commented.is_empty());
        assert!(dev.skipped.is_empty());

        let loaded = svc.repo.load("dev").unwrap();
        assert_eq!(loaded.get_secret("API_KEY").unwrap().value, "secret");
        assert_eq!(loaded.get_secret("DEBUG").unwrap().value, "true");
    }

    #[test]
    fn test_sync_commented_keys_added_empty() {
        let dir = TempDir::new().unwrap();
        let svc = setup(&dir);
        let example = dir.path().join(".env.example");
        std::fs::write(&example, "# WEBHOOK_SECRET=\n").unwrap();

        let report = svc.execute(example.to_str().unwrap(), &["dev".into()]).unwrap();
        let dev = report.env_reports.get("dev").unwrap();
        assert!(dev.added.is_empty());
        assert_eq!(dev.commented, vec!["WEBHOOK_SECRET"]);
        assert!(dev.skipped.is_empty());

        let loaded = svc.repo.load("dev").unwrap();
        assert_eq!(loaded.get_secret("WEBHOOK_SECRET").unwrap().value, "");
    }

    #[test]
    fn test_sync_skips_existing_keys() {
        let dir = TempDir::new().unwrap();
        let svc = setup(&dir);
        let example = dir.path().join(".env.example");
        std::fs::write(&example, "API_KEY=default\n").unwrap();

        let mut pre = Service::new("dev");
        pre.set_secret(Secret::new("API_KEY", "existing"));
        svc.repo.save(&pre).unwrap();

        let report = svc.execute(example.to_str().unwrap(), &["dev".into()]).unwrap();
        let dev = report.env_reports.get("dev").unwrap();
        assert!(dev.added.is_empty());
        assert!(dev.commented.is_empty());
        assert_eq!(dev.skipped, vec!["API_KEY"]);

        let loaded = svc.repo.load("dev").unwrap();
        assert_eq!(loaded.get_secret("API_KEY").unwrap().value, "existing");
    }

    #[test]
    fn test_sync_multiple_envs() {
        let dir = TempDir::new().unwrap();
        let svc = setup(&dir);
        let example = dir.path().join(".env.example");
        std::fs::write(&example, "DB_URL=postgres\n").unwrap();

        let report = svc.execute(example.to_str().unwrap(), &["dev".into(), "test".into()]).unwrap();
        assert!(report.env_reports.contains_key("dev"));
        assert!(report.env_reports.contains_key("test"));
    }

    #[test]
    fn test_sync_empty_example_fails() {
        let dir = TempDir::new().unwrap();
        let svc = setup(&dir);
        let example = dir.path().join(".env.example");
        std::fs::write(&example, "# This is just a comment\n").unwrap();

        let result = svc.execute(example.to_str().unwrap(), &["dev".into()]);
        assert!(result.is_err());
    }
}
