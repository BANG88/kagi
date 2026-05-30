use kagi_domain::entity::secret::Secret;
use kagi_domain::entity::service::Service;
use kagi_domain::env_example_parser::parse_env_example;
use kagi_domain::error::DomainError;
use kagi_domain::repository::secret_repo::SecretRepository;
use std::collections::HashMap;

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

    pub fn execute(
        &self,
        example_path: &str,
        sources: &[String],
        target_envs: &[String],
    ) -> Result<SyncReport, DomainError> {
        let mut all_entries = Vec::new();

        if let Ok(example_content) = std::fs::read_to_string(example_path) {
            let mut entries = parse_env_example(&example_content);
            all_entries.append(&mut entries);
        }

        for source_path in sources {
            let source_content = std::fs::read_to_string(source_path)?;
            let mut source_entries = parse_env_example(&source_content);
            all_entries.append(&mut source_entries);
        }

        if all_entries.is_empty() {
            return Err(DomainError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "No valid entries found in .env.example or source files".to_string(),
            )));
        }

        let mut merged: Vec<(String, String, bool)> = Vec::new();
        for entry in all_entries {
            if let Some(pos) = merged.iter().position(|(k, _, _)| k == &entry.key) {
                merged[pos] = (entry.key, entry.value, entry.is_commented);
            } else {
                merged.push((entry.key, entry.value, entry.is_commented));
            }
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

            for (key, value, is_commented) in &merged {
                if service.secrets.contains_key(key) {
                    skipped.push(key.clone());
                    continue;
                }
                if *is_commented {
                    service.set_secret(Secret::new(key, ""));
                    commented.push(key.clone());
                } else {
                    service.set_secret(Secret::new(key, value));
                    added.push(key.clone());
                }
            }

            self.repo.save(&service)?;
            env_reports.insert(
                env_name.clone(),
                EnvSyncReport {
                    added,
                    commented,
                    skipped,
                },
            );
        }

        Ok(SyncReport { env_reports })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kagi_domain::crypto::encryptor::mock::XorEncryptor;
    use kagi_store::fs_store::FileStore;
    use tempfile::TempDir;

    fn setup(dir: &TempDir) -> SyncService<FileStore> {
        let base = dir.path().join(".kagi");
        std::fs::create_dir(&base).unwrap();
        let config = kagi_domain::config::KagiConfig::new("2", "kgp_test");
        std::fs::write(
            base.join(kagi_domain::config::KAGI_CONFIG_FILE),
            serde_json::to_string(&config).unwrap(),
        )
        .unwrap();
        let store = FileStore::new(base, Box::new(XorEncryptor::new(0xAB)));
        SyncService::new(store)
    }

    #[test]
    fn test_sync_adds_missing_keys() {
        let dir = TempDir::new().unwrap();
        let svc = setup(&dir);
        let example = dir.path().join(".env.example");
        std::fs::write(&example, "API_KEY=secret\nDEBUG=true\n").unwrap();

        let report = svc
            .execute(example.to_str().unwrap(), &[], &["development".into()])
            .unwrap();
        let development = report.env_reports.get("development").unwrap();
        assert_eq!(development.added, vec!["API_KEY", "DEBUG"]);
        assert!(development.commented.is_empty());
        assert!(development.skipped.is_empty());

        let loaded = svc.repo.load("development").unwrap();
        assert_eq!(loaded.get_secret("API_KEY").unwrap().value, "secret");
        assert_eq!(loaded.get_secret("DEBUG").unwrap().value, "true");
    }

    #[test]
    fn test_sync_commented_keys_added_empty() {
        let dir = TempDir::new().unwrap();
        let svc = setup(&dir);
        let example = dir.path().join(".env.example");
        std::fs::write(&example, "# WEBHOOK_SECRET=\n").unwrap();

        let report = svc
            .execute(example.to_str().unwrap(), &[], &["development".into()])
            .unwrap();
        let development = report.env_reports.get("development").unwrap();
        assert!(development.added.is_empty());
        assert_eq!(development.commented, vec!["WEBHOOK_SECRET"]);
        assert!(development.skipped.is_empty());

        let loaded = svc.repo.load("development").unwrap();
        assert_eq!(loaded.get_secret("WEBHOOK_SECRET").unwrap().value, "");
    }

    #[test]
    fn test_sync_skips_existing_keys() {
        let dir = TempDir::new().unwrap();
        let svc = setup(&dir);
        let example = dir.path().join(".env.example");
        std::fs::write(&example, "API_KEY=default\n").unwrap();

        let mut pre = Service::new("development");
        pre.set_secret(Secret::new("API_KEY", "existing"));
        svc.repo.save(&pre).unwrap();

        let report = svc
            .execute(example.to_str().unwrap(), &[], &["development".into()])
            .unwrap();
        let development = report.env_reports.get("development").unwrap();
        assert!(development.added.is_empty());
        assert!(development.commented.is_empty());
        assert_eq!(development.skipped, vec!["API_KEY"]);

        let loaded = svc.repo.load("development").unwrap();
        assert_eq!(loaded.get_secret("API_KEY").unwrap().value, "existing");
    }

    #[test]
    fn test_sync_multiple_envs() {
        let dir = TempDir::new().unwrap();
        let svc = setup(&dir);
        let example = dir.path().join(".env.example");
        std::fs::write(&example, "DB_URL=postgres\n").unwrap();

        let report = svc
            .execute(
                example.to_str().unwrap(),
                &[],
                &["development".into(), "test".into()],
            )
            .unwrap();
        assert!(report.env_reports.contains_key("development"));
        assert!(report.env_reports.contains_key("test"));
    }

    #[test]
    fn test_sync_empty_example_fails() {
        let dir = TempDir::new().unwrap();
        let svc = setup(&dir);
        let example = dir.path().join(".env.example");
        std::fs::write(&example, "# This is just a comment\n").unwrap();

        let result = svc.execute(example.to_str().unwrap(), &[], &["development".into()]);
        assert!(result.is_err());
    }

    #[test]
    fn test_sync_without_example_uses_sources_only() {
        let dir = TempDir::new().unwrap();
        let svc = setup(&dir);
        // deliberately do NOT create .env.example
        let source = dir.path().join(".env.local");
        std::fs::write(&source, "FEATURE_FLAG=true\n").unwrap();

        let report = svc
            .execute(
                ".env.example",
                &[source.to_str().unwrap().into()],
                &["development".into()],
            )
            .unwrap();
        let development = report.env_reports.get("development").unwrap();
        assert_eq!(development.added, vec!["FEATURE_FLAG"]);

        let loaded = svc.repo.load("development").unwrap();
        assert_eq!(loaded.get_secret("FEATURE_FLAG").unwrap().value, "true");
    }

    #[test]
    fn test_sync_sources_override_example() {
        let dir = TempDir::new().unwrap();
        let svc = setup(&dir);
        let example = dir.path().join(".env.example");
        std::fs::write(&example, "API_KEY=from_example\nDEBUG=true\n").unwrap();

        let override_file = dir.path().join(".env.override");
        std::fs::write(&override_file, "API_KEY=from_override\n").unwrap();

        let report = svc
            .execute(
                example.to_str().unwrap(),
                &[override_file.to_str().unwrap().into()],
                &["development".into()],
            )
            .unwrap();
        let development = report.env_reports.get("development").unwrap();
        assert_eq!(development.added, vec!["API_KEY", "DEBUG"]);

        let loaded = svc.repo.load("development").unwrap();
        assert_eq!(loaded.get_secret("API_KEY").unwrap().value, "from_override");
        assert_eq!(loaded.get_secret("DEBUG").unwrap().value, "true");
    }

    #[test]
    fn test_sync_sources_add_new_keys() {
        let dir = TempDir::new().unwrap();
        let svc = setup(&dir);
        let example = dir.path().join(".env.example");
        std::fs::write(&example, "API_KEY=default\n").unwrap();

        let extra = dir.path().join(".env.local");
        std::fs::write(&extra, "DB_URL=postgres\n").unwrap();

        let report = svc
            .execute(
                example.to_str().unwrap(),
                &[extra.to_str().unwrap().into()],
                &["development".into()],
            )
            .unwrap();
        let development = report.env_reports.get("development").unwrap();
        assert_eq!(development.added, vec!["API_KEY", "DB_URL"]);

        let loaded = svc.repo.load("development").unwrap();
        assert_eq!(loaded.get_secret("API_KEY").unwrap().value, "default");
        assert_eq!(loaded.get_secret("DB_URL").unwrap().value, "postgres");
    }
}
