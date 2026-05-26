use std::collections::HashSet;
use std::fs;
use crate::domain::entity::secret::Secret;
use crate::domain::entity::service::Service;
use crate::domain::env_parser::parse_dotenv;
use crate::domain::error::DomainError;
use crate::domain::repository::secret_repo::SecretRepository;

pub struct ImportReport {
    pub imported: Vec<String>,
    pub overwritten: Vec<String>,
}

pub struct ImportEnvFileService<R: SecretRepository> {
    repo: R,
}

impl<R: SecretRepository> ImportEnvFileService<R> {
    pub fn new(repo: R) -> Self {
        Self { repo }
    }

    pub fn execute(&self, service_name: &str, file_path: &str, force: bool) -> Result<ImportReport, DomainError> {
        let content = fs::read_to_string(file_path)?;
        let vars = parse_dotenv(&content);

        let existing_keys: HashSet<String> = match self.repo.load(service_name) {
            Ok(svc) => svc.secrets.keys().cloned().collect(),
            Err(_) => HashSet::new(),
        };

        let mut imported = Vec::new();
        let mut overwritten = Vec::new();

        for (key, _value) in &vars {
            if existing_keys.contains(key) {
                overwritten.push(key.clone());
            }
            imported.push(key.clone());
        }

        // If conflicts exist and not forced, return preview without writing
        if !overwritten.is_empty() && !force {
            return Ok(ImportReport { imported, overwritten });
        }

        // Do actual import
        for (key, value) in vars {
            let mut service = match self.repo.load(service_name) {
                Ok(s) => s,
                Err(DomainError::ServiceNotFound(_)) => Service::new(service_name),
                Err(e) => return Err(e),
            };
            service.set_secret(Secret::new(&key, &value));
            self.repo.save(&service)?;
        }

        Ok(ImportReport { imported, overwritten })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::crypto::encryptor::mock::XorEncryptor;
    use crate::infrastructure::fs_store::FileStore;
    use tempfile::TempDir;

    fn setup(dir: &TempDir) -> ImportEnvFileService<FileStore> {
        let base = dir.path().join(".kagi");
        std::fs::create_dir(&base).unwrap();
        let config = serde_json::json!({"version": "1", "services": {}});
        std::fs::write(base.join(crate::domain::config::KAGI_CONFIG_FILE), serde_json::to_string(&config).unwrap()).unwrap();
        let store = FileStore::new(base, Box::new(XorEncryptor::new(0xAB)));
        ImportEnvFileService::new(store)
    }

    #[test]
    fn test_import_from_file() {
        let dir = TempDir::new().unwrap();
        let svc = setup(&dir);
        let env_file = dir.path().join("test.env");
        std::fs::write(&env_file, "KEY1=val1\nKEY2=val2\n").unwrap();
        let report = svc.execute("api", env_file.to_str().unwrap(), false).unwrap();
        assert_eq!(report.imported, vec!["KEY1", "KEY2"]);
        assert!(report.overwritten.is_empty());
    }

    #[test]
    fn test_import_detects_overwritten_keys_without_force() {
        let dir = TempDir::new().unwrap();
        let svc = setup(&dir);
        let env_file = dir.path().join("test.env");
        std::fs::write(&env_file, "KEY1=val1\nKEY2=val2\n").unwrap();
        svc.execute("api", env_file.to_str().unwrap(), false).unwrap();

        let env_file2 = dir.path().join("test2.env");
        std::fs::write(&env_file2, "KEY1=newval\nKEY3=val3\n").unwrap();
        let report = svc.execute("api", env_file2.to_str().unwrap(), false).unwrap();
        assert_eq!(report.imported, vec!["KEY1", "KEY3"]);
        assert_eq!(report.overwritten, vec!["KEY1"]);

        // Verify original value is NOT overwritten (force=false)
        let loaded = svc.repo.load("api").unwrap();
        assert_eq!(loaded.get_secret("KEY1").unwrap().value, "val1");
    }

    #[test]
    fn test_import_with_force_overwrites() {
        let dir = TempDir::new().unwrap();
        let svc = setup(&dir);
        let env_file = dir.path().join("test.env");
        std::fs::write(&env_file, "KEY1=val1\n").unwrap();
        svc.execute("api", env_file.to_str().unwrap(), false).unwrap();

        let env_file2 = dir.path().join("test2.env");
        std::fs::write(&env_file2, "KEY1=newval\n").unwrap();
        let report = svc.execute("api", env_file2.to_str().unwrap(), true).unwrap();
        assert_eq!(report.overwritten, vec!["KEY1"]);

        // Verify value IS overwritten (force=true)
        let loaded = svc.repo.load("api").unwrap();
        assert_eq!(loaded.get_secret("KEY1").unwrap().value, "newval");
    }
}
