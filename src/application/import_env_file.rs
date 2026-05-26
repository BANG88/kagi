use std::fs;
use crate::domain::env_parser::parse_dotenv;
use crate::domain::error::DomainError;
use crate::domain::repository::secret_repo::SecretRepository;
use crate::application::set_secret::SetSecretService;

pub struct ImportEnvFileService<R: SecretRepository> {
    set_service: SetSecretService<R>,
}

impl<R: SecretRepository> ImportEnvFileService<R> {
    pub fn new(repo: R) -> Self {
        Self {
            set_service: SetSecretService::new(repo),
        }
    }

    pub fn execute(&self, service_name: &str, file_path: &str) -> Result<Vec<String>, DomainError> {
        let content = fs::read_to_string(file_path)?;
        let vars = parse_dotenv(&content);
        let mut imported = Vec::new();
        for (key, value) in vars {
            self.set_service.execute(service_name, &key, &value)?;
            imported.push(key);
        }
        Ok(imported)
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
        std::fs::write(base.join("config.json"), serde_json::to_string(&config).unwrap()).unwrap();
        let store = FileStore::new(base, Box::new(XorEncryptor::new(0xAB)));
        ImportEnvFileService::new(store)
    }

    #[test]
    fn test_import_from_file() {
        let dir = TempDir::new().unwrap();
        let svc = setup(&dir);
        let env_file = dir.path().join("test.env");
        std::fs::write(&env_file, "KEY1=val1\nKEY2=val2\n").unwrap();
        let imported = svc.execute("api", env_file.to_str().unwrap()).unwrap();
        assert_eq!(imported, vec!["KEY1", "KEY2"]);
    }
}
