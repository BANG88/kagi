use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use base64::{Engine as _, engine::general_purpose};
use serde::{Deserialize, Serialize};
use crate::domain::crypto::encryptor::Encryptor;
use crate::domain::entity::service::Service;
use crate::domain::error::DomainError;
use crate::domain::repository::secret_repo::SecretRepository;

#[derive(Serialize, Deserialize)]
struct Config {
    version: String,
    services: HashMap<String, ServiceConfig>,
}

#[derive(Serialize, Deserialize)]
struct ServiceConfig {
    file: String,
}

#[derive(Serialize, Deserialize)]
struct EncryptedService {
    nonce: String,
    ciphertext: String,
    tag: String,
}

pub struct FileStore {
    base_path: PathBuf,
    encryptor: Box<dyn Encryptor>,
}

impl FileStore {
    pub fn new(base_path: PathBuf, encryptor: Box<dyn Encryptor>) -> Self {
        Self {
            base_path,
            encryptor,
        }
    }

    fn config_path(&self) -> PathBuf {
        self.base_path.join("config.json")
    }

    fn service_path(&self, file: &str) -> PathBuf {
        self.base_path.join(file)
    }

    fn load_config(&self) -> Result<Config, DomainError> {
        let content = fs::read_to_string(self.config_path())?;
        let config: Config = serde_json::from_str(&content)?;
        Ok(config)
    }

    fn save_config(&self, config: &Config) -> Result<(), DomainError> {
        let content = serde_json::to_string_pretty(config)?;
        fs::write(self.config_path(), content)?;
        Ok(())
    }
}

impl SecretRepository for FileStore {
    fn load(&self, service_name: &str) -> Result<Service, DomainError> {
        let config = self.load_config()?;
        let svc_config = config
            .services
            .get(service_name)
            .ok_or_else(|| DomainError::ServiceNotFound(service_name.into()))?;
        let content = fs::read_to_string(self.service_path(&svc_config.file))?;
        let enc: EncryptedService = serde_json::from_str(&content)?;
        let nonce = general_purpose::STANDARD.decode(&enc.nonce)
            .map_err(|e| DomainError::StoreCorrupted(e.to_string()))?;
        let ciphertext = general_purpose::STANDARD.decode(&enc.ciphertext)
            .map_err(|e| DomainError::StoreCorrupted(e.to_string()))?;
        let tag = general_purpose::STANDARD.decode(&enc.tag)
            .map_err(|e| DomainError::StoreCorrupted(e.to_string()))?;
        let mut data = nonce;
        data.extend_from_slice(&ciphertext);
        data.extend_from_slice(&tag);
        let decrypted = self.encryptor.decrypt(&data)?;
        let service: Service = serde_json::from_slice(&decrypted)?;
        Ok(service)
    }

    fn save(&self, service: &Service) -> Result<(), DomainError> {
        let mut config = self.load_config()?;
        let file_name = format!("services/{}.enc", service.name);
        let plaintext = serde_json::to_vec(service)?;
        let encrypted = self.encryptor.encrypt(&plaintext)?;
        if encrypted.len() < 28 {
            return Err(DomainError::EncryptFailed("encrypted data too short".into()));
        }
        let nonce = general_purpose::STANDARD.encode(&encrypted[..12]);
        let ciphertext = general_purpose::STANDARD.encode(&encrypted[12..encrypted.len()-16]);
        let tag = general_purpose::STANDARD.encode(&encrypted[encrypted.len()-16..]);
        let enc_service = EncryptedService {
            nonce,
            ciphertext,
            tag,
        };
        let service_file = self.service_path(&file_name);
        fs::create_dir_all(service_file.parent().unwrap())?;
        fs::write(&service_file, serde_json::to_string_pretty(&enc_service)?)?;
        config.services.insert(
            service.name.clone(),
            ServiceConfig { file: file_name },
        );
        self.save_config(&config)?;
        Ok(())
    }

    fn list_services(&self) -> Result<Vec<String>, DomainError> {
        let config = self.load_config()?;
        Ok(config.services.keys().cloned().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::crypto::encryptor::mock::XorEncryptor;
    use crate::domain::entity::secret::Secret;
    use tempfile::TempDir;

    fn create_store(dir: &TempDir) -> FileStore {
        let base = dir.path().join(".kagi");
        fs::create_dir(&base).unwrap();
        let config = Config {
            version: "1".into(),
            services: HashMap::new(),
        };
        fs::write(base.join("config.json"), serde_json::to_string(&config).unwrap()).unwrap();
        FileStore::new(base, Box::new(XorEncryptor::new(0xAB)))
    }

    #[test]
    fn test_save_and_load() {
        let dir = TempDir::new().unwrap();
        let store = create_store(&dir);
        let mut svc = Service::new("api");
        svc.set_secret(Secret::new("KEY", "val"));
        store.save(&svc).unwrap();
        let loaded = store.load("api").unwrap();
        assert_eq!(loaded.name, "api");
        assert_eq!(loaded.get_secret("KEY").unwrap().value, "val");
    }

    #[test]
    fn test_list_services() {
        let dir = TempDir::new().unwrap();
        let store = create_store(&dir);
        let mut svc = Service::new("api");
        svc.set_secret(Secret::new("K", "V"));
        store.save(&svc).unwrap();
        let list = store.list_services().unwrap();
        assert_eq!(list, vec!["api"]);
    }

    #[test]
    fn test_load_missing_service() {
        let dir = TempDir::new().unwrap();
        let store = create_store(&dir);
        let result = store.load("missing");
        assert!(matches!(result, Err(DomainError::ServiceNotFound(_))));
    }
}
