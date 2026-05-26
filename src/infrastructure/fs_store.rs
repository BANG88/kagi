use crate::domain::config::{KagiConfig, ServiceConfig};
use crate::domain::crypto::encryptor::Encryptor;
use crate::domain::entity::service::Service;
use crate::domain::error::DomainError;
use crate::domain::repository::secret_repo::SecretRepository;
use crate::infrastructure::xchacha_crypto::XCHACHA20_POLY1305;
use base64::{Engine as _, engine::general_purpose};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Serialize, Deserialize)]
struct EncryptedService {
    #[serde(default)]
    version: Option<u8>,
    #[serde(default)]
    algorithm: Option<String>,
    nonce: String,
    ciphertext: String,
    #[serde(default)]
    aad: Option<String>,
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
        self.base_path.join(crate::domain::config::KAGI_CONFIG_FILE)
    }

    fn service_path(&self, file: &str) -> PathBuf {
        self.base_path.join(file)
    }

    fn service_file_name(service_name: &str) -> Result<String, DomainError> {
        if service_name.is_empty()
            || service_name.starts_with('/')
            || service_name.contains('\\')
            || service_name
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == "..")
        {
            return Err(DomainError::StoreCorrupted(format!(
                "invalid service or environment name: {}",
                service_name
            )));
        }
        Ok(format!("services/{}.enc", service_name))
    }

    fn validate_configured_file(file: &str) -> Result<(), DomainError> {
        if !file.starts_with("services/")
            || file.starts_with('/')
            || file.contains('\\')
            || file
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == "..")
        {
            return Err(DomainError::StoreCorrupted(format!(
                "invalid encrypted service path: {}",
                file
            )));
        }
        Ok(())
    }

    fn aad_for_service(service_name: &str) -> Vec<u8> {
        format!("kagi:v1:{}:{}", XCHACHA20_POLY1305, service_name).into_bytes()
    }

    fn set_private_file_permissions(path: &std::path::Path) -> Result<(), DomainError> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }

    fn set_private_dir_permissions(path: &std::path::Path) -> Result<(), DomainError> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        }
        Ok(())
    }

    fn load_config(&self) -> Result<KagiConfig, DomainError> {
        let content = fs::read_to_string(self.config_path())?;
        let config: KagiConfig = serde_json::from_str(&content)?;
        Ok(config)
    }

    fn save_config(&self, config: &KagiConfig) -> Result<(), DomainError> {
        let content = serde_json::to_string_pretty(config)?;
        let path = self.config_path();
        fs::write(&path, content)?;
        Self::set_private_file_permissions(&path)?;
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
        Self::validate_configured_file(&svc_config.file)?;
        let content = fs::read_to_string(self.service_path(&svc_config.file))?;
        let enc: EncryptedService = serde_json::from_str(&content)?;
        let nonce = general_purpose::STANDARD
            .decode(&enc.nonce)
            .map_err(|e| DomainError::StoreCorrupted(e.to_string()))?;
        let ciphertext = general_purpose::STANDARD
            .decode(&enc.ciphertext)
            .map_err(|e| DomainError::StoreCorrupted(e.to_string()))?;
        let tag = general_purpose::STANDARD
            .decode(&enc.tag)
            .map_err(|e| DomainError::StoreCorrupted(e.to_string()))?;
        let mut data = nonce;
        data.extend_from_slice(&ciphertext);
        data.extend_from_slice(&tag);
        let aad = Self::aad_for_service(service_name);
        let decrypted = match enc.algorithm.as_deref() {
            Some(XCHACHA20_POLY1305) => self.encryptor.decrypt(&data, &aad)?,
            None => {
                return Err(DomainError::StoreCorrupted(
                    "missing encrypted store algorithm".into(),
                ));
            }
            Some(other) => {
                return Err(DomainError::StoreCorrupted(format!(
                    "unsupported algorithm: {}",
                    other
                )));
            }
        };
        let service: Service = serde_json::from_slice(&decrypted)?;
        Ok(service)
    }

    fn save(&self, service: &Service) -> Result<(), DomainError> {
        let mut config = self.load_config()?;
        let file_name = Self::service_file_name(&service.name)?;
        let plaintext = serde_json::to_vec(service)?;
        let aad = Self::aad_for_service(&service.name);
        let encrypted = self.encryptor.encrypt(&plaintext, &aad)?;
        if encrypted.len() < 40 {
            return Err(DomainError::EncryptFailed(
                "encrypted data too short".into(),
            ));
        }
        let nonce = general_purpose::STANDARD.encode(&encrypted[..24]);
        let ciphertext = general_purpose::STANDARD.encode(&encrypted[24..encrypted.len() - 16]);
        let tag = general_purpose::STANDARD.encode(&encrypted[encrypted.len() - 16..]);
        let enc_service = EncryptedService {
            version: Some(1),
            algorithm: Some(XCHACHA20_POLY1305.to_string()),
            nonce,
            ciphertext,
            aad: Some(general_purpose::STANDARD.encode(&aad)),
            tag,
        };
        let service_file = self.service_path(&file_name);
        fs::create_dir_all(service_file.parent().unwrap())?;
        Self::set_private_dir_permissions(service_file.parent().unwrap())?;
        fs::write(&service_file, serde_json::to_string_pretty(&enc_service)?)?;
        Self::set_private_file_permissions(&service_file)?;
        config
            .services
            .insert(service.name.clone(), ServiceConfig { file: file_name });
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
        let config = KagiConfig::new("1");
        fs::write(
            base.join(crate::domain::config::KAGI_CONFIG_FILE),
            serde_json::to_string(&config).unwrap(),
        )
        .unwrap();
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
