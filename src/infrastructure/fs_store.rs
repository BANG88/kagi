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
        Ok(format!("secrets/{}.enc", service_name))
    }

    fn validate_env_name(env_name: &str) -> Result<(), DomainError> {
        if env_name.is_empty()
            || env_name.starts_with('/')
            || env_name.contains('/')
            || env_name.contains('\\')
            || env_name == "."
            || env_name == ".."
        {
            return Err(DomainError::StoreCorrupted(format!(
                "invalid environment name: {}",
                env_name
            )));
        }
        Ok(())
    }

    fn validate_configured_file(file: &str) -> Result<(), DomainError> {
        if !file.starts_with("secrets/")
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

    fn set_private_file_permissions(_path: &std::path::Path) -> Result<(), DomainError> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(_path, fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }

    fn set_private_dir_permissions(_path: &std::path::Path) -> Result<(), DomainError> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(_path, fs::Permissions::from_mode(0o700))?;
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

    pub fn default_envs(&self) -> Result<Vec<String>, DomainError> {
        Ok(self.load_config()?.settings.envs)
    }

    pub fn default_env(&self) -> Result<String, DomainError> {
        Ok(self.load_config()?.settings.default_env)
    }

    pub fn ensure_service_envs(&self, service_name: &str) -> Result<(), DomainError> {
        for env_name in self.default_envs()? {
            let scope = format!("{}/{}", service_name, env_name);
            match self.load(&scope) {
                Ok(_) => {}
                Err(DomainError::ServiceNotFound(_)) => self.save(&Service::new(scope))?,
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    pub fn encrypted_service_content(
        &self,
        service: &Service,
    ) -> Result<(String, String), DomainError> {
        let file_name = Self::service_file_name(&service.name)?;
        let plaintext = serde_json::to_vec(service)?;
        let aad = Self::aad_for_service(&service.name);
        let encrypted = self.encryptor.encrypt(&plaintext, &aad)?;
        if encrypted.len() < 40 {
            return Err(DomainError::EncryptFailed(
                "encrypted data too short".into(),
            ));
        }
        let enc_service = EncryptedService {
            version: Some(1),
            algorithm: Some(XCHACHA20_POLY1305.to_string()),
            nonce: general_purpose::STANDARD.encode(&encrypted[..24]),
            ciphertext: general_purpose::STANDARD.encode(&encrypted[24..encrypted.len() - 16]),
            aad: Some(general_purpose::STANDARD.encode(&aad)),
            tag: general_purpose::STANDARD.encode(&encrypted[encrypted.len() - 16..]),
        };
        Ok((file_name, serde_json::to_string_pretty(&enc_service)?))
    }

    #[cfg(feature = "server")]
    pub fn raw_service_content(&self, service_name: &str) -> Result<(String, String), DomainError> {
        let config = self.load_config()?;
        let svc_config = config
            .services
            .get(service_name)
            .ok_or_else(|| DomainError::ServiceNotFound(service_name.into()))?;
        Self::validate_configured_file(&svc_config.file)?;
        let content = std::fs::read_to_string(self.service_path(&svc_config.file))?;
        Ok((svc_config.file.clone(), content))
    }

    pub fn add_env(&self, env_name: &str) -> Result<(), DomainError> {
        Self::validate_env_name(env_name)?;
        let mut config = self.load_config()?;
        let service_names = service_names_from_config(&config);
        if service_names.iter().any(|service| service == env_name) {
            return Err(DomainError::StoreCorrupted(format!(
                "environment name conflicts with existing service: {}",
                env_name
            )));
        }
        if !config.settings.envs.iter().any(|env| env == env_name) {
            config.settings.envs.push(env_name.to_string());
            self.save_config(&config)?;
        }

        for service_name in service_names {
            self.ensure_service_envs(&service_name)?;
        }
        Ok(())
    }

    pub fn rename_env(&self, old_env: &str, new_env: &str) -> Result<(), DomainError> {
        Self::validate_env_name(old_env)?;
        Self::validate_env_name(new_env)?;
        if old_env == new_env {
            return Ok(());
        }

        let config = self.load_config()?;
        if !config.settings.envs.iter().any(|env| env == old_env) {
            return Err(DomainError::StoreCorrupted(format!(
                "environment not configured: {}",
                old_env
            )));
        }
        if config.settings.envs.iter().any(|env| env == new_env) {
            return Err(DomainError::StoreCorrupted(format!(
                "environment already exists: {}",
                new_env
            )));
        }

        let mut renames = Vec::new();
        for scope in config.services.keys() {
            if scope == old_env {
                renames.push((scope.clone(), new_env.to_string()));
            } else if let Some((service, env)) = scope.split_once('/')
                && env == old_env
            {
                renames.push((scope.clone(), format!("{}/{}", service, new_env)));
            }
        }

        for (_, new_scope) in &renames {
            if config.services.contains_key(new_scope) {
                return Err(DomainError::StoreCorrupted(format!(
                    "scope already exists: {}",
                    new_scope
                )));
            }
        }

        for (old_scope, new_scope) in renames {
            self.rename_scope(&old_scope, &new_scope)?;
        }

        let mut config = self.load_config()?;
        for env in &mut config.settings.envs {
            if env == old_env {
                *env = new_env.to_string();
            }
        }
        if config.settings.default_env == old_env {
            config.settings.default_env = new_env.to_string();
        }
        self.save_config(&config)?;
        Ok(())
    }

    pub fn delete_env(&self, env_name: &str) -> Result<(), DomainError> {
        Self::validate_env_name(env_name)?;
        let config = self.load_config()?;
        if config.settings.default_env == env_name {
            return Err(DomainError::StoreCorrupted(format!(
                "cannot delete default environment: {}",
                env_name
            )));
        }
        if !config.settings.envs.iter().any(|env| env == env_name) {
            return Err(DomainError::StoreCorrupted(format!(
                "environment not configured: {}",
                env_name
            )));
        }

        let delete_scopes: Vec<(String, String)> = config
            .services
            .iter()
            .filter_map(|(scope, svc)| {
                if scope == env_name {
                    Some((scope.clone(), svc.file.clone()))
                } else if let Some((_, env)) = scope.split_once('/')
                    && env == env_name
                {
                    Some((scope.clone(), svc.file.clone()))
                } else {
                    None
                }
            })
            .collect();

        let mut config = self.load_config()?;
        for (scope, file) in delete_scopes {
            config.services.remove(&scope);
            let path = self.service_path(&file);
            if path.exists() {
                fs::remove_file(path)?;
            }
        }
        config.settings.envs.retain(|env| env != env_name);
        self.save_config(&config)?;
        Ok(())
    }

    fn rename_scope(&self, old_scope: &str, new_scope: &str) -> Result<(), DomainError> {
        let config = self.load_config()?;
        let old_file = config
            .services
            .get(old_scope)
            .ok_or_else(|| DomainError::ServiceNotFound(old_scope.to_string()))?
            .file
            .clone();
        if config.services.contains_key(new_scope) {
            return Err(DomainError::StoreCorrupted(format!(
                "scope already exists: {}",
                new_scope
            )));
        }

        let mut service = self.load(old_scope)?;
        service.name = new_scope.to_string();
        self.save(&service)?;

        let mut config = self.load_config()?;
        config.services.remove(old_scope);
        self.save_config(&config)?;

        let old_path = self.service_path(&old_file);
        if old_path.exists() {
            fs::remove_file(old_path)?;
        }
        Ok(())
    }
}

fn service_names_from_config(config: &KagiConfig) -> Vec<String> {
    config
        .services
        .keys()
        .filter_map(|scope| {
            scope
                .split_once('/')
                .map(|(service, _)| service.to_string())
        })
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect()
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
        let (file_name, content) = self.encrypted_service_content(service)?;
        let service_file = self.service_path(&file_name);
        fs::create_dir_all(service_file.parent().unwrap())?;
        Self::set_private_dir_permissions(service_file.parent().unwrap())?;
        fs::write(&service_file, content)?;
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
        let config = KagiConfig::new("2", "kgp_test");
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
