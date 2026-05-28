use crate::domain::error::DomainError;
use crate::domain::sync::remote_config::RemoteMetadata;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::path::PathBuf;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TokenStore {
    pub version: u8,
    pub project_id: String,
    pub token: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ClaimSecretStore {
    pub version: u8,
    pub project_id: String,
    pub claim_secret: String,
}

pub struct RemoteLocalStore {
    local_data_dir: PathBuf,
}

impl RemoteLocalStore {
    pub fn new(local_data_dir: PathBuf) -> Self {
        Self { local_data_dir }
    }

    pub fn remote_metadata_path(&self, project_id: &str) -> PathBuf {
        self.local_data_dir
            .join(format!("projects/{}/remote.json", project_id))
    }

    pub fn token_path(&self, project_id: &str) -> PathBuf {
        self.local_data_dir
            .join(format!("projects/{}/token.json", project_id))
    }

    pub fn claim_secret_path(&self, project_id: &str) -> PathBuf {
        self.local_data_dir
            .join(format!("projects/{}/claim_secret.json", project_id))
    }

    pub fn save_remote_metadata(&self, meta: &RemoteMetadata) -> Result<(), DomainError> {
        let path = self.remote_metadata_path(&meta.project_id);
        ensure_private_dir(path.parent().unwrap())?;
        write_private_file(&path, serde_json::to_string_pretty(meta)?.as_bytes())?;
        Ok(())
    }

    pub fn load_remote_metadata(
        &self,
        project_id: &str,
    ) -> Result<Option<RemoteMetadata>, DomainError> {
        let path = self.remote_metadata_path(project_id);
        if !path.exists() {
            return Ok(None);
        }
        let content = fs::read_to_string(path)?;
        Ok(Some(serde_json::from_str(&content)?))
    }

    pub fn save_token(&self, project_id: &str, token: &str) -> Result<(), DomainError> {
        let path = self.token_path(project_id);
        ensure_private_dir(path.parent().unwrap())?;
        let store = TokenStore {
            version: 1,
            project_id: project_id.to_string(),
            token: token.to_string(),
        };
        write_private_file(&path, serde_json::to_string_pretty(&store)?.as_bytes())?;
        Ok(())
    }

    pub fn load_token(&self, project_id: &str) -> Result<Option<String>, DomainError> {
        let path = self.token_path(project_id);
        if !path.exists() {
            return Ok(None);
        }
        let content = fs::read_to_string(path)?;
        let store: TokenStore = serde_json::from_str(&content)?;
        Ok(Some(store.token))
    }

    pub fn save_claim_secret(
        &self,
        project_id: &str,
        claim_secret: &str,
    ) -> Result<(), DomainError> {
        let path = self.claim_secret_path(project_id);
        ensure_private_dir(path.parent().unwrap())?;
        let store = ClaimSecretStore {
            version: 1,
            project_id: project_id.to_string(),
            claim_secret: claim_secret.to_string(),
        };
        write_private_file(&path, serde_json::to_string_pretty(&store)?.as_bytes())?;
        Ok(())
    }

    pub fn load_claim_secret(&self, project_id: &str) -> Result<Option<String>, DomainError> {
        let path = self.claim_secret_path(project_id);
        if !path.exists() {
            return Ok(None);
        }
        let content = fs::read_to_string(path)?;
        let store: ClaimSecretStore = serde_json::from_str(&content)?;
        Ok(Some(store.claim_secret))
    }

    pub fn delete_claim_secret(&self, project_id: &str) -> Result<(), DomainError> {
        let path = self.claim_secret_path(project_id);
        if path.exists() {
            fs::remove_file(path)?;
        }
        Ok(())
    }

    // Admin tokens are stored exclusively in the OS keychain.
    // File-based storage has been removed for security.

    pub fn admin_remote_path(&self, server_fingerprint: &str) -> PathBuf {
        self.local_data_dir
            .join(format!("admins/{}/remote.json", server_fingerprint))
    }

    pub fn save_admin_remote(
        &self,
        server_fingerprint: &str,
        remote_url: &str,
    ) -> Result<(), DomainError> {
        let path = self.admin_remote_path(server_fingerprint);
        ensure_private_dir(path.parent().unwrap())?;
        let config = crate::domain::sync::remote_config::AdminRemoteConfig {
            version: 1,
            remote: remote_url.to_string(),
            server_fingerprint: server_fingerprint.to_string(),
        };
        write_private_file(&path, serde_json::to_string_pretty(&config)?.as_bytes())?;
        Ok(())
    }

    pub fn load_admin_remote(
        &self,
        server_fingerprint: &str,
    ) -> Result<Option<String>, DomainError> {
        let path = self.admin_remote_path(server_fingerprint);
        if !path.exists() {
            return Ok(None);
        }
        let content = fs::read_to_string(path)?;
        let config: crate::domain::sync::remote_config::AdminRemoteConfig =
            serde_json::from_str(&content)?;
        Ok(Some(config.remote))
    }
}

fn ensure_private_dir(path: &std::path::Path) -> Result<(), DomainError> {
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn write_private_file(path: &std::path::Path, content: &[u8]) -> Result<(), DomainError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(content)?;
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        Ok(())
    }

    #[cfg(not(unix))]
    {
        let mut file = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(path)?;
        file.write_all(content)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::sync::remote_config::RemoteMetadata;

    fn test_store() -> RemoteLocalStore {
        let dir = tempfile::tempdir().unwrap();
        RemoteLocalStore::new(dir.path().to_path_buf())
    }

    #[test]
    fn test_save_and_load_remote_metadata() {
        let store = test_store();
        let meta = RemoteMetadata {
            version: 1,
            project_id: "kgp_test".into(),
            remote: "http://localhost:13816".into(),
            server_key_id: "kgs_abc".into(),
            server_fingerprint: "fp_abc".into(),
            local_revision: Some(0),
            last_pulled_at: None,
            last_pushed_at: None,
            last_manifest_hash: None,
        };
        store.save_remote_metadata(&meta).unwrap();
        let loaded = store.load_remote_metadata("kgp_test").unwrap();
        assert!(loaded.is_some());
        let loaded = loaded.unwrap();
        assert_eq!(loaded.project_id, meta.project_id);
        assert_eq!(loaded.remote, meta.remote);
        assert_eq!(loaded.server_key_id, meta.server_key_id);
    }

    #[test]
    fn test_load_remote_metadata_missing() {
        let store = test_store();
        let loaded = store.load_remote_metadata("kgp_missing").unwrap();
        assert!(loaded.is_none());
    }

    #[test]
    fn test_save_and_load_token() {
        let store = test_store();
        store.save_token("kgp_test", "my_secret_token").unwrap();
        let loaded = store.load_token("kgp_test").unwrap();
        assert_eq!(loaded, Some("my_secret_token".to_string()));
    }

    #[test]
    #[cfg(unix)]
    fn test_token_file_uses_private_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let store = RemoteLocalStore::new(dir.path().to_path_buf());
        store.save_token("kgp_test", "my_secret_token").unwrap();

        let token_path = store.token_path("kgp_test");
        let project_dir = token_path.parent().unwrap();
        let dir_mode = fs::metadata(project_dir).unwrap().permissions().mode() & 0o777;
        let file_mode = fs::metadata(token_path).unwrap().permissions().mode() & 0o777;

        assert_eq!(dir_mode, 0o700);
        assert_eq!(file_mode, 0o600);
    }

    #[test]
    fn test_load_token_missing() {
        let store = test_store();
        let loaded = store.load_token("kgp_missing").unwrap();
        assert!(loaded.is_none());
    }

    #[test]
    fn test_save_and_load_admin_remote() {
        let store = test_store();
        store
            .save_admin_remote("kgs_abc", "http://localhost:13816")
            .unwrap();
        let loaded = store.load_admin_remote("kgs_abc").unwrap();
        assert_eq!(loaded, Some("http://localhost:13816".to_string()));
    }

    #[test]
    fn test_load_admin_remote_missing() {
        let store = test_store();
        let loaded = store.load_admin_remote("kgs_missing").unwrap();
        assert!(loaded.is_none());
    }
}
