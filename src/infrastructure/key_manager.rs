use crate::domain::config::{KAGI_CONFIG_FILE, KagiConfig};
use crate::domain::error::DomainError;
use age::secrecy::ExposeSecret;
use age::{Decryptor, Encryptor, x25519};
use base64::{Engine as _, engine::general_purpose};
#[cfg(not(test))]
use directories::ProjectDirs;
use keyring_core::Entry;
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::str::FromStr;
use zeroize::Zeroizing;

const PROJECT_KEY_ENV: &str = "KAGI_PROJECT_KEY";
const PROJECT_KEY_FILE_ENV: &str = "KAGI_PROJECT_KEY_FILE";
const LOCAL_HOME_ENV: &str = "KAGI_HOME";
#[cfg(not(test))]
const DISABLE_KEYRING_ENV: &str = "KAGI_DISABLE_KEYRING";
const KEYRING_SERVICE: &str = "dev.kagi.kagi";
const ACCESS_FILE: &str = "access.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberMetadata {
    pub member_id: String,
    pub name: String,
    pub recipient: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wrapped_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AccessState {
    version: String,
    members: Vec<MemberMetadata>,
}

impl Default for AccessState {
    fn default() -> Self {
        Self {
            version: "2".to_string(),
            members: Vec::new(),
        }
    }
}

pub struct KeyManager {
    base_path: PathBuf,
}

impl KeyManager {
    pub fn new(base_path: PathBuf) -> Self {
        Self { base_path }
    }

    pub fn generate_project_id() -> String {
        format!("kgp_{}", nanoid::nanoid!(12))
    }

    pub fn generate_member_id() -> String {
        format!("kgm_{}", nanoid::nanoid!(12))
    }

    pub fn generate_project_key() -> Zeroizing<Vec<u8>> {
        generate_project_key()
    }

    pub fn load(&self) -> Result<Zeroizing<Vec<u8>>, DomainError> {
        if let Ok(key_hex) = env::var(PROJECT_KEY_ENV) {
            return decode_hex(key_hex.trim());
        }
        if let Ok(path) = env::var(PROJECT_KEY_FILE_ENV) {
            let key_hex = fs::read_to_string(path)?;
            return decode_hex(key_hex.trim());
        }

        let project_id = self.project_id()?;
        if let Ok(identity) = self.load_identity()
            && let Ok(key) = self.unwrap_access_key(&identity)
        {
            self.save_local_project_key(&project_id, &key)?;
            return Ok(key);
        }
        if let Some(key) = self.load_keyring_project_key(&project_id)? {
            return Ok(key);
        }
        if let Some(key) = self.load_local_project_key(&project_id)? {
            return Ok(key);
        }

        let identity = self.load_identity()?;
        let key = self.unwrap_access_key(&identity)?;
        self.save_local_project_key(&project_id, &key)?;
        Ok(key)
    }

    pub fn initialize_project(
        &self,
        project_id: &str,
        member_id: &str,
    ) -> Result<Zeroizing<Vec<u8>>, DomainError> {
        let identity = self.load_or_create_identity()?;
        let recipient = identity.to_public();
        let key = generate_project_key();
        let member = MemberMetadata {
            member_id: member_id.to_string(),
            name: default_member_name(),
            recipient: recipient.to_string(),
            status: "active".to_string(),
            wrapped_key: Some(wrap_key_for_recipient(&recipient, &key)?),
        };
        self.save_access_state(&AccessState {
            version: "2".to_string(),
            members: vec![member],
        })?;

        self.save_local_project_key(project_id, &key)?;
        Ok(key)
    }

    pub fn create_join_request(&self, name: Option<String>) -> Result<MemberMetadata, DomainError> {
        let identity = self.load_or_create_identity()?;
        let member_id = Self::generate_member_id();
        let member = MemberMetadata {
            member_id: member_id.clone(),
            name: name
                .map(|name| name.trim().to_string())
                .filter(|name| !name.is_empty())
                .unwrap_or_else(default_member_name),
            recipient: identity.to_public().to_string(),
            status: "pending".to_string(),
            wrapped_key: None,
        };
        let mut state = self.load_access_state()?;
        upsert_member(&mut state.members, member.clone());
        self.save_access_state(&state)?;
        Ok(member)
    }

    pub fn list_members(&self) -> Result<Vec<MemberMetadata>, DomainError> {
        let mut members: Vec<_> = self
            .load_access_state()?
            .members
            .into_iter()
            .filter(|member| member.status != "pending")
            .collect();
        members.sort_by(|a, b| a.member_id.cmp(&b.member_id));
        Ok(members)
    }

    pub fn list_join_requests(&self) -> Result<Vec<MemberMetadata>, DomainError> {
        let mut members: Vec<_> = self
            .load_access_state()?
            .members
            .into_iter()
            .filter(|member| member.status == "pending")
            .collect();
        members.sort_by(|a, b| a.member_id.cmp(&b.member_id));
        Ok(members)
    }

    pub fn approve_join_request(&self, member_id: &str) -> Result<MemberMetadata, DomainError> {
        let key = self.load()?;
        let mut state = self.load_access_state()?;
        let member = state
            .members
            .iter_mut()
            .find(|member| member.member_id == member_id && member.status == "pending")
            .ok_or_else(|| {
                DomainError::StoreCorrupted(format!("join request not found: {}", member_id))
            })?;
        let recipient = x25519::Recipient::from_str(&member.recipient)
            .map_err(|e| DomainError::StoreCorrupted(format!("invalid member recipient: {}", e)))?;
        member.status = "active".to_string();
        member.wrapped_key = Some(wrap_key_for_recipient(&recipient, &key)?);
        let member = member.clone();
        self.save_access_state(&state)?;
        Ok(member)
    }

    pub fn project_id(&self) -> Result<String, DomainError> {
        let content = fs::read_to_string(self.base_path.join(KAGI_CONFIG_FILE))?;
        let config: KagiConfig = serde_json::from_str(&content)?;
        if config.project_id.trim().is_empty() {
            return Err(DomainError::StoreCorrupted(
                "missing project_id in kagi.json".into(),
            ));
        }
        Ok(config.project_id)
    }

    pub fn rotation_journal_path(&self) -> Result<PathBuf, DomainError> {
        Ok(local_data_dir()?.join(format!("projects/{}.rotation.json", self.project_id()?)))
    }

    pub fn cache_project_key(&self, key: &[u8]) -> Result<(), DomainError> {
        self.save_local_project_key(&self.project_id()?, key)
    }

    pub fn rotated_access_json(
        &self,
        key: &[u8],
        remove_member_id: Option<&str>,
    ) -> Result<String, DomainError> {
        let mut state = self.load_access_state()?;
        if let Some(member_id) = remove_member_id {
            let active_count = state
                .members
                .iter()
                .filter(|member| member.status == "active")
                .count();
            let member = state
                .members
                .iter_mut()
                .find(|member| member.member_id == member_id)
                .ok_or_else(|| {
                    DomainError::StoreCorrupted(format!("member not found: {}", member_id))
                })?;
            if member.status == "active" && active_count <= 1 {
                return Err(DomainError::StoreCorrupted(
                    "cannot remove the last active member".into(),
                ));
            }
            member.status = "removed".to_string();
            member.wrapped_key = None;
        }

        let mut active_count = 0usize;
        for member in &mut state.members {
            if member.status != "active" {
                continue;
            }
            active_count += 1;
            let recipient = x25519::Recipient::from_str(&member.recipient).map_err(|e| {
                DomainError::StoreCorrupted(format!(
                    "invalid recipient for member {}: {}",
                    member.member_id, e
                ))
            })?;
            member.wrapped_key = Some(wrap_key_for_recipient(&recipient, key)?);
        }
        if active_count == 0 {
            return Err(DomainError::StoreCorrupted(
                "cannot rotate project key without active members".into(),
            ));
        }

        Ok(serde_json::to_string_pretty(&state)?)
    }

    fn load_access_state(&self) -> Result<AccessState, DomainError> {
        let path = self.base_path.join(ACCESS_FILE);
        if !path.exists() {
            return Ok(AccessState::default());
        }
        let content = fs::read_to_string(path)?;
        let mut state: AccessState = serde_json::from_str(&content)?;
        state.members.sort_by(|a, b| a.member_id.cmp(&b.member_id));
        Ok(state)
    }

    fn save_access_state(&self, state: &AccessState) -> Result<(), DomainError> {
        fs::create_dir_all(&self.base_path)?;
        let path = self.base_path.join(ACCESS_FILE);
        fs::write(&path, serde_json::to_string_pretty(state)?)?;
        set_private_file_permissions(&path)?;
        Ok(())
    }

    fn unwrap_access_key(
        &self,
        identity: &x25519::Identity,
    ) -> Result<Zeroizing<Vec<u8>>, DomainError> {
        let state = self.load_access_state()?;
        for member in state.members {
            if member.status != "active" {
                continue;
            }
            if let Some(wrapped_key) = member.wrapped_key {
                let encrypted = general_purpose::STANDARD
                    .decode(wrapped_key)
                    .map_err(|e| DomainError::StoreCorrupted(e.to_string()))?;
                if let Ok(key) = decrypt_with_identity(identity, &encrypted)
                    && key.len() == 32
                {
                    return Ok(Zeroizing::new(key));
                }
            }
        }

        Err(DomainError::StoreCorrupted(
            "no access entry could be decrypted by the local identity. Run `kagi join` or ask a member to approve access.".into(),
        ))
    }

    fn load_or_create_identity(&self) -> Result<x25519::Identity, DomainError> {
        match self.load_identity() {
            Ok(identity) => Ok(identity),
            Err(_) => {
                let identity = x25519::Identity::generate();
                self.save_identity(&identity)?;
                Ok(identity)
            }
        }
    }

    fn load_identity(&self) -> Result<x25519::Identity, DomainError> {
        let path = local_data_dir()?.join("identities/default.agekey");
        let content = fs::read_to_string(path)?;
        x25519::Identity::from_str(content.trim())
            .map_err(|e| DomainError::StoreCorrupted(format!("invalid local identity key: {}", e)))
    }

    fn save_identity(&self, identity: &x25519::Identity) -> Result<(), DomainError> {
        let path = local_data_dir()?.join("identities/default.agekey");
        fs::create_dir_all(path.parent().unwrap())?;
        set_private_dir_permissions(path.parent().unwrap())?;
        fs::write(&path, identity.to_string().expose_secret())?;
        set_private_file_permissions(&path)?;
        Ok(())
    }

    fn local_project_key_path(project_id: &str) -> Result<PathBuf, DomainError> {
        Ok(local_data_dir()?.join(format!("projects/{}.key", project_id)))
    }

    fn load_local_project_key(
        &self,
        project_id: &str,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, DomainError> {
        let path = Self::local_project_key_path(project_id)?;
        if !path.exists() {
            return Ok(None);
        }
        let key_hex = fs::read_to_string(path)?;
        Ok(Some(decode_hex(key_hex.trim())?))
    }

    fn save_local_project_key(&self, project_id: &str, key: &[u8]) -> Result<(), DomainError> {
        if self.save_keyring_project_key(project_id, key).is_ok() {
            return Ok(());
        }

        let path = Self::local_project_key_path(project_id)?;
        fs::create_dir_all(path.parent().unwrap())?;
        set_private_dir_permissions(path.parent().unwrap())?;
        fs::write(&path, hex::encode(key))?;
        set_private_file_permissions(&path)?;
        Ok(())
    }

    fn load_keyring_project_key(
        &self,
        project_id: &str,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, DomainError> {
        if keyring_disabled() {
            return Ok(None);
        }
        let Ok(entry) = keyring_entry(project_id) else {
            return Ok(None);
        };
        match entry.get_password() {
            Ok(key_hex) => Ok(Some(decode_hex(key_hex.trim())?)),
            Err(_) => Ok(None),
        }
    }

    fn save_keyring_project_key(&self, project_id: &str, key: &[u8]) -> Result<(), DomainError> {
        if keyring_disabled() {
            return Err(DomainError::StoreCorrupted("keyring disabled".into()));
        }
        let entry = keyring_entry(project_id)?;
        entry
            .set_password(&hex::encode(key))
            .map_err(|e| DomainError::StoreCorrupted(format!("keyring unavailable: {}", e)))?;
        Ok(())
    }
}

fn generate_project_key() -> Zeroizing<Vec<u8>> {
    Zeroizing::new((0..32).map(|_| rand::random::<u8>()).collect())
}

fn encrypt_for_recipient(
    recipient: &x25519::Recipient,
    plaintext: &[u8],
) -> Result<Vec<u8>, DomainError> {
    let encryptor = Encryptor::with_recipients(std::iter::once(recipient as _))
        .map_err(|e| DomainError::EncryptFailed(e.to_string()))?;
    let mut encrypted = Vec::new();
    let mut writer = encryptor
        .wrap_output(&mut encrypted)
        .map_err(|e| DomainError::EncryptFailed(e.to_string()))?;
    writer
        .write_all(plaintext)
        .map_err(|e| DomainError::EncryptFailed(e.to_string()))?;
    writer
        .finish()
        .map_err(|e| DomainError::EncryptFailed(e.to_string()))?;
    Ok(encrypted)
}

fn wrap_key_for_recipient(
    recipient: &x25519::Recipient,
    key: &[u8],
) -> Result<String, DomainError> {
    Ok(general_purpose::STANDARD.encode(encrypt_for_recipient(recipient, key)?))
}

fn upsert_member(members: &mut Vec<MemberMetadata>, member: MemberMetadata) {
    if let Some(existing) = members
        .iter_mut()
        .find(|existing| existing.member_id == member.member_id)
    {
        *existing = member;
    } else {
        members.push(member);
    }
}

fn decrypt_with_identity(
    identity: &x25519::Identity,
    encrypted: &[u8],
) -> Result<Vec<u8>, DomainError> {
    let decryptor =
        Decryptor::new(encrypted).map_err(|e| DomainError::DecryptFailed(e.to_string()))?;
    let mut reader = decryptor
        .decrypt(std::iter::once(identity as &dyn age::Identity))
        .map_err(|e| DomainError::DecryptFailed(e.to_string()))?;
    let mut decrypted = Vec::new();
    reader
        .read_to_end(&mut decrypted)
        .map_err(|e| DomainError::DecryptFailed(e.to_string()))?;
    Ok(decrypted)
}

fn decode_hex(s: &str) -> Result<Zeroizing<Vec<u8>>, DomainError> {
    if s.len() != 64 {
        return Err(DomainError::InvalidProjectKey);
    }
    let bytes = hex::decode(s).map_err(|_| DomainError::InvalidProjectKey)?;
    if bytes.len() != 32 {
        return Err(DomainError::InvalidProjectKey);
    }
    Ok(Zeroizing::new(bytes))
}

#[cfg(test)]
fn keyring_disabled() -> bool {
    true
}

#[cfg(not(test))]
fn keyring_disabled() -> bool {
    env::var_os(DISABLE_KEYRING_ENV).is_some() || env::var_os(LOCAL_HOME_ENV).is_some()
}

fn keyring_entry(project_id: &str) -> Result<Entry, DomainError> {
    keyring::use_native_store(false)
        .map_err(|e| DomainError::StoreCorrupted(format!("keyring unavailable: {}", e)))?;
    Entry::new(KEYRING_SERVICE, project_id)
        .map_err(|e| DomainError::StoreCorrupted(format!("keyring unavailable: {}", e)))
}

#[cfg(test)]
fn local_data_dir() -> Result<PathBuf, DomainError> {
    if let Ok(path) = env::var(LOCAL_HOME_ENV) {
        return Ok(PathBuf::from(path));
    }
    Ok(env::temp_dir().join("kagi-unit-tests"))
}

#[cfg(not(test))]
fn local_data_dir() -> Result<PathBuf, DomainError> {
    if let Ok(path) = env::var(LOCAL_HOME_ENV) {
        return Ok(PathBuf::from(path));
    }
    ProjectDirs::from("dev", "kagi", "kagi")
        .map(|dirs| dirs.data_dir().to_path_buf())
        .ok_or_else(|| DomainError::StoreCorrupted("failed to resolve local data directory".into()))
}

fn default_member_name() -> String {
    env::var("USER")
        .or_else(|_| env::var("USERNAME"))
        .unwrap_or_else(|_| "local".to_string())
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_initialize_and_load_project_key() {
        let dir = TempDir::new().unwrap();
        let local = TempDir::new().unwrap();
        unsafe {
            env::set_var(LOCAL_HOME_ENV, local.path());
        }
        fs::create_dir(dir.path().join(".kagi")).unwrap();
        let config = KagiConfig {
            version: "2".into(),
            project_id: "kgp_test".into(),
            services: Default::default(),
            settings: Default::default(),
        };
        fs::write(
            dir.path().join(".kagi").join(KAGI_CONFIG_FILE),
            serde_json::to_string(&config).unwrap(),
        )
        .unwrap();

        let km = KeyManager::new(dir.path().join(".kagi"));
        let key = km.initialize_project("kgp_test", "kgm_test").unwrap();
        assert_eq!(key.len(), 32);
        let loaded = km.load().unwrap();
        assert_eq!(key.to_vec(), loaded.to_vec());
        let access: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(dir.path().join(".kagi/access.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(access["members"].as_array().unwrap().len(), 1);
        assert_eq!(access["members"][0]["member_id"], "kgm_test");
        assert_eq!(access["members"][0]["status"], "active");
        assert!(access["members"][0]["wrapped_key"].as_str().unwrap().len() > 20);
        assert!(local.path().join("projects/kgp_test.key").exists());
        assert!(local.path().join("identities/default.agekey").exists());
        unsafe {
            env::remove_var(LOCAL_HOME_ENV);
        }
    }

    #[test]
    fn test_decode_hex_invalid_length() {
        let result = decode_hex("tooshort");
        assert!(matches!(result, Err(DomainError::InvalidProjectKey)));
    }

    #[test]
    fn test_decode_hex_invalid_chars() {
        let result = decode_hex("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz");
        assert!(matches!(result, Err(DomainError::InvalidProjectKey)));
    }
}
