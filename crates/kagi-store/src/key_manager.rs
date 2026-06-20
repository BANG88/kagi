use age::secrecy::ExposeSecret;
use age::{Decryptor, Encryptor, x25519};
use base64::{Engine as _, engine::general_purpose};
#[cfg(not(test))]
use directories::ProjectDirs;
use kagi_domain::config::{KAGI_CONFIG_FILE, KagiConfig};
use kagi_domain::error::DomainError;
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
    pub role: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wrapped_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wrapped_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing_public_key: Option<String>,
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
    project_id: Option<String>,
    #[cfg(any(test, feature = "test-utils"))]
    local_data_dir: Option<PathBuf>,
}

impl KeyManager {
    pub fn new(base_path: PathBuf) -> Self {
        Self {
            base_path,
            project_id: None,
            #[cfg(any(test, feature = "test-utils"))]
            local_data_dir: None,
        }
    }

    pub fn new_with_project_id(base_path: PathBuf, project_id: String) -> Self {
        Self {
            base_path,
            project_id: Some(project_id),
            #[cfg(any(test, feature = "test-utils"))]
            local_data_dir: None,
        }
    }

    #[cfg(any(test, feature = "test-utils"))]
    pub fn new_with_local_data_dir(base_path: PathBuf, local_data_dir: PathBuf) -> Self {
        Self {
            base_path,
            project_id: None,
            local_data_dir: Some(local_data_dir),
        }
    }

    #[cfg(any(test, feature = "test-utils"))]
    pub fn new_with_project_id_and_local_data_dir(
        base_path: PathBuf,
        project_id: String,
        local_data_dir: PathBuf,
    ) -> Self {
        Self {
            base_path,
            project_id: Some(project_id),
            local_data_dir: Some(local_data_dir),
        }
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
        let signing_key = generate_signing_keypair();
        let signing_public_key = base64_encode(&signing_key.verifying_key().to_bytes());
        self.save_signing_key(member_id, &signing_key)?;
        let member = MemberMetadata {
            member_id: member_id.to_string(),
            name: default_member_name(),
            recipient: recipient.to_string(),
            role: "owner".to_string(),
            status: "active".to_string(),
            wrapped_key: Some(wrap_key_for_recipient(&recipient, &key)?),
            wrapped_token: None,
            signing_public_key: Some(signing_public_key),
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
        let signing_key = generate_signing_keypair();
        let signing_public_key = base64_encode(&signing_key.verifying_key().to_bytes());
        self.save_signing_key(&member_id, &signing_key)?;
        let member = MemberMetadata {
            member_id: member_id.clone(),
            name: name
                .map(|name| name.trim().to_string())
                .filter(|name| !name.is_empty())
                .unwrap_or_else(default_member_name),
            recipient: identity.to_public().to_string(),
            role: "member".to_string(),
            status: "pending".to_string(),
            wrapped_key: None,
            wrapped_token: None,
            signing_public_key: Some(signing_public_key),
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

    pub fn validate_access_state(&self) -> Result<(), DomainError> {
        let _ = self.load_access_state()?;
        Ok(())
    }

    pub fn validate_access_json(access_json: &str) -> Result<(), DomainError> {
        let _ = parse_access_json(access_json)?;
        Ok(())
    }

    pub fn backup_access_json(&self, access_json: &str) -> Result<(), DomainError> {
        let state = parse_access_json(access_json)?;
        self.backup_access_state(&state)
    }

    pub fn restore_access_backup(&self) -> Result<(), DomainError> {
        let path = self.access_backup_path()?;
        if !path.exists() {
            return Err(DomainError::StoreCorrupted(
                "no local access backup found for this project".into(),
            ));
        }
        let content = fs::read_to_string(path)?;
        let state = parse_access_json(&content)?;
        self.write_access_state(&state)
    }

    #[cfg(feature = "server")]
    pub fn find_member(&self, member_id: &str) -> Result<Option<MemberMetadata>, DomainError> {
        let state = self.load_access_state()?;
        Ok(state
            .members
            .into_iter()
            .find(|member| member.member_id == member_id))
    }

    pub fn approve_join_request(&self, member_id: &str) -> Result<MemberMetadata, DomainError> {
        self.approve_join_request_with_optional_wrapped_token(member_id, None)
    }

    #[cfg(feature = "server")]
    pub fn delete_join_request(&self, member_id: &str) -> Result<(), DomainError> {
        let mut state = self.load_access_state()?;
        let before = state.members.len();
        state
            .members
            .retain(|member| member.member_id != member_id || member.status != "pending");
        if state.members.len() == before {
            return Err(DomainError::StoreCorrupted(format!(
                "pending member not found: {member_id}"
            )));
        }
        self.save_access_state(&state)?;
        Ok(())
    }

    #[cfg(feature = "server")]
    pub fn create_pending_member_from_server(
        &self,
        member_id: &str,
        name: &str,
        recipient: &str,
        signing_public_key: Option<&str>,
    ) -> Result<MemberMetadata, DomainError> {
        let member = MemberMetadata {
            member_id: member_id.to_string(),
            name: name.to_string(),
            recipient: recipient.to_string(),
            role: "member".to_string(),
            status: "pending".to_string(),
            wrapped_key: None,
            wrapped_token: None,
            signing_public_key: signing_public_key.map(std::string::ToString::to_string),
        };
        let mut state = self.load_access_state()?;
        upsert_member(&mut state.members, member.clone());
        self.save_access_state(&state)?;
        Ok(member)
    }

    #[cfg(feature = "server")]
    pub fn approve_join_request_with_wrapped_token(
        &self,
        member_id: &str,
        wrapped_token: &str,
    ) -> Result<MemberMetadata, DomainError> {
        self.approve_join_request_with_optional_wrapped_token(member_id, Some(wrapped_token))
    }

    fn approve_join_request_with_optional_wrapped_token(
        &self,
        member_id: &str,
        wrapped_token: Option<&str>,
    ) -> Result<MemberMetadata, DomainError> {
        let key = self.load()?;
        let mut state = self.load_access_state()?;
        self.require_local_owner(&state)?;
        let member = state
            .members
            .iter_mut()
            .find(|member| member.member_id == member_id && member.status == "pending")
            .ok_or_else(|| {
                DomainError::StoreCorrupted(format!("member request not found: {member_id}"))
            })?;
        let recipient = x25519::Recipient::from_str(&member.recipient)
            .map_err(|e| DomainError::StoreCorrupted(format!("invalid member recipient: {e}")))?;
        member.status = "active".to_string();
        member.wrapped_key = Some(wrap_key_for_recipient(&recipient, &key)?);
        if let Some(wrapped_token) = wrapped_token {
            member.wrapped_token = Some(wrapped_token.to_string());
        }
        let member = member.clone();
        self.save_access_state(&state)?;
        Ok(member)
    }

    pub fn promote_member(&self, member_id: &str) -> Result<MemberMetadata, DomainError> {
        let mut state = self.load_access_state()?;
        self.require_local_owner(&state)?;
        let member = state
            .members
            .iter_mut()
            .find(|member| member.member_id == member_id && member.status == "active")
            .ok_or_else(|| {
                DomainError::StoreCorrupted(format!("active member not found: {member_id}"))
            })?;
        member.role = "owner".to_string();
        let member = member.clone();
        self.save_access_state(&state)?;
        Ok(member)
    }

    pub fn demote_member(&self, member_id: &str) -> Result<MemberMetadata, DomainError> {
        let mut state = self.load_access_state()?;
        self.require_local_owner(&state)?;
        let active_owner_count = state
            .members
            .iter()
            .filter(|member| member.status == "active" && member.role == "owner")
            .count();
        let member = state
            .members
            .iter_mut()
            .find(|member| member.member_id == member_id && member.status == "active")
            .ok_or_else(|| {
                DomainError::StoreCorrupted(format!("active member not found: {member_id}"))
            })?;
        if member.role == "owner" && active_owner_count <= 1 {
            return Err(DomainError::StoreCorrupted(
                "cannot demote the last owner".into(),
            ));
        }
        member.role = "member".to_string();
        let member = member.clone();
        self.save_access_state(&state)?;
        Ok(member)
    }

    pub fn project_id(&self) -> Result<String, DomainError> {
        if let Some(project_id) = &self.project_id {
            if project_id.trim().is_empty() {
                return Err(DomainError::StoreCorrupted("missing project_id".into()));
            }
            return Ok(project_id.clone());
        }

        let content = fs::read_to_string(self.base_path.join(KAGI_CONFIG_FILE))?;
        let config: KagiConfig = serde_json::from_str(&content)?;
        if config.project_id.trim().is_empty() {
            return Err(DomainError::StoreCorrupted(
                "missing project_id in kagi.json".into(),
            ));
        }
        Ok(config.project_id)
    }

    #[cfg(feature = "server")]
    pub fn member_id(&self) -> Result<String, DomainError> {
        let identity = self.load_or_create_identity()?;
        let state = self.load_access_state()?;
        for member in state.members {
            if member.status != "active" {
                continue;
            }
            if let Some(wrapped_key) = member.wrapped_key {
                let encrypted = general_purpose::STANDARD
                    .decode(wrapped_key)
                    .map_err(|e| DomainError::StoreCorrupted(e.to_string()))?;
                if let Ok(key) = decrypt_with_identity(&identity, &encrypted)
                    && key.len() == 32
                {
                    return Ok(member.member_id);
                }
            }
        }
        Err(DomainError::StoreCorrupted(
            "no active member found for this device".into(),
        ))
    }

    #[cfg(feature = "server")]
    pub fn unwrap_member_token(&self) -> Result<Option<String>, DomainError> {
        let identity = self.load_or_create_identity()?;
        let state = self.load_access_state()?;
        for member in state.members {
            if member.status != "active" {
                continue;
            }
            let Some(wrapped_token) = member.wrapped_token else {
                continue;
            };
            let encrypted = general_purpose::STANDARD
                .decode(wrapped_token)
                .map_err(|e| DomainError::StoreCorrupted(e.to_string()))?;
            let Ok(token_bytes) = decrypt_with_identity(&identity, &encrypted) else {
                continue;
            };
            let token = String::from_utf8(token_bytes)
                .map_err(|e| DomainError::StoreCorrupted(format!("invalid token: {e}")))?;
            return Ok(Some(token));
        }
        Ok(None)
    }

    pub fn rotation_journal_path(&self) -> Result<PathBuf, DomainError> {
        Ok(self
            .local_data_dir()?
            .join(format!("projects/{}.rotation.json", self.project_id()?)))
    }

    pub fn cache_project_key(&self, key: &[u8]) -> Result<(), DomainError> {
        self.save_local_project_key(&self.project_id()?, key)
    }

    pub fn clear_cached_project_key(&self, project_id: &str) -> Result<(), DomainError> {
        let local_key_path = self.local_project_key_path(project_id)?;
        if local_key_path.exists() {
            fs::remove_file(local_key_path)?;
        }

        if !keyring_disabled()
            && let Ok(entry) = keyring_entry(project_id)
        {
            let _ = entry.delete_credential();
        }

        Ok(())
    }

    pub fn clear_rotation_journal(&self) -> Result<(), DomainError> {
        let path = self.rotation_journal_path()?;
        if path.exists() {
            fs::remove_file(path)?;
        }
        Ok(())
    }

    pub fn rotated_access_json(
        &self,
        key: &[u8],
        remove_member_id: Option<&str>,
    ) -> Result<String, DomainError> {
        let mut state = self.load_access_state()?;
        self.require_local_owner(&state)?;
        if let Some(member_id) = remove_member_id {
            let active_owner_count = state
                .members
                .iter()
                .filter(|member| member.status == "active" && member.role == "owner")
                .count();
            let member = state
                .members
                .iter_mut()
                .find(|member| member.member_id == member_id)
                .ok_or_else(|| {
                    DomainError::StoreCorrupted(format!("member not found: {member_id}"))
                })?;
            if member.status == "active" && member.role == "owner" && active_owner_count <= 1 {
                return Err(DomainError::StoreCorrupted(
                    "cannot remove the last owner".into(),
                ));
            }
            member.status = "removed".to_string();
            member.wrapped_key = None;
            member.wrapped_token = None;
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

    fn require_local_owner(&self, state: &AccessState) -> Result<(), DomainError> {
        let identity = self.load_identity().map_err(|_| {
            DomainError::StoreCorrupted(
                "only an owner can manage project members; local identity is missing".into(),
            )
        })?;
        for member in &state.members {
            if member.status != "active" || member.role != "owner" {
                continue;
            }
            let Some(wrapped_key) = &member.wrapped_key else {
                continue;
            };
            let encrypted = general_purpose::STANDARD
                .decode(wrapped_key)
                .map_err(|e| DomainError::StoreCorrupted(e.to_string()))?;
            if let Ok(key) = decrypt_with_identity(&identity, &encrypted)
                && key.len() == 32
            {
                return Ok(());
            }
        }
        Err(DomainError::StoreCorrupted(
            "only an owner can manage project members".into(),
        ))
    }

    fn load_access_state(&self) -> Result<AccessState, DomainError> {
        let path = self.base_path.join(ACCESS_FILE);
        if !path.exists() {
            return Ok(AccessState::default());
        }
        let content = fs::read_to_string(path)?;
        parse_access_json(&content)
    }

    fn save_access_state(&self, state: &AccessState) -> Result<(), DomainError> {
        validate_access_state(state)?;
        self.write_access_state(state)?;
        self.backup_access_state(state)?;
        Ok(())
    }

    fn write_access_state(&self, state: &AccessState) -> Result<(), DomainError> {
        fs::create_dir_all(&self.base_path)?;
        let path = self.base_path.join(ACCESS_FILE);
        fs::write(&path, serde_json::to_string_pretty(state)?)?;
        set_private_file_permissions(&path)?;
        Ok(())
    }

    fn backup_access_state(&self, state: &AccessState) -> Result<(), DomainError> {
        let path = self.access_backup_path()?;
        fs::create_dir_all(path.parent().unwrap())?;
        set_private_dir_permissions(path.parent().unwrap())?;
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
            "no access entry could be decrypted by the local identity. Run `kagi member request` or ask a member to approve access.".into(),
        ))
    }

    pub fn load_or_create_identity(&self) -> Result<x25519::Identity, DomainError> {
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
        let path = self.local_data_dir()?.join("identities/default.agekey");
        let content = fs::read_to_string(path)?;
        x25519::Identity::from_str(content.trim())
            .map_err(|e| DomainError::StoreCorrupted(format!("invalid local identity key: {e}")))
    }

    fn save_identity(&self, identity: &x25519::Identity) -> Result<(), DomainError> {
        let path = self.local_data_dir()?.join("identities/default.agekey");
        fs::create_dir_all(path.parent().unwrap())?;
        set_private_dir_permissions(path.parent().unwrap())?;
        fs::write(&path, identity.to_string().expose_secret())?;
        set_private_file_permissions(&path)?;
        Ok(())
    }

    fn local_project_key_path(&self, project_id: &str) -> Result<PathBuf, DomainError> {
        Ok(self
            .local_data_dir()?
            .join(format!("projects/{project_id}.key")))
    }

    fn access_backup_path(&self) -> Result<PathBuf, DomainError> {
        Ok(self
            .local_data_dir()?
            .join(format!("projects/{}.access.json", self.project_id()?)))
    }

    fn load_local_project_key(
        &self,
        project_id: &str,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, DomainError> {
        let path = self.local_project_key_path(project_id)?;
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

        let path = self.local_project_key_path(project_id)?;
        fs::create_dir_all(path.parent().unwrap())?;
        set_private_dir_permissions(path.parent().unwrap())?;
        fs::write(&path, hex::encode(key))?;
        set_private_file_permissions(&path)?;
        Ok(())
    }

    pub fn load_keyring_project_key(
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

    pub fn save_keyring_project_key(
        &self,
        project_id: &str,
        key: &[u8],
    ) -> Result<(), DomainError> {
        if keyring_disabled() {
            return Err(DomainError::StoreCorrupted("keyring disabled".into()));
        }
        let entry = keyring_entry(project_id)?;
        entry
            .set_password(&hex::encode(key))
            .map_err(|e| DomainError::StoreCorrupted(format!("keyring unavailable: {e}")))?;
        Ok(())
    }

    fn local_data_dir(&self) -> Result<PathBuf, DomainError> {
        #[cfg(any(test, feature = "test-utils"))]
        if let Some(path) = &self.local_data_dir {
            return Ok(path.clone());
        }
        local_data_dir()
    }

    fn signing_key_path(&self, member_id: &str) -> Result<PathBuf, DomainError> {
        Ok(self
            .local_data_dir()?
            .join(format!("identities/{member_id}.signkey")))
    }

    fn save_signing_key(
        &self,
        member_id: &str,
        key: &ed25519_dalek::SigningKey,
    ) -> Result<(), DomainError> {
        let path = self.signing_key_path(member_id)?;
        fs::create_dir_all(path.parent().unwrap())?;
        set_private_dir_permissions(path.parent().unwrap())?;
        fs::write(&path, base64_encode(&key.to_bytes()))?;
        set_private_file_permissions(&path)?;
        Ok(())
    }

    #[cfg(feature = "server")]
    pub fn load_signing_key(
        &self,
        member_id: &str,
    ) -> Result<ed25519_dalek::SigningKey, DomainError> {
        let path = self.signing_key_path(member_id)?;
        let b64 = fs::read_to_string(&path)?;
        let bytes = general_purpose::STANDARD
            .decode(b64.trim())
            .map_err(|e| DomainError::StoreCorrupted(format!("invalid signing key: {e}")))?;
        if bytes.len() != 32 {
            return Err(DomainError::StoreCorrupted(
                "signing key must be 32 bytes".into(),
            ));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(ed25519_dalek::SigningKey::from_bytes(&arr))
    }

    #[cfg(feature = "server")]
    pub fn ensure_signing_key(
        &self,
        member_id: &str,
    ) -> Result<ed25519_dalek::SigningKey, DomainError> {
        match self.load_signing_key(member_id) {
            Ok(key) => {
                let public_key = base64_encode(&key.verifying_key().to_bytes());
                let mut state = self.load_access_state()?;
                let mut updated = false;
                for member in &mut state.members {
                    if member.member_id == member_id {
                        if member.signing_public_key.as_deref() != Some(&public_key) {
                            member.signing_public_key = Some(public_key);
                            updated = true;
                        }
                        break;
                    }
                }
                if updated {
                    self.save_access_state(&state)?;
                }
                Ok(key)
            }
            Err(_) => {
                let key = generate_signing_keypair();
                let public_key = base64_encode(&key.verifying_key().to_bytes());
                self.save_signing_key(member_id, &key)?;
                let mut state = self.load_access_state()?;
                let mut updated = false;
                for member in &mut state.members {
                    if member.member_id == member_id {
                        member.signing_public_key = Some(public_key);
                        updated = true;
                        break;
                    }
                }
                if updated {
                    self.save_access_state(&state)?;
                }
                Ok(key)
            }
        }
    }
}

fn generate_signing_keypair() -> ed25519_dalek::SigningKey {
    let mut bytes = [0u8; 32];
    for byte in &mut bytes {
        *byte = rand::random::<u8>();
    }
    ed25519_dalek::SigningKey::from_bytes(&bytes)
}

fn base64_encode(bytes: &[u8]) -> String {
    general_purpose::STANDARD.encode(bytes)
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

fn parse_access_json(access_json: &str) -> Result<AccessState, DomainError> {
    let mut state: AccessState = serde_json::from_str(access_json)?;
    state.members.sort_by(|a, b| a.member_id.cmp(&b.member_id));
    validate_access_state(&state)?;
    Ok(state)
}

fn validate_access_state(state: &AccessState) -> Result<(), DomainError> {
    if state.members.is_empty() {
        return Ok(());
    }

    let mut active_owner_count = 0usize;
    for member in &state.members {
        match member.role.as_str() {
            "owner" | "member" => {}
            role => {
                return Err(DomainError::StoreCorrupted(format!(
                    "invalid member role for {}: {role}",
                    member.member_id
                )));
            }
        }
        match member.status.as_str() {
            "active" => {
                if member.wrapped_key.is_none() {
                    return Err(DomainError::StoreCorrupted(format!(
                        "active member {} is missing wrapped_key",
                        member.member_id
                    )));
                }
                if member.role == "owner" {
                    active_owner_count += 1;
                }
            }
            "pending" => {
                if member.wrapped_key.is_some() {
                    return Err(DomainError::StoreCorrupted(format!(
                        "pending member {} must not have wrapped_key",
                        member.member_id
                    )));
                }
            }
            "removed" => {}
            status => {
                return Err(DomainError::StoreCorrupted(format!(
                    "invalid member status for {}: {status}",
                    member.member_id
                )));
            }
        }
    }

    if active_owner_count == 0 {
        return Err(DomainError::StoreCorrupted(
            "access state must contain at least one active owner".into(),
        ));
    }
    Ok(())
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
        .map_err(|e| DomainError::StoreCorrupted(format!("keyring unavailable: {e}")))?;
    Entry::new(KEYRING_SERVICE, project_id)
        .map_err(|e| DomainError::StoreCorrupted(format!("keyring unavailable: {e}")))
}

#[cfg(feature = "server")]
pub fn keyring_admin_entry(server_fingerprint: &str) -> Result<Entry, DomainError> {
    keyring::use_native_store(false)
        .map_err(|e| DomainError::StoreCorrupted(format!("keyring unavailable: {e}")))?;
    let key = format!("admin:{server_fingerprint}");
    Entry::new(KEYRING_SERVICE, &key)
        .map_err(|e| DomainError::StoreCorrupted(format!("keyring unavailable: {e}")))
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

pub fn default_member_name() -> String {
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

        let km = KeyManager::new_with_local_data_dir(
            dir.path().join(".kagi"),
            local.path().to_path_buf(),
        );
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
        assert_eq!(access["members"][0]["role"], "owner");
        assert!(access["members"][0]["wrapped_key"].as_str().unwrap().len() > 20);
        assert!(local.path().join("projects/kgp_test.key").exists());
        assert!(local.path().join("identities/default.agekey").exists());
    }

    #[test]
    fn test_supplied_project_id_does_not_require_kagi_config_file() {
        let dir = TempDir::new().unwrap();
        let local = TempDir::new().unwrap();
        let base = dir.path().join(".osuki/vault");
        fs::create_dir_all(&base).unwrap();

        let km = KeyManager::new_with_project_id_and_local_data_dir(
            base.clone(),
            "kgp_osuki".to_string(),
            local.path().to_path_buf(),
        );

        assert_eq!(km.project_id().unwrap(), "kgp_osuki");
        let key = km.initialize_project("kgp_osuki", "kgm_owner").unwrap();
        let loaded = km.load().unwrap();

        assert_eq!(key.to_vec(), loaded.to_vec());
        assert!(base.join("access.json").exists());
        assert!(local.path().join("projects/kgp_osuki.key").exists());
        assert!(!base.join(KAGI_CONFIG_FILE).exists());
    }

    #[test]
    fn test_join_request_defaults_to_member_role() {
        let dir = TempDir::new().unwrap();
        let local = TempDir::new().unwrap();
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

        let km = KeyManager::new_with_local_data_dir(
            dir.path().join(".kagi"),
            local.path().to_path_buf(),
        );
        km.initialize_project("kgp_test", "kgm_owner").unwrap();
        let member = km.create_join_request(Some("alice".to_string())).unwrap();

        assert_eq!(member.status, "pending");
        assert_eq!(member.role, "member");
        assert!(member.wrapped_key.is_none());
    }

    #[test]
    fn test_access_state_requires_member_role() {
        let dir = TempDir::new().unwrap();
        let local = TempDir::new().unwrap();
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
        fs::write(
            dir.path().join(".kagi/access.json"),
            r#"{"version":"2","members":[{"member_id":"kgm_owner","name":"owner","recipient":"age1invalid","status":"active"}]}"#,
        )
        .unwrap();

        let km = KeyManager::new_with_local_data_dir(
            dir.path().join(".kagi"),
            local.path().to_path_buf(),
        );
        let err = km.list_members().unwrap_err();
        assert!(
            err.to_string().contains("missing field `role`"),
            "expected missing role error, got: {err}"
        );
    }

    #[test]
    fn test_cannot_remove_last_owner_during_rotation() {
        let dir = TempDir::new().unwrap();
        let local = TempDir::new().unwrap();
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

        let km = KeyManager::new_with_local_data_dir(
            dir.path().join(".kagi"),
            local.path().to_path_buf(),
        );
        km.initialize_project("kgp_test", "kgm_owner").unwrap();

        let err = km
            .rotated_access_json(&[9_u8; 32], Some("kgm_owner"))
            .unwrap_err();
        assert!(
            err.to_string().contains("last owner"),
            "expected last owner protection, got: {err}"
        );
    }

    #[test]
    fn test_non_owner_cannot_approve_join_request() {
        let dir = TempDir::new().unwrap();
        let local = TempDir::new().unwrap();
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

        let km = KeyManager::new_with_local_data_dir(
            dir.path().join(".kagi"),
            local.path().to_path_buf(),
        );
        km.initialize_project("kgp_test", "kgm_owner").unwrap();
        let pending = km.create_join_request(Some("alice".to_string())).unwrap();

        let access_path = dir.path().join(".kagi/access.json");
        let mut access: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&access_path).unwrap()).unwrap();
        access["members"][0]["role"] = serde_json::json!("member");
        fs::write(&access_path, serde_json::to_string_pretty(&access).unwrap()).unwrap();

        let err = km.approve_join_request(&pending.member_id).unwrap_err();
        assert!(
            err.to_string().contains("owner"),
            "expected owner permission error, got: {err}"
        );
    }

    #[test]
    fn test_promote_and_demote_member_roles() {
        let dir = TempDir::new().unwrap();
        let local = TempDir::new().unwrap();
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

        let km = KeyManager::new_with_local_data_dir(
            dir.path().join(".kagi"),
            local.path().to_path_buf(),
        );
        km.initialize_project("kgp_test", "kgm_owner").unwrap();
        let pending = km.create_join_request(Some("alice".to_string())).unwrap();
        km.approve_join_request(&pending.member_id).unwrap();

        let promoted = km.promote_member(&pending.member_id).unwrap();
        assert_eq!(promoted.role, "owner");

        let demoted = km.demote_member(&pending.member_id).unwrap();
        assert_eq!(demoted.role, "member");
    }

    #[test]
    fn test_cannot_demote_last_owner() {
        let dir = TempDir::new().unwrap();
        let local = TempDir::new().unwrap();
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

        let km = KeyManager::new_with_local_data_dir(
            dir.path().join(".kagi"),
            local.path().to_path_buf(),
        );
        km.initialize_project("kgp_test", "kgm_owner").unwrap();

        let err = km.demote_member("kgm_owner").unwrap_err();
        assert!(
            err.to_string().contains("last owner"),
            "expected last owner protection, got: {err}"
        );
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

    #[test]
    fn test_clear_cached_project_key() {
        let dir = tempfile::tempdir().unwrap();
        let local = tempfile::tempdir().unwrap();
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

        let km = KeyManager::new_with_local_data_dir(
            dir.path().join(".kagi"),
            local.path().to_path_buf(),
        );
        let project_id = km.project_id().unwrap();
        let key = vec![1u8; 32];

        km.save_local_project_key(&project_id, &key).unwrap();
        assert!(km.load_local_project_key(&project_id).unwrap().is_some());

        km.clear_cached_project_key(&project_id).unwrap();
        assert!(km.load_local_project_key(&project_id).unwrap().is_none());
    }

    #[test]
    fn test_clear_rotation_journal() {
        let dir = tempfile::tempdir().unwrap();
        let local = tempfile::tempdir().unwrap();
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

        let km = KeyManager::new_with_local_data_dir(
            dir.path().join(".kagi"),
            local.path().to_path_buf(),
        );
        let path = km.rotation_journal_path().unwrap();
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, "{}").unwrap();
        assert!(path.exists());

        km.clear_rotation_journal().unwrap();
        assert!(!path.exists());
    }
}
