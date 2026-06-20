#![cfg(feature = "server")]

use anyhow::{Context, Result, anyhow};
use base64::Engine as _;
use ed25519_dalek::Signer;
use kagi_crypto::xchacha_crypto::XChaChaEncryptor;
use kagi_domain::config::KagiConfig;
use kagi_domain::repository::secret_repo::SecretRepository;
use kagi_store::fs_store::{FileStore, FileVaultConfigRepository, VaultConfigRepository};
use kagi_store::key_manager::{KeyManager, default_member_name};
use kagi_sync::domain::remote_config::RemoteMetadata;
use kagi_sync::infrastructure::remote_local::RemoteLocalStore;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Clone)]
struct SharedVaultConfigRepository {
    inner: Arc<dyn VaultConfigRepository>,
}

impl SharedVaultConfigRepository {
    fn new(inner: Arc<dyn VaultConfigRepository>) -> Self {
        Self { inner }
    }
}

impl VaultConfigRepository for SharedVaultConfigRepository {
    fn load_config(&self) -> Result<KagiConfig, kagi_domain::error::DomainError> {
        self.inner.load_config()
    }

    fn save_config(&self, config: &KagiConfig) -> Result<(), kagi_domain::error::DomainError> {
        self.inner.save_config(config)
    }
}

#[derive(Clone)]
pub struct RemoteProject {
    base_path: PathBuf,
    local_data_dir: PathBuf,
    config_repository: SharedVaultConfigRepository,
}

impl RemoteProject {
    pub fn from_kagi_base(base_path: PathBuf, local_data_dir: PathBuf) -> Self {
        let config_path = base_path.join(kagi_domain::config::KAGI_CONFIG_FILE);
        Self::new(
            base_path,
            local_data_dir,
            Arc::new(FileVaultConfigRepository::new(config_path)),
        )
    }

    pub fn new(
        base_path: PathBuf,
        local_data_dir: PathBuf,
        config_repository: Arc<dyn VaultConfigRepository>,
    ) -> Self {
        Self {
            base_path,
            local_data_dir,
            config_repository: SharedVaultConfigRepository::new(config_repository),
        }
    }

    pub fn base_path(&self) -> &Path {
        &self.base_path
    }

    pub fn local_data_dir(&self) -> &Path {
        &self.local_data_dir
    }

    pub fn load_config(&self) -> Result<KagiConfig> {
        Ok(self.config_repository.load_config()?)
    }

    pub fn save_config(&self, config: &KagiConfig) -> Result<()> {
        Ok(self.config_repository.save_config(config)?)
    }

    fn store(&self) -> Result<FileStore> {
        let project_key = KeyManager::new_with_project_id(
            self.base_path.clone(),
            self.load_config()?.project_id,
        )
        .load()
        .context(
            "Failed to load project key. Did you run `kagi init`? If this is a shared repository, run `kagi member request` to ask an active member to approve it, or set KAGI_PROJECT_KEY / KAGI_PROJECT_KEY_FILE for CI.",
        )?;
        let key_array: [u8; 32] = project_key
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("Invalid project key length"))?;
        Ok(FileStore::new_with_vault_config_repository(
            self.base_path.clone(),
            Box::new(XChaChaEncryptor::new(&key_array)),
            Box::new(self.config_repository.clone()),
        ))
    }
}

pub struct RemoteService {
    allow_insecure: bool,
}

impl RemoteService {
    pub fn new(allow_insecure: bool) -> Self {
        Self { allow_insecure }
    }

    pub async fn login(
        &self,
        local_data_dir: PathBuf,
        remote_url: &str,
        token: &str,
    ) -> Result<LoginResult> {
        let remote_client = kagi_sync::infrastructure::remote_client::RemoteClient::new(
            remote_url.to_string(),
            self.allow_insecure,
        )
        .await
        .map_err(|e| anyhow!("failed to connect to remote: {e}"))?;
        let fingerprint = remote_client.fingerprint().to_string();
        validate_admin_token_for_fingerprint(token, &fingerprint)?;

        let remote_store = RemoteLocalStore::new(local_data_dir);
        if admin_keyring_disabled() {
            remote_store
                .save_admin_token(&fingerprint, token)
                .map_err(|e| anyhow!("failed to save admin token: {e}"))?;
        } else {
            let entry =
                kagi_store::key_manager::keyring_admin_entry(&fingerprint).map_err(|e| {
                    anyhow!("keyring unavailable: {e}. admin token requires OS keychain.")
                })?;
            entry
                .set_password(token)
                .map_err(|e| anyhow!("failed to save admin token to keyring: {e}"))?;
        }
        remote_store
            .save_admin_remote(&fingerprint, remote_url)
            .map_err(|e| anyhow!("failed to save admin remote config: {e}"))?;

        Ok(LoginResult {
            remote: remote_url.to_string(),
            server_fingerprint: fingerprint,
        })
    }

    pub async fn register(
        &self,
        project: &RemoteProject,
        remote_url: &str,
    ) -> Result<RegisterResult> {
        if !project.base_path.is_dir() {
            return Err(anyhow!("no vault directory found. Run init first."));
        }

        let mut config = project.load_config()?;
        let existing_project_id = if config.project_id.trim().is_empty() {
            None
        } else {
            Some(config.project_id.clone())
        };

        let key_manager =
            KeyManager::new_with_project_id(project.base_path.clone(), config.project_id.clone());
        let identity = key_manager.load_or_create_identity()?;
        let recipient = identity.to_public();
        let name = default_member_name();
        let member_id = key_manager.member_id()?;

        let remote_client = kagi_sync::infrastructure::remote_client::RemoteClient::new(
            remote_url.to_string(),
            self.allow_insecure,
        )
        .await?;

        let claim_secret = format!(r"kgs_{}", nanoid::nanoid!(24));
        let claim_secret_hash = {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(claim_secret.as_bytes());
            format!(
                "cs:{}",
                kagi_sync::domain::project_token::base64_encode_url(&hasher.finalize())
            )
        };

        let request_id = format!(r"kgr_{}", nanoid::nanoid!(12));
        let plaintext = kagi_sync::domain::envelope::RequestPlaintext {
            version: 1,
            request_id: request_id.clone(),
            issued_at: now_rfc3339(),
            operation: "create_project_request".into(),
            method: "POST".into(),
            path: "/v1/projects/requests".into(),
            project_id: existing_project_id.clone(),
            token: None,
            claim_secret: None,
            payload: serde_json::json!({
                "requester_member_id": member_id,
                "requester_name": name,
                "requester_recipient": recipient.to_string(),
                "claim_secret_hash": claim_secret_hash,
            }),
        };

        let data = remote_client.send_request(&plaintext, &identity).await?;
        let project_id = data["project_id"]
            .as_str()
            .ok_or_else(|| anyhow!("missing project_id in response"))?
            .to_string();

        config.settings.sync = Some(serde_json::json!({
            "mode": "server",
            "remote": remote_url,
        }));
        if existing_project_id.is_none() {
            config.project_id = project_id.clone();
        }
        project.save_config(&config)?;

        let remote_store = RemoteLocalStore::new(project.local_data_dir.clone());
        remote_store.save_remote_metadata(&RemoteMetadata {
            version: 1,
            project_id: project_id.clone(),
            remote: remote_url.to_string(),
            server_key_id: remote_client.server_key_id().to_string(),
            server_fingerprint: remote_client.fingerprint().to_string(),
            local_revision: Some(0),
            last_pulled_at: None,
            last_pushed_at: None,
            last_manifest_hash: None,
            pending_token_ids: None,
            pending_accepted_member_ids: None,
        })?;
        remote_store.save_claim_secret(&project_id, &claim_secret)?;

        Ok(RegisterResult { project_id })
    }

    pub async fn push(&self, project: &RemoteProject) -> Result<PushResult> {
        let config = project.load_config()?;
        validate_config(&config)?;
        let project_id = config.project_id.as_str();
        let remote_url = remote_url(&config)
            .ok_or_else(|| anyhow!("missing remote URL. Run remote register first."))?;

        let remote_store = RemoteLocalStore::new(project.local_data_dir.clone());
        let token = remote_store
            .load_token(project_id)?
            .ok_or_else(|| anyhow!("no project token found"))?;
        let meta = remote_store
            .load_remote_metadata(project_id)?
            .ok_or_else(|| anyhow!("no remote metadata found"))?;
        let base_revision = meta.local_revision.unwrap_or(0);

        let key_manager =
            KeyManager::new_with_project_id(project.base_path.clone(), project_id.to_string());
        let identity = key_manager.load_or_create_identity()?;
        let member_id = key_manager.member_id()?;
        let signing_key = key_manager.ensure_signing_key(&member_id)?;
        let signing_public_key = base64::engine::general_purpose::STANDARD
            .encode(signing_key.verifying_key().to_bytes());

        let store = project.store()?;
        let kagi_json = serde_json::to_string_pretty(&config)?;
        let access_json = fs::read_to_string(project.base_path.join("access.json"))
            .unwrap_or_else(|_| "{}".to_string());
        let files = collect_project_state_files_for_push(&project.base_path, &store)?;

        let project_state = kagi_sync::domain::project_state::ProjectState {
            project_id: project_id.to_string(),
            revision: base_revision,
            kagi_json,
            access_json,
            files,
        };

        let previous_manifest_hash = if base_revision > 0 {
            Some(meta.last_manifest_hash.clone().ok_or_else(|| {
                anyhow!(
                    "missing local manifest hash for revision {base_revision}; run remote pull before pushing"
                )
            })?)
        } else {
            None
        };
        let manifest = kagi_sync::domain::manifest::ProjectStateManifest {
            version: 1,
            project_id: project_id.to_string(),
            revision: base_revision + 1,
            previous_manifest_hash,
            kagi_json_hash: kagi_sync::domain::manifest::hash_json(&project_state.kagi_json),
            access_json_hash: kagi_sync::domain::manifest::hash_json(&project_state.access_json),
            file_hashes: project_state
                .files
                .iter()
                .map(|f| kagi_sync::domain::manifest::FileHash {
                    path: f.path.clone(),
                    sha256: f.sha256.clone().unwrap_or_default(),
                })
                .collect(),
            timestamp: now_rfc3339(),
            signer_member_id: member_id,
            signer_public_key: signing_public_key,
        };
        let manifest_json = serde_json::to_string(&manifest)?;
        let manifest_hash = manifest.compute_hash();
        let signature = signing_key.sign(manifest_hash.as_bytes());
        let signature_b64 = base64::engine::general_purpose::STANDARD.encode(signature.to_bytes());

        let mut payload = serde_json::json!({
            "base_revision": base_revision,
            "state": project_state,
            "manifest": manifest_json,
            "manifest_signature": signature_b64,
        });
        if let Some(ref token_ids) = meta.pending_token_ids {
            payload["activate_token_ids"] = serde_json::json!(token_ids);
        }
        if let Some(ref member_ids) = meta.pending_accepted_member_ids {
            payload["accepted_join_member_ids"] = serde_json::json!(member_ids);
        }

        let request_id = format!(r"kgr_{}", nanoid::nanoid!(12));
        let plaintext = kagi_sync::domain::envelope::RequestPlaintext {
            version: 1,
            request_id: request_id.clone(),
            issued_at: now_rfc3339(),
            operation: "push".into(),
            method: "POST".into(),
            path: format!("/v1/projects/{project_id}/push"),
            project_id: Some(project_id.to_string()),
            token: Some(token),
            claim_secret: None,
            payload,
        };

        let client = kagi_sync::infrastructure::remote_client::RemoteClient::new_pinned(
            remote_url.to_string(),
            &meta.server_fingerprint,
            self.allow_insecure,
        )
        .await?;
        let data = client.send_request(&plaintext, &identity).await?;
        let new_revision = data["revision"].as_i64().unwrap_or(base_revision + 1);

        remote_store.save_remote_metadata(&RemoteMetadata {
            version: 1,
            project_id: project_id.to_string(),
            remote: remote_url.to_string(),
            server_key_id: meta.server_key_id,
            server_fingerprint: meta.server_fingerprint,
            local_revision: Some(new_revision),
            last_pulled_at: meta.last_pulled_at,
            last_pushed_at: Some(now_rfc3339()),
            last_manifest_hash: Some(manifest_hash),
            pending_token_ids: None,
            pending_accepted_member_ids: None,
        })?;

        Ok(PushResult {
            revision: new_revision,
        })
    }

    pub async fn pull(&self, project: &RemoteProject, token: Option<&str>) -> Result<PullResult> {
        if let Some(token) = token {
            return self.pull_with_token(project, token).await;
        }

        let config = project.load_config()?;
        validate_config(&config)?;
        let project_id = config.project_id.as_str();
        let remote_url = remote_url(&config).ok_or_else(|| anyhow!("missing remote URL"))?;
        let local_access_json = fs::read_to_string(project.base_path.join("access.json"))
            .unwrap_or_else(|_| "{}".to_string());

        let remote_store = RemoteLocalStore::new(project.local_data_dir.clone());
        let meta = remote_store
            .load_remote_metadata(project_id)?
            .ok_or_else(|| anyhow!("no remote metadata found"))?;
        let key_manager =
            KeyManager::new_with_project_id(project.base_path.clone(), project_id.to_string());
        let identity = key_manager.load_or_create_identity()?;
        let request_id = format!(r"kgr_{}", nanoid::nanoid!(12));

        let token = match remote_store.load_token(project_id)? {
            Some(token) => token,
            None => {
                let claim_secret = remote_store
                    .load_claim_secret(project_id)?
                    .ok_or_else(|| anyhow!("no claim secret found; run remote register first"))?;
                let member_id = key_manager.member_id()?;
                let claim_plaintext = kagi_sync::domain::envelope::RequestPlaintext {
                    version: 1,
                    request_id: request_id.clone(),
                    issued_at: now_rfc3339(),
                    operation: "pull".into(),
                    method: "POST".into(),
                    path: format!("/v1/projects/{project_id}/pull"),
                    project_id: Some(project_id.to_string()),
                    token: None,
                    claim_secret: Some(claim_secret.clone()),
                    payload: serde_json::json!({ "member_id": member_id }),
                };
                let client = kagi_sync::infrastructure::remote_client::RemoteClient::new_pinned(
                    remote_url.to_string(),
                    &meta.server_fingerprint,
                    self.allow_insecure,
                )
                .await?;
                let data = client.send_request(&claim_plaintext, &identity).await?;
                if let Some(wrapped_b64) =
                    data.get("wrapped_project_token").and_then(|v| v.as_str())
                {
                    let wrapped = base64::engine::general_purpose::URL_SAFE_NO_PAD
                        .decode(wrapped_b64)
                        .map_err(|e| anyhow!("invalid wrapped token: {e}"))?;
                    let decrypted = kagi_sync::infrastructure::remote_envelope::decrypt_bytes(
                        &wrapped, &identity,
                    )
                    .map_err(|e| anyhow!("failed to decrypt wrapped token: {e}"))?;
                    String::from_utf8(decrypted).map_err(|e| anyhow!("invalid token: {e}"))?
                } else {
                    return Err(anyhow!(
                        "no project token available; run remote register first or ask admin to approve"
                    ));
                }
            }
        };
        self.pull_inner(project, remote_url, &token, Some(meta), &local_access_json)
            .await
    }

    pub async fn status(&self, project: &RemoteProject) -> Result<StatusResult> {
        let config = project.load_config()?;
        validate_config(&config)?;
        let project_id = config.project_id.as_str();
        let remote_url = remote_url(&config).ok_or_else(|| anyhow!("missing remote URL"))?;

        let remote_store = RemoteLocalStore::new(project.local_data_dir.clone());
        let token = remote_store
            .load_token(project_id)?
            .ok_or_else(|| anyhow!("no project token found"))?;
        let meta = remote_store
            .load_remote_metadata(project_id)?
            .ok_or_else(|| anyhow!("no remote metadata found"))?;
        let local_revision = meta.local_revision.unwrap_or(0);

        let key_manager =
            KeyManager::new_with_project_id(project.base_path.clone(), project_id.to_string());
        let identity = key_manager.load_or_create_identity()?;
        let request_id = format!(r"kgr_{}", nanoid::nanoid!(12));
        let plaintext = kagi_sync::domain::envelope::RequestPlaintext {
            version: 1,
            request_id: request_id.clone(),
            issued_at: now_rfc3339(),
            operation: "status".into(),
            method: "POST".into(),
            path: format!("/v1/projects/{project_id}/status"),
            project_id: Some(project_id.to_string()),
            token: Some(token),
            claim_secret: None,
            payload: serde_json::json!({ "local_revision": local_revision }),
        };

        let client = kagi_sync::infrastructure::remote_client::RemoteClient::new_pinned(
            remote_url.to_string(),
            &meta.server_fingerprint,
            self.allow_insecure,
        )
        .await?;
        let data = client.send_request(&plaintext, &identity).await?;

        Ok(StatusResult {
            state: data["state"].as_str().unwrap_or("unknown").to_string(),
            local_revision,
            remote_revision: data["remote_revision"].as_i64().unwrap_or(0),
            pending_join_count: data["pending_join_count"].as_i64().unwrap_or(0),
        })
    }

    async fn pull_with_token(
        &self,
        project: &RemoteProject,
        token_str: &str,
    ) -> Result<PullResult> {
        let token = kagi_sync::domain::project_token::ProjectToken::parse(token_str)
            .ok_or_else(|| anyhow!("invalid project token"))?;
        let local_access_json = fs::read_to_string(project.base_path.join("access.json"))
            .unwrap_or_else(|_| "{}".to_string());
        self.pull_inner(
            project,
            &token.payload.remote,
            token_str,
            None,
            &local_access_json,
        )
        .await
    }

    async fn pull_inner(
        &self,
        project: &RemoteProject,
        remote_url: &str,
        token_str: &str,
        existing_meta: Option<RemoteMetadata>,
        local_access_json: &str,
    ) -> Result<PullResult> {
        let token = kagi_sync::domain::project_token::ProjectToken::parse(token_str)
            .ok_or_else(|| anyhow!("token from server is malformed"))?;
        let project_id = token.payload.project_id.clone();
        let remote_store = RemoteLocalStore::new(project.local_data_dir.clone());
        let meta = existing_meta.or_else(|| {
            remote_store
                .load_remote_metadata(&project_id)
                .ok()
                .flatten()
        });
        let known_revision = meta.as_ref().and_then(|m| m.local_revision).unwrap_or(0);
        let last_manifest_hash = meta.as_ref().and_then(|m| m.last_manifest_hash.as_deref());
        let pending_token_ids = meta.as_ref().and_then(|m| m.pending_token_ids.clone());
        let pending_accepted_member_ids = meta
            .as_ref()
            .and_then(|m| m.pending_accepted_member_ids.clone());

        let key_manager =
            KeyManager::new_with_project_id(project.base_path.clone(), project_id.clone());
        let identity = key_manager.load_or_create_identity()?;
        let request_id = format!(r"kgr_{}", nanoid::nanoid!(12));
        let plaintext = kagi_sync::domain::envelope::RequestPlaintext {
            version: 1,
            request_id: request_id.clone(),
            issued_at: now_rfc3339(),
            operation: "pull".into(),
            method: "POST".into(),
            path: format!("/v1/projects/{project_id}/pull"),
            project_id: Some(project_id.clone()),
            token: Some(token_str.to_string()),
            claim_secret: None,
            payload: serde_json::json!({ "known_revision": known_revision }),
        };

        let remote_client = kagi_sync::infrastructure::remote_client::RemoteClient::new_pinned(
            remote_url.to_string(),
            &token.payload.server_fingerprint,
            self.allow_insecure,
        )
        .await?;
        let data = remote_client.send_request(&plaintext, &identity).await?;
        let state = data["state"].clone();
        let manifest_hash = verify_pulled_manifest(
            &data,
            &state,
            &project_id,
            known_revision,
            last_manifest_hash,
            local_access_json,
            token.payload.bootstrap_signer_public_key.as_deref(),
        )?;
        let remote_revision = data["revision"].as_i64().unwrap_or(0);
        let pulled_access_json = state
            .get("access_json")
            .and_then(|v| v.as_str())
            .unwrap_or("{}");
        let has_pending = pending_token_ids.as_ref().is_some_and(|v| !v.is_empty())
            || pending_accepted_member_ids
                .as_ref()
                .is_some_and(|v| !v.is_empty());
        let would_change_state =
            remote_revision != known_revision || pulled_access_json != local_access_json;
        if has_pending && would_change_state {
            return Err(anyhow!(
                "Cannot pull while member approval metadata is pending. Run remote push to publish the approval, or resolve the pending member approval before pulling."
            ));
        }

        apply_pulled_state(project, &state)?;
        let token_to_save = key_manager
            .unwrap_member_token()?
            .unwrap_or_else(|| token_str.to_string());
        remote_store.save_token(&project_id, &token_to_save)?;
        remote_store.delete_claim_secret(&project_id)?;
        remote_store.save_remote_metadata(&RemoteMetadata {
            version: 1,
            project_id: project_id.clone(),
            remote: remote_url.to_string(),
            server_key_id: remote_client.server_key_id().to_string(),
            server_fingerprint: remote_client.fingerprint().to_string(),
            local_revision: Some(remote_revision),
            last_pulled_at: Some(now_rfc3339()),
            last_pushed_at: meta.and_then(|m| m.last_pushed_at),
            last_manifest_hash: if manifest_hash.is_empty() {
                None
            } else {
                Some(manifest_hash)
            },
            pending_token_ids,
            pending_accepted_member_ids,
        })?;

        Ok(PullResult {
            revision: remote_revision,
        })
    }
}

pub struct LoginResult {
    pub remote: String,
    pub server_fingerprint: String,
}

pub struct RegisterResult {
    pub project_id: String,
}

pub struct PushResult {
    pub revision: i64,
}

pub struct PullResult {
    pub revision: i64,
}

pub struct StatusResult {
    pub state: String,
    pub local_revision: i64,
    pub remote_revision: i64,
    pub pending_join_count: i64,
}

fn validate_config(config: &KagiConfig) -> Result<()> {
    if (config.version != "2" && config.version != "3") || config.project_id.trim().is_empty() {
        return Err(anyhow!(
            "Unsupported kagi repository format. This version requires a v2 team-ready config with project_id. Run init --force to create a new repository."
        ));
    }
    Ok(())
}

fn remote_url(config: &KagiConfig) -> Option<&str> {
    config
        .settings
        .sync
        .as_ref()
        .and_then(|sync| sync.get("remote"))
        .and_then(Value::as_str)
}

fn now_rfc3339() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap()
}

fn project_state_file(
    path: String,
    content: String,
) -> kagi_sync::domain::project_state::ProjectFile {
    let content_hash = {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(content.as_bytes());
        hex::encode(hasher.finalize())
    };
    kagi_sync::domain::project_state::ProjectFile {
        path,
        content,
        sha256: Some(content_hash),
    }
}

pub(crate) fn collect_project_state_files_for_push(
    base_path: &Path,
    store: &FileStore,
) -> Result<Vec<kagi_sync::domain::project_state::ProjectFile>> {
    let mut files = Vec::new();
    for scope in store.list_services()? {
        let (file_name, content) = store.raw_service_content(&scope)?;
        files.push(project_state_file(file_name, content));
    }
    for (file_name, content) in
        crate::application::file_artifacts::collect_encrypted_file_artifacts(base_path)?
    {
        files.push(project_state_file(file_name, content));
    }
    Ok(files)
}

fn remove_stale_pulled_secret_files(
    base_path: &Path,
    expected_files: &BTreeSet<String>,
) -> Result<()> {
    fn visit_dir(base_path: &Path, dir: &Path, expected_files: &BTreeSet<String>) -> Result<()> {
        if !dir.exists() {
            return Ok(());
        }
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                visit_dir(base_path, &path, expected_files)?;
                if fs::read_dir(&path)?.next().is_none() {
                    fs::remove_dir(&path)?;
                }
            } else if path.extension().is_some_and(|ext| ext == "enc") {
                let relative_path = path
                    .strip_prefix(base_path)
                    .map_err(|e| anyhow!("failed to inspect local secret path: {e}"))?
                    .to_string_lossy()
                    .replace('\\', "/");
                if !expected_files.contains(&relative_path) {
                    fs::remove_file(path)?;
                }
            }
        }
        Ok(())
    }

    visit_dir(base_path, &base_path.join("secrets"), expected_files)?;
    visit_dir(base_path, &base_path.join("files"), expected_files)
}

fn apply_pulled_state(project: &RemoteProject, state: &Value) -> Result<()> {
    let project_state: kagi_sync::domain::project_state::ProjectState =
        serde_json::from_value(state.clone())?;
    let mut expected_files = BTreeSet::new();
    for file in &project_state.files {
        kagi_sync::domain::project_state::validate_file_path(&file.path)
            .map_err(|err| anyhow!("invalid remote file path {}: {}", file.path, err))?;
        expected_files.insert(file.path.clone());
    }

    let kagi_json_empty = serde_json::from_str::<Value>(&project_state.kagi_json)
        .map(|v| {
            v.as_object()
                .map(serde_json::Map::is_empty)
                .unwrap_or(false)
        })
        .unwrap_or(false);
    let access_json_empty = serde_json::from_str::<Value>(&project_state.access_json)
        .map(|v| {
            v.as_object()
                .map(serde_json::Map::is_empty)
                .unwrap_or(false)
        })
        .unwrap_or(false);
    let is_empty_remote = project_state.revision == 0
        && kagi_json_empty
        && access_json_empty
        && project_state.files.is_empty();

    if is_empty_remote {
        let local_access = project.base_path.join("access.json");
        if !local_access.exists() {
            return Err(anyhow!(
                "remote project is empty; run init first, or ask the owner to push first"
            ));
        }
    } else {
        KeyManager::validate_access_json(&project_state.access_json)
            .map_err(|e| anyhow!("invalid remote access.json: {e}"))?;
        let config: KagiConfig = serde_json::from_str(&project_state.kagi_json)?;
        project.save_config(&config)?;
        atomic_write(
            &project.base_path.join("access.json"),
            &project_state.access_json,
        )?;
        KeyManager::new_with_project_id(project.base_path.clone(), config.project_id)
            .backup_access_json(&project_state.access_json)?;
    }

    for file in project_state.files {
        let file_path = project.base_path.join(&file.path);
        fs::create_dir_all(file_path.parent().unwrap())?;
        atomic_write(&file_path, &file.content)?;
    }
    if !is_empty_remote {
        remove_stale_pulled_secret_files(&project.base_path, &expected_files)?;
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn apply_pulled_state_for_kagi_base(base_path: &Path, state: &Value) -> Result<()> {
    let project = RemoteProject::from_kagi_base(
        base_path.to_path_buf(),
        std::env::temp_dir().join("kagi-tests"),
    );
    apply_pulled_state(&project, state)
}

fn is_empty_json_object(input: Option<&str>) -> bool {
    input
        .and_then(|value| serde_json::from_str::<Value>(value).ok())
        .and_then(|value| value.as_object().map(serde_json::Map::is_empty))
        .unwrap_or(false)
}

fn is_empty_genesis_state(state: &Value, project_id: &str) -> bool {
    state.get("project_id").and_then(Value::as_str) == Some(project_id)
        && state.get("revision").and_then(Value::as_i64) == Some(0)
        && is_empty_json_object(state.get("kagi_json").and_then(Value::as_str))
        && is_empty_json_object(state.get("access_json").and_then(Value::as_str))
        && state
            .get("files")
            .and_then(Value::as_array)
            .map(std::vec::Vec::is_empty)
            .unwrap_or(false)
}

pub(crate) fn verify_pulled_manifest(
    data: &Value,
    state: &Value,
    project_id: &str,
    known_revision: i64,
    last_manifest_hash: Option<&str>,
    access_json_str: &str,
    trusted_bootstrap_signer_public_key: Option<&str>,
) -> Result<String> {
    let remote_revision = data
        .get("revision")
        .and_then(Value::as_i64)
        .ok_or_else(|| anyhow!("server response missing revision"))?;
    let manifest_str = match data.get("manifest").and_then(Value::as_str) {
        Some(manifest_str) => manifest_str,
        None => {
            if data.get("manifest_hash").is_some() {
                return Err(anyhow!("server returned manifest_hash but no manifest"));
            }
            if remote_revision == 0
                && known_revision == 0
                && is_empty_genesis_state(state, project_id)
            {
                return Ok(String::new());
            }
            return Err(anyhow!("server response missing manifest"));
        }
    };
    let manifest: kagi_sync::domain::manifest::ProjectStateManifest =
        serde_json::from_str(manifest_str)
            .map_err(|e| anyhow!("invalid manifest from server: {e}"))?;
    let expected_hash = manifest.compute_hash();
    let server_hash = data
        .get("manifest_hash")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("server response missing manifest_hash"))?;
    if expected_hash != server_hash {
        return Err(anyhow!(
            "manifest hash mismatch: computed {expected_hash} vs server {server_hash}"
        ));
    }
    if manifest.project_id != project_id {
        return Err(anyhow!(
            "manifest project_id mismatch: {} vs {}",
            manifest.project_id,
            project_id
        ));
    }
    if manifest.revision != remote_revision {
        return Err(anyhow!(
            "manifest revision mismatch: {} vs {}",
            manifest.revision,
            remote_revision
        ));
    }
    if manifest.revision < known_revision {
        return Err(anyhow!(
            "server rolled back revision: {} < local {}",
            manifest.revision,
            known_revision
        ));
    }
    if manifest.revision == known_revision {
        if let Some(last_hash) = last_manifest_hash {
            if expected_hash != last_hash {
                return Err(anyhow!(
                    "manifest replay detected: revision {} hash changed but expected {}",
                    manifest.revision,
                    last_hash
                ));
            }
        } else {
            return Err(anyhow!(
                "manifest replay detected: revision {} already known locally",
                manifest.revision
            ));
        }
    }
    if manifest.revision > known_revision && known_revision > 0 {
        let last_hash = last_manifest_hash.ok_or_else(|| {
            anyhow!("manifest chain missing local hash for revision {known_revision}")
        })?;
        if manifest.previous_manifest_hash.as_deref() != Some(last_hash) {
            return Err(anyhow!(
                "manifest chain mismatch: expected previous hash {} got {}",
                last_hash,
                manifest
                    .previous_manifest_hash
                    .as_deref()
                    .unwrap_or("<missing>")
            ));
        }
    }

    let kagi_json_str = state
        .get("kagi_json")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("state missing kagi_json"))?;
    let remote_access_json_str = state
        .get("access_json")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("state missing access_json"))?;
    if manifest.kagi_json_hash != kagi_sync::domain::manifest::hash_json(kagi_json_str) {
        return Err(anyhow!("manifest kagi_json hash mismatch"));
    }
    if manifest.access_json_hash != kagi_sync::domain::manifest::hash_json(remote_access_json_str) {
        return Err(anyhow!("manifest access_json hash mismatch"));
    }

    let files = state
        .get("files")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("state missing files"))?;
    let mut state_file_hashes = BTreeMap::new();
    for file_value in files {
        let path = file_value
            .get("path")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("state file missing path"))?;
        let content = file_value
            .get("content")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("state file {path} missing content"))?;
        let expected_file_hash = {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(content.as_bytes());
            hex::encode(hasher.finalize())
        };
        if state_file_hashes
            .insert(path.to_string(), expected_file_hash)
            .is_some()
        {
            return Err(anyhow!("state contains duplicate file path: {path}"));
        }
    }

    let mut manifest_paths = BTreeSet::new();
    for manifest_file in &manifest.file_hashes {
        if !manifest_paths.insert(manifest_file.path.clone()) {
            return Err(anyhow!(
                "manifest contains duplicate file path: {}",
                manifest_file.path
            ));
        }
        let expected_file_hash = state_file_hashes
            .get(&manifest_file.path)
            .ok_or_else(|| anyhow!("manifest references missing file: {}", manifest_file.path))?;
        if manifest_file.sha256 != *expected_file_hash {
            return Err(anyhow!(
                "manifest file hash mismatch for {}: expected {} got {}",
                manifest_file.path,
                expected_file_hash,
                manifest_file.sha256
            ));
        }
    }

    let state_paths: BTreeSet<String> = state_file_hashes.keys().cloned().collect();
    if state_paths != manifest_paths {
        let missing_paths: Vec<String> = manifest_paths.difference(&state_paths).cloned().collect();
        if !missing_paths.is_empty() {
            return Err(anyhow!(
                "manifest references missing files: {}",
                missing_paths.join(", ")
            ));
        }
        let extra_paths: Vec<String> = state_paths.difference(&manifest_paths).cloned().collect();
        if !extra_paths.is_empty() {
            return Err(anyhow!(
                "state contains extra files not in manifest: {}",
                extra_paths.join(", ")
            ));
        }
    }

    let signature_b64 = data
        .get("manifest_signature")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("manifest present but manifest_signature missing"))?;
    let signature_bytes = base64::engine::general_purpose::STANDARD
        .decode(signature_b64)
        .map_err(|e| anyhow!("invalid manifest signature: {e}"))?;
    if signature_bytes.len() != 64 {
        return Err(anyhow!(
            "manifest signature must be 64 bytes, got {}",
            signature_bytes.len()
        ));
    }
    let signature = ed25519_dalek::Signature::from_slice(&signature_bytes)
        .map_err(|e| anyhow!("invalid signature: {e}"))?;
    let public_key_bytes = base64::engine::general_purpose::STANDARD
        .decode(&manifest.signer_public_key)
        .map_err(|e| anyhow!("invalid signer public key: {e}"))?;
    if public_key_bytes.len() != 32 {
        return Err(anyhow!(
            "signer public key must be 32 bytes, got {}",
            public_key_bytes.len()
        ));
    }
    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&public_key_bytes);
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&pk_arr)
        .map_err(|e| anyhow!("invalid verifying key: {e}"))?;

    let access: Value = serde_json::from_str(access_json_str).unwrap_or(Value::Null);
    let empty_members = vec![];
    let members = access
        .get("members")
        .and_then(Value::as_array)
        .unwrap_or(&empty_members);
    let known_public_key = members
        .iter()
        .find(|member| {
            member
                .get("member_id")
                .and_then(Value::as_str)
                .map(|id| id == manifest.signer_member_id)
                .unwrap_or(false)
        })
        .and_then(|member| member.get("signing_public_key"))
        .and_then(Value::as_str);
    let trusted_public_key = known_public_key
        .or(trusted_bootstrap_signer_public_key)
        .ok_or_else(|| {
            anyhow!(
                "manifest signed by unknown member {} (no trusted signing key available)",
                manifest.signer_member_id
            )
        })?;
    if trusted_public_key != manifest.signer_public_key {
        return Err(anyhow!(
            "manifest signer_public_key does not match trusted key for {}: expected {} got {}",
            manifest.signer_member_id,
            trusted_public_key,
            manifest.signer_public_key
        ));
    }

    use ed25519_dalek::Verifier;
    verifying_key
        .verify(expected_hash.as_bytes(), &signature)
        .map_err(|e| anyhow!("manifest signature verification failed: {e}"))?;
    Ok(expected_hash)
}

fn validate_admin_token_for_fingerprint(token: &str, fingerprint: &str) -> Result<()> {
    let parsed = kagi_sync::domain::project_token::ProjectToken::parse(token)
        .ok_or_else(|| anyhow!("invalid admin token"))?;
    if !token.starts_with("kagi_admin_v1_")
        || parsed.payload.project_id != "admin"
        || !parsed
            .payload
            .capabilities
            .iter()
            .any(|capability| capability == "admin")
    {
        return Err(anyhow!("invalid admin token"));
    }
    if parsed.payload.server_fingerprint != fingerprint {
        return Err(anyhow!(
            "admin token belongs to server {}, but remote fingerprint is {}",
            parsed.payload.server_fingerprint,
            fingerprint
        ));
    }
    Ok(())
}

fn admin_keyring_disabled() -> bool {
    std::env::var_os("KAGI_DISABLE_KEYRING").is_some() || std::env::var_os("KAGI_HOME").is_some()
}

fn atomic_write(path: &Path, content: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp_path = path.with_extension(format!(
        "{}.tmp",
        path.extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or("kagi")
    ));
    fs::write(&tmp_path, content)?;
    fs::rename(&tmp_path, path)?;
    set_private_file_permissions(path)?;
    Ok(())
}

fn set_private_file_permissions(_path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(_path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}
