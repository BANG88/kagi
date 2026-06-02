use anyhow::Context;
use base64::{Engine as _, engine::general_purpose};
use kagi_crypto::xchacha_crypto::XChaChaEncryptor;
use kagi_domain::XCHACHA20_POLY1305;
use kagi_domain::crypto::encryptor::Encryptor;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::path::{Component, Path, PathBuf};

pub const DEFAULT_MAX_FILE_SIZE: u64 = 1024 * 1024;
pub const LARGE_MAX_FILE_SIZE: u64 = 5 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileArtifactEntry {
    pub id: String,
    pub scope: String,
    pub name: String,
    #[serde(default)]
    pub location: FileArtifactLocation,
    pub restore_path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
    pub size: u64,
    pub sha256: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum FileArtifactLocation {
    #[default]
    Repo,
    Home,
}

impl FileArtifactLocation {
    pub fn label(self) -> &'static str {
        match self {
            Self::Repo => "repo",
            Self::Home => "home",
        }
    }
}

impl FileArtifactEntry {
    pub fn locator(&self) -> String {
        format!("{}:{}", self.location.label(), self.restore_path)
    }

    pub fn display_name(&self) -> &str {
        self.alias.as_deref().unwrap_or(&self.name)
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct FileArtifactIndex {
    version: u8,
    files: Vec<FileArtifactEntry>,
}

impl Default for FileArtifactIndex {
    fn default() -> Self {
        Self {
            version: 1,
            files: Vec::new(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct EncryptedBlob {
    version: u8,
    algorithm: String,
    kind: String,
    nonce: String,
    ciphertext: String,
    aad: String,
    tag: String,
}

pub struct AddedFile {
    pub entry: FileArtifactEntry,
    pub replaced: bool,
}

pub struct RestoredFile {
    pub entry: FileArtifactEntry,
    pub path: PathBuf,
    pub backup_path: Option<PathBuf>,
    pub changed: bool,
}

#[derive(Debug, Clone)]
pub struct FileRestorePlanEntry {
    pub entry: FileArtifactEntry,
    pub target: PathBuf,
    pub status: FileRestoreStatus,
    pub backup_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileRestoreStatus {
    Missing,
    Same,
    Different,
    BlockedExisting,
}

impl FileRestorePlanEntry {
    pub fn can_apply(&self) -> bool {
        self.status != FileRestoreStatus::BlockedExisting
    }
}

pub struct FileArtifactService {
    base_path: PathBuf,
    project_root: PathBuf,
    home_root: PathBuf,
    project_id: String,
    encryptor: XChaChaEncryptor,
}

impl FileArtifactService {
    pub fn new(base_path: PathBuf, project_key: &[u8]) -> anyhow::Result<Self> {
        let key: &[u8; 32] = project_key
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid project key length"))?;
        let config_path = base_path.join(kagi_domain::config::KAGI_CONFIG_FILE);
        let config: kagi_domain::config::KagiConfig =
            serde_json::from_str(&fs::read_to_string(config_path)?)?;
        let project_root = base_path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("invalid .kagi path"))?
            .canonicalize()?;
        let home_root = home_root()?;
        Ok(Self {
            base_path,
            project_root,
            home_root,
            project_id: config.project_id,
            encryptor: XChaChaEncryptor::new(key),
        })
    }

    pub fn add_file(
        &self,
        scope: &str,
        file_path: &Path,
        name: Option<&str>,
        force: bool,
        allow_large: bool,
        location: FileArtifactLocation,
    ) -> anyhow::Result<AddedFile> {
        let input = resolve_input_path(file_path, &self.home_root)?;
        let metadata = fs::symlink_metadata(&input)?;
        if metadata.file_type().is_symlink() {
            return Err(anyhow::anyhow!("refusing to add symlink"));
        }
        if !metadata.file_type().is_file() {
            return Err(anyhow::anyhow!("refusing to add non-regular file"));
        }
        let limit = if allow_large {
            LARGE_MAX_FILE_SIZE
        } else {
            DEFAULT_MAX_FILE_SIZE
        };
        if metadata.len() > limit {
            return Err(anyhow::anyhow!(
                "file too large: {} bytes exceeds {} bytes",
                metadata.len(),
                limit
            ));
        }

        let canonical = input.canonicalize()?;
        let restore_path = match location {
            FileArtifactLocation::Repo => {
                reject_symlink_components_except_trusted_ancestors(&input, &self.project_root)?;
                let path = repo_relative_path(&self.project_root, &canonical)?;
                validate_safe_repo_relative_path(&path)?;
                reject_tracked_file(&self.project_root, &path)?;
                path
            }
            FileArtifactLocation::Home => {
                reject_symlink_components_except_trusted_ancestors(&input, &self.home_root)?;
                let path = home_relative_path(&self.home_root, &canonical)?;
                validate_safe_home_relative_path(&path)?;
                path
            }
        };

        let alias = match name {
            Some(name) if !name.trim().is_empty() => {
                let alias = name.trim().to_string();
                validate_logical_name(&alias)?;
                Some(alias)
            }
            Some(_) => return Err(anyhow::anyhow!("file name cannot be empty")),
            None => None,
        };
        let logical_name = match &alias {
            Some(alias) => alias.clone(),
            None => canonical
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| anyhow::anyhow!("file name must be valid UTF-8"))?
                .to_string(),
        };
        validate_logical_name(&logical_name)?;

        let plaintext = fs::read(&canonical)?;
        let sha256 = sha256_hex(&plaintext);
        let now = now_string();
        let mut index = self.load_index()?;
        let existing_position = index.files.iter().position(|entry| {
            entry.scope == scope && entry.location == location && entry.restore_path == restore_path
        });
        if existing_position.is_some() && !force {
            return Err(anyhow::anyhow!(
                "file already exists in {scope}: {}. Use --force to replace it.",
                format_locator(location, &restore_path)
            ));
        }
        if let Some(alias) = &alias
            && index.files.iter().enumerate().any(|(position, entry)| {
                Some(position) != existing_position
                    && entry.scope == scope
                    && entry.alias.as_deref().unwrap_or(&entry.name) == alias
            })
        {
            return Err(anyhow::anyhow!(
                "file name already exists in {scope}: {alias}. Choose a different --name."
            ));
        }

        let (id, created_at, replaced) = if let Some(position) = existing_position {
            let existing = index.files.remove(position);
            let _ = fs::remove_file(self.content_path(&existing.id));
            (existing.id, existing.created_at, true)
        } else {
            (format!("kgf_{}", nanoid::nanoid!(10)), now.clone(), false)
        };

        let blob = self.encrypt_blob("file", &id, &plaintext)?;
        self.write_encrypted_blob(&self.content_path(&id), &blob)?;

        let entry = FileArtifactEntry {
            id,
            scope: scope.to_string(),
            name: logical_name,
            location,
            restore_path,
            alias,
            size: metadata.len(),
            sha256,
            created_at,
            updated_at: now,
        };
        index.files.push(entry.clone());
        sort_file_entries(&mut index.files);
        self.save_index(&index)?;
        if entry.location == FileArtifactLocation::Repo {
            self.ensure_local_git_exclude(&entry.restore_path)?;
        }
        Ok(AddedFile { entry, replaced })
    }

    pub fn list_files(&self, scope: Option<&str>) -> anyhow::Result<Vec<FileArtifactEntry>> {
        let mut files = self.load_index()?.files;
        if let Some(scope) = scope {
            files.retain(|entry| entry.scope == scope);
        }
        sort_file_entries(&mut files);
        Ok(files)
    }

    pub fn restore_file(
        &self,
        scope: &str,
        name: &str,
        out: Option<&Path>,
        force: bool,
    ) -> anyhow::Result<RestoredFile> {
        let entry = self.find_entry(scope, name)?;
        let plan = self.plan_restore_entry(entry, out, force)?;
        if !plan.can_apply() {
            return Err(anyhow::anyhow!(
                "output file already exists: {}. Use --force to overwrite it.",
                plan.target.display()
            ));
        }
        self.apply_restore_plan_entry(&plan)
    }

    pub fn plan_restore_files(
        &self,
        scope: Option<&str>,
        force: bool,
    ) -> anyhow::Result<Vec<FileRestorePlanEntry>> {
        let mut entries = self.load_index()?.files;
        if let Some(scope) = scope {
            entries.retain(|entry| entry.scope == scope);
        }
        sort_file_entries(&mut entries);
        entries
            .into_iter()
            .map(|entry| self.plan_restore_entry(entry, None, force))
            .collect()
    }

    pub fn restore_planned_files(
        &self,
        plan: &[FileRestorePlanEntry],
    ) -> anyhow::Result<Vec<RestoredFile>> {
        let mut restored = Vec::new();
        for entry in plan {
            if !entry.can_apply() {
                return Err(anyhow::anyhow!(
                    "restore plan contains blocked file: {}",
                    entry.entry.locator()
                ));
            }
            restored.push(self.apply_restore_plan_entry(entry)?);
        }
        Ok(restored)
    }

    pub fn read_file(&self, scope: &str, name: &str) -> anyhow::Result<Vec<u8>> {
        let entry = self.find_entry(scope, name)?;
        let blob = self.read_encrypted_blob(&self.content_path(&entry.id))?;
        self.decrypt_blob("file", &entry.id, &blob)
    }

    pub fn remove_file(&self, scope: &str, name: &str) -> anyhow::Result<FileArtifactEntry> {
        let mut index = self.load_index()?;
        let position = self.find_entry_position(&index.files, scope, name)?;
        let entry = index.files.remove(position);
        let _ = fs::remove_file(self.content_path(&entry.id));
        self.save_index(&index)?;
        Ok(entry)
    }

    fn find_entry(&self, scope: &str, name: &str) -> anyhow::Result<FileArtifactEntry> {
        let index = self.load_index()?;
        let position = self.find_entry_position(&index.files, scope, name)?;
        Ok(index.files[position].clone())
    }

    fn find_entry_position(
        &self,
        files: &[FileArtifactEntry],
        scope: &str,
        selector: &str,
    ) -> anyhow::Result<usize> {
        if let Some((location, restore_path)) = self.parse_file_selector(selector)? {
            return files
                .iter()
                .position(|entry| {
                    entry.scope == scope
                        && entry.location == location
                        && entry.restore_path == restore_path
                })
                .ok_or_else(|| anyhow::anyhow!("file not found in {scope}: {selector}"));
        }

        let matches: Vec<usize> = files
            .iter()
            .enumerate()
            .filter_map(|(position, entry)| {
                if entry.scope == scope && entry.alias.as_deref().unwrap_or(&entry.name) == selector
                {
                    Some(position)
                } else {
                    None
                }
            })
            .collect();
        match matches.as_slice() {
            [position] => Ok(*position),
            [] => Err(anyhow::anyhow!("file not found in {scope}: {selector}")),
            _ => Err(anyhow::anyhow!(
                "file selector is ambiguous in {scope}: {selector}. Use the restore path instead."
            )),
        }
    }

    fn files_dir(&self) -> PathBuf {
        self.base_path.join("files")
    }

    fn index_path(&self) -> PathBuf {
        self.files_dir().join("index.enc")
    }

    fn content_path(&self, id: &str) -> PathBuf {
        self.files_dir().join(format!("{id}.enc"))
    }

    fn load_index(&self) -> anyhow::Result<FileArtifactIndex> {
        let path = self.index_path();
        if !path.exists() {
            return Ok(FileArtifactIndex::default());
        }
        let blob = self.read_encrypted_blob(&path)?;
        let plaintext = self.decrypt_blob("file-index", "index", &blob)?;
        Ok(serde_json::from_slice(&plaintext)?)
    }

    fn save_index(&self, index: &FileArtifactIndex) -> anyhow::Result<()> {
        let plaintext = serde_json::to_vec(index)?;
        let blob = self.encrypt_blob("file-index", "index", &plaintext)?;
        self.write_encrypted_blob(&self.index_path(), &blob)
    }

    fn encrypt_blob(
        &self,
        kind: &str,
        logical_id: &str,
        plaintext: &[u8],
    ) -> anyhow::Result<EncryptedBlob> {
        let aad = self.aad(kind, logical_id);
        let encrypted = self.encryptor.encrypt(plaintext, aad.as_bytes())?;
        if encrypted.len() < 40 {
            return Err(anyhow::anyhow!("encrypted data too short"));
        }
        Ok(EncryptedBlob {
            version: 1,
            algorithm: XCHACHA20_POLY1305.to_string(),
            kind: kind.to_string(),
            nonce: general_purpose::STANDARD.encode(&encrypted[..24]),
            ciphertext: general_purpose::STANDARD.encode(&encrypted[24..encrypted.len() - 16]),
            aad: general_purpose::STANDARD.encode(aad.as_bytes()),
            tag: general_purpose::STANDARD.encode(&encrypted[encrypted.len() - 16..]),
        })
    }

    fn decrypt_blob(
        &self,
        kind: &str,
        logical_id: &str,
        blob: &EncryptedBlob,
    ) -> anyhow::Result<Vec<u8>> {
        if blob.version != 1 {
            return Err(anyhow::anyhow!("unsupported encrypted file version"));
        }
        if blob.algorithm != XCHACHA20_POLY1305 {
            return Err(anyhow::anyhow!(
                "unsupported encrypted file algorithm: {}",
                blob.algorithm
            ));
        }
        if blob.kind != kind {
            return Err(anyhow::anyhow!("encrypted file kind mismatch"));
        }
        let aad = self.aad(kind, logical_id);
        let encoded_aad = general_purpose::STANDARD.encode(aad.as_bytes());
        if blob.aad != encoded_aad {
            return Err(anyhow::anyhow!("encrypted file aad mismatch"));
        }
        let mut data = general_purpose::STANDARD.decode(&blob.nonce)?;
        data.extend_from_slice(&general_purpose::STANDARD.decode(&blob.ciphertext)?);
        data.extend_from_slice(&general_purpose::STANDARD.decode(&blob.tag)?);
        Ok(self.encryptor.decrypt(&data, aad.as_bytes())?)
    }

    fn aad(&self, kind: &str, logical_id: &str) -> String {
        format!(
            "kagi:v1:{XCHACHA20_POLY1305}:{kind}:{}:{logical_id}",
            self.project_id
        )
    }

    fn read_encrypted_blob(&self, path: &Path) -> anyhow::Result<EncryptedBlob> {
        Ok(serde_json::from_str(&fs::read_to_string(path)?)?)
    }

    fn write_encrypted_blob(&self, path: &Path, blob: &EncryptedBlob) -> anyhow::Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
            set_private_dir_permissions(parent)?;
        }
        fs::write(path, serde_json::to_string_pretty(blob)?)?;
        set_private_file_permissions(path)
    }

    fn plan_restore_entry(
        &self,
        entry: FileArtifactEntry,
        out: Option<&Path>,
        force: bool,
    ) -> anyhow::Result<FileRestorePlanEntry> {
        let target = self.resolve_output_path(&entry, out)?;
        let (status, backup_path) = if target.exists() {
            let metadata = fs::symlink_metadata(&target)?;
            if metadata.file_type().is_symlink() {
                return Err(anyhow::anyhow!("refusing to restore over symlink"));
            }
            if !metadata.file_type().is_file() {
                return Err(anyhow::anyhow!("refusing to restore over non-regular file"));
            }
            let existing = fs::read(&target)?;
            if sha256_hex(&existing) == entry.sha256 {
                (FileRestoreStatus::Same, None)
            } else if entry.location == FileArtifactLocation::Home {
                (
                    FileRestoreStatus::Different,
                    Some(next_backup_path(&target)?),
                )
            } else if force {
                (FileRestoreStatus::Different, None)
            } else {
                (FileRestoreStatus::BlockedExisting, None)
            }
        } else {
            (FileRestoreStatus::Missing, None)
        };
        Ok(FileRestorePlanEntry {
            entry,
            target,
            status,
            backup_path,
        })
    }

    fn apply_restore_plan_entry(
        &self,
        plan: &FileRestorePlanEntry,
    ) -> anyhow::Result<RestoredFile> {
        if plan.status == FileRestoreStatus::Same {
            return Ok(RestoredFile {
                entry: plan.entry.clone(),
                path: plan.target.clone(),
                backup_path: None,
                changed: false,
            });
        }
        let blob = self.read_encrypted_blob(&self.content_path(&plan.entry.id))?;
        let plaintext = self.decrypt_blob("file", &plan.entry.id, &blob)?;
        if let Some(parent) = plan.target.parent() {
            fs::create_dir_all(parent)?;
        }
        if let Some(backup_path) = &plan.backup_path {
            fs::copy(&plan.target, backup_path)?;
            set_private_file_permissions(backup_path)?;
        }
        write_private_file(&plan.target, &plaintext)?;
        if plan.entry.location == FileArtifactLocation::Repo {
            let actual_restore_path = repo_relative_path(&self.project_root, &plan.target)?;
            self.ensure_local_git_exclude(&actual_restore_path)?;
        }
        Ok(RestoredFile {
            entry: plan.entry.clone(),
            path: plan.target.clone(),
            backup_path: plan.backup_path.clone(),
            changed: true,
        })
    }

    fn resolve_output_path(
        &self,
        entry: &FileArtifactEntry,
        out: Option<&Path>,
    ) -> anyhow::Result<PathBuf> {
        let target = if let Some(out) = out {
            if out.is_absolute() {
                normalize_path(out.to_path_buf())?
            } else {
                normalize_path(std::env::current_dir()?.join(out))?
            }
        } else {
            match entry.location {
                FileArtifactLocation::Repo => {
                    normalize_path(self.project_root.join(&entry.restore_path))?
                }
                FileArtifactLocation::Home => {
                    normalize_path(self.home_root.join(&entry.restore_path))?
                }
            }
        };
        let trusted_root = match entry.location {
            FileArtifactLocation::Repo => &self.project_root,
            FileArtifactLocation::Home => &self.home_root,
        };
        reject_symlink_components_except_trusted_ancestors(&target, trusted_root)?;
        let target = canonicalize_existing_path_prefix(&target)?;
        match entry.location {
            FileArtifactLocation::Repo => {
                let relative = repo_relative_path(&self.project_root, &target)
                    .map_err(|_| anyhow::anyhow!("output path must stay inside the repository"))?;
                validate_safe_repo_relative_path(&relative)?;
            }
            FileArtifactLocation::Home => {
                let relative = home_relative_path(&self.home_root, &target).map_err(|_| {
                    anyhow::anyhow!("output path must stay inside the home directory")
                })?;
                validate_safe_home_relative_path(&relative)?;
            }
        }
        Ok(target)
    }

    fn parse_file_selector(
        &self,
        selector: &str,
    ) -> anyhow::Result<Option<(FileArtifactLocation, String)>> {
        if let Some(path) = selector.strip_prefix("home:") {
            validate_safe_home_relative_path(path)?;
            return Ok(Some((FileArtifactLocation::Home, path.to_string())));
        }
        if let Some(path) = selector.strip_prefix("repo:") {
            validate_safe_repo_relative_path(path)?;
            return Ok(Some((FileArtifactLocation::Repo, path.to_string())));
        }
        if !looks_like_path(selector) {
            return Ok(None);
        }
        let path = expand_tilde_path(selector, &self.home_root);
        let absolute = if path.is_absolute() {
            path
        } else {
            std::env::current_dir()?.join(path)
        };
        let target = canonicalize_existing_path_prefix(&absolute)?;
        if let Ok(relative) = repo_relative_path(&self.project_root, &target) {
            validate_safe_repo_relative_path(&relative)?;
            return Ok(Some((FileArtifactLocation::Repo, relative)));
        }
        if let Ok(relative) = home_relative_path(&self.home_root, &target) {
            validate_safe_home_relative_path(&relative)?;
            return Ok(Some((FileArtifactLocation::Home, relative)));
        }
        Err(anyhow::anyhow!(
            "file selector path must stay inside the repository or home directory"
        ))
    }

    fn ensure_local_git_exclude(&self, restore_path: &str) -> anyhow::Result<()> {
        let info_dir = self.project_root.join(".git/info");
        if !info_dir.is_dir() {
            return Ok(());
        }
        fs::create_dir_all(&info_dir)?;
        let exclude_path = info_dir.join("exclude");
        let ignore_line = format!("/{restore_path}");
        let existing = fs::read_to_string(&exclude_path).unwrap_or_default();
        if existing.lines().any(|line| line.trim() == ignore_line) {
            return Ok(());
        }
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&exclude_path)?;
        if !existing.is_empty() && !existing.ends_with('\n') {
            writeln!(file)?;
        }
        writeln!(file, "{ignore_line}")?;
        Ok(())
    }
}

pub fn collect_encrypted_file_artifacts(base_path: &Path) -> anyhow::Result<Vec<(String, String)>> {
    let files_dir = base_path.join("files");
    if !files_dir.exists() {
        return Ok(Vec::new());
    }
    let mut files = Vec::new();
    for entry in fs::read_dir(files_dir)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() || path.extension().and_then(|ext| ext.to_str()) != Some("enc") {
            continue;
        }
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| anyhow::anyhow!("encrypted file artifact path must be UTF-8"))?;
        if !is_valid_encrypted_file_artifact_name(file_name) {
            continue;
        }
        files.push((format!("files/{file_name}"), fs::read_to_string(path)?));
    }
    files.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(files)
}

pub fn validate_file_artifacts(base_path: &Path, project_key: &[u8]) -> anyhow::Result<usize> {
    let files_dir = base_path.join("files");
    if !files_dir.exists() {
        return Ok(0);
    }

    let mut encrypted_files = 0_usize;
    let mut has_index = false;
    for entry in fs::read_dir(&files_dir)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() || path.extension().and_then(|ext| ext.to_str()) != Some("enc") {
            continue;
        }
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| anyhow::anyhow!("encrypted file artifact path must be UTF-8"))?;
        if !is_valid_encrypted_file_artifact_name(file_name) {
            return Err(anyhow::anyhow!(
                "invalid file artifact path: files/{file_name}"
            ));
        }
        encrypted_files += 1;
        if file_name == "index.enc" {
            has_index = true;
        }
    }

    if encrypted_files == 0 {
        return Ok(0);
    }
    if !has_index {
        return Err(anyhow::anyhow!("missing files/index.enc"));
    }

    let service = FileArtifactService::new(base_path.to_path_buf(), project_key)?;
    let index = service
        .load_index()
        .context("failed to decrypt file artifact index")?;
    for entry in &index.files {
        validate_artifact_id(&entry.id)?;
        validate_logical_name(&entry.name)?;
        if let Some(alias) = &entry.alias {
            validate_logical_name(alias)?;
        }
        match entry.location {
            FileArtifactLocation::Repo => validate_safe_repo_relative_path(&entry.restore_path)?,
            FileArtifactLocation::Home => validate_safe_home_relative_path(&entry.restore_path)?,
        }
        let content_path = service.content_path(&entry.id);
        if !content_path.is_file() {
            return Err(anyhow::anyhow!(
                "missing encrypted file artifact content: files/{}.enc",
                entry.id
            ));
        }
    }

    Ok(index.files.len())
}

fn is_valid_encrypted_file_artifact_name(file_name: &str) -> bool {
    if file_name == "index.enc" {
        return true;
    }
    let Some(id) = file_name.strip_suffix(".enc") else {
        return false;
    };
    validate_artifact_id(id).is_ok()
}

fn validate_artifact_id(id: &str) -> anyhow::Result<()> {
    let Some(rest) = id.strip_prefix("kgf_") else {
        return Err(anyhow::anyhow!("invalid file artifact id"));
    };
    if rest.is_empty()
        || !rest
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-')
    {
        return Err(anyhow::anyhow!("invalid file artifact id"));
    }
    Ok(())
}

fn resolve_input_path(path: &Path, home_root: &Path) -> anyhow::Result<PathBuf> {
    if let Some(path) = path.to_str()
        && path.starts_with('~')
    {
        return Ok(expand_tilde_path(path, home_root));
    }
    Ok(if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    })
}

fn repo_relative_path(project_root: &Path, path: &Path) -> anyhow::Result<String> {
    Ok(path
        .strip_prefix(project_root)
        .map_err(|_| anyhow::anyhow!("file must be inside the repository"))?
        .to_string_lossy()
        .replace('\\', "/"))
}

fn home_relative_path(home_root: &Path, path: &Path) -> anyhow::Result<String> {
    Ok(path
        .strip_prefix(home_root)
        .map_err(|_| anyhow::anyhow!("file must be inside the home directory"))?
        .to_string_lossy()
        .replace('\\', "/"))
}

fn validate_relative_path_shape(path: &str) -> anyhow::Result<()> {
    if path.is_empty()
        || path.starts_with('/')
        || path.contains('\\')
        || path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(anyhow::anyhow!("invalid relative file path"));
    }
    Ok(())
}

fn validate_safe_repo_relative_path(path: &str) -> anyhow::Result<()> {
    let blocked = [
        ".git",
        ".kagi",
        "node_modules",
        "target",
        "dist",
        "build",
        ".next",
        "out",
        "vendor",
    ];
    validate_relative_path_shape(path)
        .map_err(|_| anyhow::anyhow!("invalid repository-relative file path"))?;
    if path.split('/').any(|part| blocked.contains(&part)) {
        return Err(anyhow::anyhow!(
            "refusing to use file inside ignored or internal directory"
        ));
    }
    Ok(())
}

fn validate_safe_home_relative_path(path: &str) -> anyhow::Result<()> {
    let blocked = [".git", ".kagi", ".ssh", ".gnupg"];
    validate_relative_path_shape(path)
        .map_err(|_| anyhow::anyhow!("invalid home-relative file path"))?;
    if path.split('/').any(|part| blocked.contains(&part)) {
        return Err(anyhow::anyhow!(
            "refusing to use file inside sensitive or internal home directory"
        ));
    }
    Ok(())
}

fn validate_logical_name(name: &str) -> anyhow::Result<()> {
    if name.is_empty()
        || name.len() > 255
        || name.contains('/')
        || name.contains('\\')
        || name == "."
        || name == ".."
    {
        return Err(anyhow::anyhow!("invalid file name"));
    }
    Ok(())
}

fn reject_tracked_file(project_root: &Path, restore_path: &str) -> anyhow::Result<()> {
    if !project_root.join(".git").exists() {
        return Ok(());
    }
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(project_root)
        .arg("ls-files")
        .arg("--error-unmatch")
        .arg(restore_path)
        .output();
    if let Ok(output) = output
        && output.status.success()
    {
        return Err(anyhow::anyhow!(
            "file is already tracked by git; remove it first with `git rm --cached {restore_path}`"
        ));
    }
    Ok(())
}

fn normalize_path(path: PathBuf) -> anyhow::Result<PathBuf> {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            Component::Normal(part) => normalized.push(part),
        }
    }
    Ok(normalized)
}

fn home_root() -> anyhow::Result<PathBuf> {
    if let Some(base_dirs) = directories::BaseDirs::new() {
        return base_dirs
            .home_dir()
            .canonicalize()
            .context("failed to canonicalize home directory");
    }
    for key in ["USERPROFILE", "HOME"] {
        if let Some(path) = std::env::var_os(key) {
            return PathBuf::from(path)
                .canonicalize()
                .with_context(|| format!("failed to canonicalize {key}"));
        }
    }
    #[cfg(windows)]
    {
        if let (Some(drive), Some(path)) =
            (std::env::var_os("HOMEDRIVE"), std::env::var_os("HOMEPATH"))
        {
            return PathBuf::from(format!(
                "{}{}",
                drive.to_string_lossy(),
                path.to_string_lossy()
            ))
            .canonicalize()
            .context("failed to canonicalize HOMEDRIVE/HOMEPATH");
        }
    }
    Err(anyhow::anyhow!("could not determine home directory"))
}

fn format_locator(location: FileArtifactLocation, path: &str) -> String {
    format!("{}:{path}", location.label())
}

fn looks_like_path(selector: &str) -> bool {
    selector.starts_with('~')
        || selector.contains('/')
        || selector.contains('\\')
        || Path::new(selector).is_absolute()
}

fn expand_tilde_path(path: &str, home_root: &Path) -> PathBuf {
    if path == "~" {
        return home_root.to_path_buf();
    }
    if let Some(rest) = path.strip_prefix("~/").or_else(|| path.strip_prefix("~\\")) {
        return home_root.join(rest);
    }
    PathBuf::from(path)
}

fn sort_file_entries(files: &mut [FileArtifactEntry]) {
    files.sort_by(|a, b| {
        (
            &a.scope,
            a.location.label(),
            &a.restore_path,
            a.display_name(),
        )
            .cmp(&(
                &b.scope,
                b.location.label(),
                &b.restore_path,
                b.display_name(),
            ))
    });
}

fn next_backup_path(target: &Path) -> anyhow::Result<PathBuf> {
    let file_name = target
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow::anyhow!("backup file name must be valid UTF-8"))?;
    let parent = target
        .parent()
        .ok_or_else(|| anyhow::anyhow!("backup path has no parent"))?;
    let stamp = compact_now_string();
    let mut candidate = parent.join(format!("{file_name}.kagi.bak.{stamp}"));
    let mut counter = 1_u32;
    while candidate.exists() {
        candidate = parent.join(format!("{file_name}.kagi.bak.{stamp}.{counter}"));
        counter += 1;
    }
    Ok(candidate)
}

fn compact_now_string() -> String {
    let now = time::OffsetDateTime::now_utc();
    format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
        now.year(),
        u8::from(now.month()),
        now.day(),
        now.hour(),
        now.minute(),
        now.second()
    )
}

fn canonicalize_existing_path_prefix(path: &Path) -> anyhow::Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let absolute = normalize_path(absolute)?;
    if let Ok(canonical) = absolute.canonicalize() {
        return Ok(canonical);
    }

    let mut missing = Vec::new();
    let mut current = absolute.as_path();
    while !current.exists() {
        let Some(name) = current.file_name() else {
            break;
        };
        missing.push(name.to_os_string());
        current = current
            .parent()
            .ok_or_else(|| anyhow::anyhow!("output path has no existing parent"))?;
    }

    let mut canonical = current.canonicalize()?;
    for component in missing.iter().rev() {
        canonical.push(component);
    }
    normalize_path(canonical)
}

fn reject_symlink_components_except_trusted_ancestors(
    path: &Path,
    trusted_root: &Path,
) -> anyhow::Result<()> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        if let Ok(metadata) = fs::symlink_metadata(&current)
            && metadata.file_type().is_symlink()
        {
            if let Ok(canonical) = current.canonicalize()
                && trusted_root.starts_with(&canonical)
                && !current.starts_with(trusted_root)
            {
                continue;
            }
            return Err(anyhow::anyhow!(
                "refusing to restore through symlink: {}",
                current.display()
            ));
        }
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn now_string() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

fn write_private_file(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("output path has no parent"))?;
    fs::create_dir_all(parent)?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow::anyhow!("output file name must be valid UTF-8"))?;
    let tmp = parent.join(format!(".{file_name}.kagi.tmp.{}", nanoid::nanoid!(8)));
    fs::write(&tmp, bytes)?;
    set_private_file_permissions(&tmp)?;
    if path.exists() {
        fs::remove_file(path)?;
    }
    fs::rename(&tmp, path)?;
    set_private_file_permissions(path)
}

fn set_private_file_permissions(_path: &Path) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(_path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn set_private_dir_permissions(_path: &Path) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(_path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}
