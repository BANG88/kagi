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
    pub restore_path: String,
    pub size: u64,
    pub sha256: String,
    pub created_at: String,
    pub updated_at: String,
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
}

pub struct FileArtifactService {
    base_path: PathBuf,
    project_root: PathBuf,
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
        Ok(Self {
            base_path,
            project_root,
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
    ) -> anyhow::Result<AddedFile> {
        let input = resolve_input_path(file_path)?;
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
        let restore_path = repo_relative_path(&self.project_root, &canonical)?;
        validate_safe_relative_path(&restore_path)?;
        reject_tracked_file(&self.project_root, &restore_path)?;

        let logical_name = match name {
            Some(name) if !name.trim().is_empty() => name.trim().to_string(),
            Some(_) => return Err(anyhow::anyhow!("file name cannot be empty")),
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
        let existing_position = index
            .files
            .iter()
            .position(|entry| entry.scope == scope && entry.name == logical_name);
        if existing_position.is_some() && !force {
            return Err(anyhow::anyhow!(
                "file already exists in {scope}: {logical_name}. Use --force to replace it."
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
            restore_path,
            size: metadata.len(),
            sha256,
            created_at,
            updated_at: now,
        };
        index.files.push(entry.clone());
        index
            .files
            .sort_by(|a, b| (&a.scope, &a.name).cmp(&(&b.scope, &b.name)));
        self.save_index(&index)?;
        self.ensure_local_git_exclude(&entry.restore_path)?;
        Ok(AddedFile { entry, replaced })
    }

    pub fn list_files(&self, scope: Option<&str>) -> anyhow::Result<Vec<FileArtifactEntry>> {
        let mut files = self.load_index()?.files;
        if let Some(scope) = scope {
            files.retain(|entry| entry.scope == scope);
        }
        files.sort_by(|a, b| (&a.scope, &a.name).cmp(&(&b.scope, &b.name)));
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
        let blob = self.read_encrypted_blob(&self.content_path(&entry.id))?;
        let plaintext = self.decrypt_blob("file", &entry.id, &blob)?;
        let target = self.resolve_output_path(&entry, out)?;
        if target.exists() && !force {
            return Err(anyhow::anyhow!(
                "output file already exists: {}. Use --force to overwrite it.",
                target.display()
            ));
        }
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        write_private_file(&target, &plaintext)?;
        let actual_restore_path = repo_relative_path(&self.project_root, &target)?;
        self.ensure_local_git_exclude(&actual_restore_path)?;
        Ok(RestoredFile {
            entry,
            path: target,
        })
    }

    pub fn read_file(&self, scope: &str, name: &str) -> anyhow::Result<Vec<u8>> {
        let entry = self.find_entry(scope, name)?;
        let blob = self.read_encrypted_blob(&self.content_path(&entry.id))?;
        self.decrypt_blob("file", &entry.id, &blob)
    }

    pub fn remove_file(&self, scope: &str, name: &str) -> anyhow::Result<FileArtifactEntry> {
        let mut index = self.load_index()?;
        let position = index
            .files
            .iter()
            .position(|entry| entry.scope == scope && entry.name == name)
            .ok_or_else(|| anyhow::anyhow!("file not found in {scope}: {name}"))?;
        let entry = index.files.remove(position);
        let _ = fs::remove_file(self.content_path(&entry.id));
        self.save_index(&index)?;
        Ok(entry)
    }

    fn find_entry(&self, scope: &str, name: &str) -> anyhow::Result<FileArtifactEntry> {
        self.load_index()?
            .files
            .into_iter()
            .find(|entry| entry.scope == scope && entry.name == name)
            .ok_or_else(|| anyhow::anyhow!("file not found in {scope}: {name}"))
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
            normalize_path(self.project_root.join(&entry.restore_path))?
        };
        reject_symlink_components(&target)?;
        let target = canonicalize_existing_path_prefix(&target)?;
        let relative = repo_relative_path(&self.project_root, &target)
            .map_err(|_| anyhow::anyhow!("output path must stay inside the repository"))?;
        validate_safe_relative_path(&relative)?;
        Ok(target)
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
        validate_safe_relative_path(&entry.restore_path)?;
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

fn resolve_input_path(path: &Path) -> anyhow::Result<PathBuf> {
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

fn validate_safe_relative_path(path: &str) -> anyhow::Result<()> {
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
    if path.is_empty()
        || path.starts_with('/')
        || path.contains('\\')
        || path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(anyhow::anyhow!("invalid repository-relative file path"));
    }
    if path.split('/').any(|part| blocked.contains(&part)) {
        return Err(anyhow::anyhow!(
            "refusing to use file inside ignored or internal directory"
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

fn reject_symlink_components(path: &Path) -> anyhow::Result<()> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        if let Ok(metadata) = fs::symlink_metadata(&current)
            && metadata.file_type().is_symlink()
        {
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
    fs::write(path, bytes)?;
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
