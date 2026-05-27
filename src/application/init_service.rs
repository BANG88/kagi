use crate::domain::config::{
    DEFAULT_ENV_NAME, KAGI_CONFIG_FILE, KagiConfig, NestedMode, STANDARD_ENV_NAMES,
};
use crate::domain::error::DomainError;
use crate::infrastructure::key_manager::KeyManager;
use std::fs;
use std::path::{Path, PathBuf};

pub struct InitService {
    key_manager: KeyManager,
    base_path: PathBuf,
    nested: bool,
    envs: Vec<String>,
}

impl InitService {
    #[cfg(test)]
    pub fn new(base_path: PathBuf) -> Self {
        Self::with_nested(base_path, false)
    }

    #[cfg(test)]
    pub fn with_nested(base_path: PathBuf, nested: bool) -> Self {
        Self::with_nested_and_envs(base_path, nested, None)
    }

    pub fn with_nested_and_envs(
        base_path: PathBuf,
        nested: bool,
        envs: Option<Vec<String>>,
    ) -> Self {
        let envs = match envs {
            Some(envs) => {
                let envs: Vec<String> = envs
                    .into_iter()
                    .filter(|env| !env.trim().is_empty())
                    .collect();
                if envs.is_empty() {
                    STANDARD_ENV_NAMES
                        .iter()
                        .map(|env| (*env).to_string())
                        .collect()
                } else {
                    envs
                }
            }
            None => vec![DEFAULT_ENV_NAME.to_string()],
        };
        let envs = if envs.iter().any(|env| env == DEFAULT_ENV_NAME) {
            envs
        } else {
            let mut with_default = vec![DEFAULT_ENV_NAME.to_string()];
            with_default.extend(envs);
            with_default
        };

        Self {
            key_manager: KeyManager::new(base_path.clone()),
            base_path,
            nested,
            envs,
        }
    }

    pub fn execute(&self) -> Result<(), DomainError> {
        fs::create_dir_all(&self.base_path)?;
        set_private_dir_permissions(&self.base_path)?;
        fs::create_dir_all(self.base_path.join("secrets"))?;
        set_private_dir_permissions(&self.base_path.join("secrets"))?;

        let project_id = KeyManager::generate_project_id();
        let member_id = KeyManager::generate_member_id();
        let config = KagiConfig::new_with_settings(
            "2",
            project_id.clone(),
            NestedMode::Bool(self.nested),
            self.envs.clone(),
        );
        let config_path = self.base_path.join(KAGI_CONFIG_FILE);
        fs::write(&config_path, serde_json::to_string_pretty(&config)?)?;
        set_private_file_permissions(&config_path)?;
        self.key_manager
            .initialize_project(&project_id, &member_id)?;

        if let Some(parent) = self.base_path.parent()
            && let Some(git_root) = find_git_root(parent)
        {
            let gitignore_path = git_root.join(".gitignore");
            let kagi_prefix = gitignore_kagi_prefix(&git_root, parent);
            if gitignore_path.exists() {
                let content = fs::read_to_string(&gitignore_path)?;
                let content = next_gitignore_content(&content, &kagi_prefix);
                fs::write(&gitignore_path, content)?;
            } else {
                fs::write(&gitignore_path, gitignore_entries())?;
            }
        }

        Ok(())
    }
}

fn find_git_root(start: &Path) -> Option<PathBuf> {
    let mut current = start;
    loop {
        if current.join(".git").exists() {
            return Some(current.to_path_buf());
        }
        current = current.parent()?;
    }
}

fn gitignore_kagi_prefix(git_root: &Path, project_root: &Path) -> String {
    let relative = project_root.strip_prefix(git_root).unwrap_or(project_root);
    if relative.as_os_str().is_empty() {
        ".kagi".to_string()
    } else {
        format!("{}/.kagi", path_to_gitignore_pattern(relative))
    }
}

fn path_to_gitignore_pattern(path: &Path) -> String {
    path.components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

fn gitignore_entries() -> String {
    [".env", ".env.*", "!.env.example"].join("\n") + "\n"
}

fn next_gitignore_content(content: &str, kagi_prefix: &str) -> String {
    let mut lines: Vec<String> = content
        .lines()
        .filter(|line| !is_broad_kagi_ignore(line.trim(), kagi_prefix))
        .map(ToString::to_string)
        .collect();

    for entry in gitignore_entries().lines() {
        if !lines.iter().any(|line| line.trim() == entry) {
            lines.push(entry.to_string());
        }
    }

    let mut next = lines.join("\n");
    next.push('\n');
    next
}

fn is_broad_kagi_ignore(pattern: &str, kagi_prefix: &str) -> bool {
    if pattern.is_empty() || pattern.starts_with('#') || pattern.starts_with('!') {
        return false;
    }

    let normalized = pattern.trim_start_matches('/');
    let root_wide_patterns = [".kagi", ".kagi/", ".kagi/*", ".kagi/**"];
    if root_wide_patterns.contains(&normalized) {
        return true;
    }

    [
        kagi_prefix.to_string(),
        format!("{kagi_prefix}/"),
        format!("{kagi_prefix}/*"),
        format!("{kagi_prefix}/**"),
    ]
    .iter()
    .any(|entry| normalized == entry)
}

fn set_private_dir_permissions(_path: &Path) -> Result<(), DomainError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(_path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn set_private_file_permissions(_path: &Path) -> Result<(), DomainError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(_path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_init_creates_structure() {
        let dir = TempDir::new().unwrap();
        let base = dir.path().join(".kagi");
        let service = InitService::new(base.clone());
        service.execute().unwrap();
        assert!(base.join(KAGI_CONFIG_FILE).exists());
        assert!(base.join("access.json").exists());
        assert!(base.join("secrets").exists());
        assert!(!base.join("key").exists());
        assert!(!base.join("members").exists());
        assert!(!base.join("access").exists());
        assert!(!base.join("services").exists());
        assert!(!base.join("envs").exists());

        let config: KagiConfig =
            serde_json::from_str(&fs::read_to_string(base.join(KAGI_CONFIG_FILE)).unwrap())
                .unwrap();
        assert!(config.project_id.starts_with("kgp_"));
        assert!(matches!(
            config.settings.nested,
            crate::domain::config::NestedMode::Bool(false)
        ));
        let access: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(base.join("access.json")).unwrap()).unwrap();
        assert_eq!(access["members"].as_array().unwrap().len(), 1);
        assert_eq!(access["members"][0]["status"], "active");

        let gitignore = dir.path().join(".gitignore");
        assert!(!gitignore.exists());
    }

    #[test]
    fn test_init_can_enable_nested() {
        let dir = TempDir::new().unwrap();
        let base = dir.path().join(".kagi");
        let service = InitService::with_nested(base.clone(), true);
        service.execute().unwrap();

        let config: KagiConfig =
            serde_json::from_str(&fs::read_to_string(base.join(KAGI_CONFIG_FILE)).unwrap())
                .unwrap();
        assert!(matches!(
            config.settings.nested,
            crate::domain::config::NestedMode::Bool(true)
        ));
    }

    #[test]
    fn test_init_updates_gitignore_in_git_repo() {
        let dir = TempDir::new().unwrap();
        fs::create_dir(dir.path().join(".git")).unwrap();

        let base = dir.path().join(".kagi");
        let service = InitService::new(base);
        service.execute().unwrap();

        let gitignore = dir.path().join(".gitignore");
        assert!(gitignore.exists());
        let content = fs::read_to_string(gitignore).unwrap();
        assert!(content.contains(".env"));
        assert!(content.contains(".env.*"));
        assert!(!content.contains(".kagi/local/"));
        assert!(!content.contains(".kagi/*.key"));
        assert!(
            !content
                .lines()
                .any(|line| is_broad_kagi_ignore(line.trim(), ".kagi"))
        );
    }

    #[test]
    fn test_init_appends_to_existing_gitignore() {
        let dir = TempDir::new().unwrap();
        fs::create_dir(dir.path().join(".git")).unwrap();
        let gitignore = dir.path().join(".gitignore");
        fs::write(&gitignore, "/target\n").unwrap();

        let base = dir.path().join(".kagi");
        let service = InitService::new(base);
        service.execute().unwrap();

        let content = fs::read_to_string(&gitignore).unwrap();
        assert!(content.contains("/target"));
        assert!(content.contains(".env"));
        assert!(!content.contains(".kagi/local/"));
        assert!(!content.contains(".kagi/*.key"));
        assert!(
            !content
                .lines()
                .any(|line| is_broad_kagi_ignore(line.trim(), ".kagi"))
        );
        assert!(content.ends_with("\n"));
    }

    #[test]
    fn test_init_rewrites_gitignore_for_subdirectory_project() {
        let dir = TempDir::new().unwrap();
        fs::create_dir(dir.path().join(".git")).unwrap();
        fs::create_dir_all(dir.path().join("tests")).unwrap();
        let gitignore = dir.path().join(".gitignore");
        fs::write(&gitignore, ".kagi/\n/tests/.kagi/\n/target\n").unwrap();

        let base = dir.path().join("tests/.kagi");
        let service = InitService::new(base);
        service.execute().unwrap();

        let content = fs::read_to_string(&gitignore).unwrap();
        assert!(content.contains("/target"));
        assert!(content.contains(".env"));
        assert!(!content.contains("tests/.kagi/local/"));
        assert!(!content.contains("tests/.kagi/*.key"));
        assert!(
            !content
                .lines()
                .any(|line| is_broad_kagi_ignore(line.trim(), "tests/.kagi"))
        );
    }
}
