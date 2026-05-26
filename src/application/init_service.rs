use crate::domain::config::{KAGI_CONFIG_FILE, KagiConfig, NestedMode};
use crate::domain::error::DomainError;
use crate::infrastructure::key_manager::KeyManager;
use std::fs;
use std::path::PathBuf;

pub struct InitService {
    key_manager: KeyManager,
    base_path: PathBuf,
    nested: bool,
}

impl InitService {
    pub fn new(base_path: PathBuf) -> Self {
        Self::with_nested(base_path, false)
    }

    pub fn with_nested(base_path: PathBuf, nested: bool) -> Self {
        Self {
            key_manager: KeyManager::new(base_path.clone()),
            base_path,
            nested,
        }
    }

    pub fn execute(&self) -> Result<(), DomainError> {
        fs::create_dir_all(&self.base_path)?;
        set_private_dir_permissions(&self.base_path)?;
        fs::create_dir_all(self.base_path.join("services"))?;
        set_private_dir_permissions(&self.base_path.join("services"))?;
        fs::create_dir_all(self.base_path.join("key"))?;
        set_private_dir_permissions(&self.base_path.join("key"))?;
        let config = if self.nested {
            KagiConfig::new_with_nested("1", NestedMode::Bool(true))
        } else {
            KagiConfig::new("1")
        };
        let config_path = self.base_path.join(KAGI_CONFIG_FILE);
        fs::write(&config_path, serde_json::to_string_pretty(&config)?)?;
        set_private_file_permissions(&config_path)?;
        self.key_manager.generate_and_save()?;

        if let Some(parent) = self.base_path.parent()
            && let Some(git_root) = find_git_root(parent)
        {
            let gitignore_path = git_root.join(".gitignore");
            let entry = ".kagi/";
            if gitignore_path.exists() {
                let content = fs::read_to_string(&gitignore_path)?;
                if !content.lines().any(|line| line.trim() == entry) {
                    let separator = if content.ends_with('\n') { "" } else { "\n" };
                    fs::write(
                        &gitignore_path,
                        format!("{}{}{}\n", content, separator, entry),
                    )?;
                }
            } else {
                fs::write(&gitignore_path, format!("{}\n", entry))?;
            }
        }

        Ok(())
    }
}

fn find_git_root(start: &std::path::Path) -> Option<PathBuf> {
    let mut current = start;
    loop {
        if current.join(".git").exists() {
            return Some(current.to_path_buf());
        }
        current = current.parent()?;
    }
}

fn set_private_dir_permissions(path: &std::path::Path) -> Result<(), DomainError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn set_private_file_permissions(path: &std::path::Path) -> Result<(), DomainError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
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
        assert!(base.join("key/master.key").exists());
        assert!(base.join("services").exists());

        let config: KagiConfig =
            serde_json::from_str(&fs::read_to_string(base.join(KAGI_CONFIG_FILE)).unwrap())
                .unwrap();
        assert!(matches!(
            config.settings.nested,
            crate::domain::config::NestedMode::Bool(false)
        ));

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
        assert!(content.contains(".kagi/"));
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
        assert!(content.contains(".kagi/"));
        assert!(content.ends_with("\n"));
    }
}
