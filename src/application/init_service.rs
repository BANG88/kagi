use crate::domain::config::{
    DEFAULT_ENV_NAME, KAGI_CONFIG_FILE, KagiConfig, NestedMode, STANDARD_ENV_NAMES,
};
use crate::domain::error::DomainError;
use crate::infrastructure::key_manager::KeyManager;
use std::fs;
use std::path::PathBuf;

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
        fs::create_dir_all(self.base_path.join("services"))?;
        set_private_dir_permissions(&self.base_path.join("services"))?;
        fs::create_dir_all(self.base_path.join("envs"))?;
        set_private_dir_permissions(&self.base_path.join("envs"))?;
        fs::create_dir_all(self.base_path.join("key"))?;
        set_private_dir_permissions(&self.base_path.join("key"))?;
        let config =
            KagiConfig::new_with_settings("1", NestedMode::Bool(self.nested), self.envs.clone());
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

fn set_private_dir_permissions(_path: &std::path::Path) -> Result<(), DomainError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(_path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn set_private_file_permissions(_path: &std::path::Path) -> Result<(), DomainError> {
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
        assert!(base.join("key/master.key").exists());
        assert!(base.join("services").exists());
        assert!(base.join("envs").exists());

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
