use std::fs;
use std::path::PathBuf;
use crate::domain::error::DomainError;
use crate::infrastructure::key_manager::KeyManager;

pub struct InitService {
    key_manager: KeyManager,
    base_path: PathBuf,
}

impl InitService {
    pub fn new(base_path: PathBuf) -> Self {
        Self {
            key_manager: KeyManager::new(base_path.clone()),
            base_path,
        }
    }

    pub fn execute(&self) -> Result<(), DomainError> {
        fs::create_dir_all(&self.base_path)?;
        fs::create_dir_all(self.base_path.join("services"))?;
        fs::create_dir_all(self.base_path.join("key"))?;
        let config = serde_json::json!({
            "version": "1",
            "services": {}
        });
        fs::write(self.base_path.join("config.json"), serde_json::to_string_pretty(&config)?)?;
        self.key_manager.generate_and_save()?;
        Ok(())
    }
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
        assert!(base.join("config.json").exists());
        assert!(base.join("key/master.key").exists());
        assert!(base.join("services").exists());
    }
}
