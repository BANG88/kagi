use crate::domain::error::DomainError;
use crate::domain::repository::secret_repo::SecretRepository;

pub struct ListServicesService<R: SecretRepository> {
    repo: R,
}

impl<R: SecretRepository> ListServicesService<R> {
    pub fn new(repo: R) -> Self {
        Self { repo }
    }

    /// When service_name is None, returns list of service names (value is empty).
    /// When service_name is Some, returns list of (key, value) pairs for that service.
    pub fn execute(&self, service_name: Option<&str>) -> Result<Vec<(String, String)>, DomainError> {
        match service_name {
            Some(name) => {
                let service = self.repo.load(name)?;
                let mut items: Vec<_> = service.secrets.iter()
                    .map(|(k, v)| (k.clone(), v.value.clone()))
                    .collect();
                items.sort_by(|a, b| a.0.cmp(&b.0));
                Ok(items)
            }
            None => {
                let mut services = self.repo.list_services()?;
                services.sort();
                Ok(services.into_iter().map(|s| (s, String::new())).collect())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::crypto::encryptor::mock::XorEncryptor;
    use crate::domain::entity::secret::Secret;
    use crate::domain::entity::service::Service;
    use crate::infrastructure::fs_store::FileStore;
    use tempfile::TempDir;

    fn setup(dir: &TempDir) -> ListServicesService<FileStore> {
        let base = dir.path().join(".kagi");
        std::fs::create_dir(&base).unwrap();
        let config = serde_json::json!({"version": "1", "services": {}});
        std::fs::write(base.join(crate::domain::config::KAGI_CONFIG_FILE), serde_json::to_string(&config).unwrap()).unwrap();
        let store = FileStore::new(base, Box::new(XorEncryptor::new(0xAB)));
        let mut svc = Service::new("api");
        svc.set_secret(Secret::new("A", "1"));
        svc.set_secret(Secret::new("B", "2"));
        store.save(&svc).unwrap();
        ListServicesService::new(store)
    }

    #[test]
    fn test_list_services() {
        let dir = TempDir::new().unwrap();
        let svc = setup(&dir);
        let list = svc.execute(None).unwrap();
        assert_eq!(list, vec![("api".into(), "".into())]);
    }

    #[test]
    fn test_list_keys() {
        let dir = TempDir::new().unwrap();
        let svc = setup(&dir);
        let keys = svc.execute(Some("api")).unwrap();
        assert_eq!(keys, vec![("A".into(), "1".into()), ("B".into(), "2".into())]);
    }
}
