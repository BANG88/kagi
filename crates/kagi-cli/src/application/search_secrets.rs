use kagi_domain::error::DomainError;
use kagi_domain::repository::secret_repo::SecretRepository;

pub struct SearchSecretsService<R: SecretRepository> {
    repo: R,
}

#[derive(Debug, Clone)]
pub struct SearchResult {
    pub scope: String,
    pub key: String,
    pub description: Option<String>,
}

impl<R: SecretRepository> SearchSecretsService<R> {
    pub fn new(repo: R) -> Self {
        Self { repo }
    }

    /// Search secret key names and descriptions (case-insensitive).
    pub fn search_keys(&self, query: &str) -> Result<Vec<SearchResult>, DomainError> {
        let services = self.repo.list_services()?;
        let query_lower = query.to_lowercase();
        let mut results = Vec::new();
        for scope in services {
            let service = self.repo.load(&scope)?;
            for (key, secret) in &service.secrets {
                let desc_match = secret
                    .description
                    .as_ref()
                    .map(|d| d.to_lowercase().contains(&query_lower))
                    .unwrap_or(false);
                if key.to_lowercase().contains(&query_lower) || desc_match {
                    results.push(SearchResult {
                        scope: scope.clone(),
                        key: key.clone(),
                        description: secret.description.clone(),
                    });
                }
            }
        }
        results.sort_by(|a, b| a.scope.cmp(&b.scope).then(a.key.cmp(&b.key)));
        Ok(results)
    }

    /// Search secret key names, descriptions, and decrypted values (case-insensitive).
    pub fn search_values(&self, query: &str) -> Result<Vec<SearchResult>, DomainError> {
        let services = self.repo.list_services()?;
        let query_lower = query.to_lowercase();
        let mut results = Vec::new();
        for scope in services {
            let service = self.repo.load(&scope)?;
            for (key, secret) in &service.secrets {
                let desc_match = secret
                    .description
                    .as_ref()
                    .map(|d| d.to_lowercase().contains(&query_lower))
                    .unwrap_or(false);
                if key.to_lowercase().contains(&query_lower)
                    || desc_match
                    || secret.value.to_lowercase().contains(&query_lower)
                {
                    results.push(SearchResult {
                        scope: scope.clone(),
                        key: key.clone(),
                        description: secret.description.clone(),
                    });
                }
            }
        }
        results.sort_by(|a, b| a.scope.cmp(&b.scope).then(a.key.cmp(&b.key)));
        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kagi_domain::crypto::encryptor::mock::XorEncryptor;
    use kagi_domain::entity::secret::Secret;
    use kagi_domain::entity::service::Service;
    use kagi_store::fs_store::FileStore;
    use tempfile::TempDir;

    fn setup(dir: &TempDir) -> SearchSecretsService<FileStore> {
        let base = dir.path().join(".kagi");
        std::fs::create_dir(&base).unwrap();
        let config = serde_json::json!({"version": "2", "project_id": "kgp_test", "services": {}});
        std::fs::write(
            base.join(kagi_domain::config::KAGI_CONFIG_FILE),
            serde_json::to_string(&config).unwrap(),
        )
        .unwrap();
        let store = FileStore::new(base, Box::new(XorEncryptor::new(0xAB)));
        let mut api = Service::new("api");
        api.set_secret({
            let mut s = Secret::new("DB_HOST", "localhost");
            s.description = Some("Database host".to_string());
            s
        });
        api.set_secret(Secret::new("API_KEY", "secret123"));
        store.save(&api).unwrap();

        let mut web = Service::new("web");
        web.set_secret(Secret::new("REACT_APP_URL", "https://example.com"));
        store.save(&web).unwrap();

        SearchSecretsService::new(store)
    }

    #[test]
    fn test_search_key_name() {
        let dir = TempDir::new().unwrap();
        let svc = setup(&dir);
        let results = svc.search_keys("DB").unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].scope, "api");
        assert_eq!(results[0].key, "DB_HOST");
    }

    #[test]
    fn test_search_description() {
        let dir = TempDir::new().unwrap();
        let svc = setup(&dir);
        let results = svc.search_keys("database").unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].key, "DB_HOST");
    }

    #[test]
    fn test_search_case_insensitive() {
        let dir = TempDir::new().unwrap();
        let svc = setup(&dir);
        let results = svc.search_keys("api").unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].key, "API_KEY");
    }

    #[test]
    fn test_search_values_includes_value_matches() {
        let dir = TempDir::new().unwrap();
        let svc = setup(&dir);
        let results = svc.search_values("example.com").unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].key, "REACT_APP_URL");
    }

    #[test]
    fn test_search_no_matches() {
        let dir = TempDir::new().unwrap();
        let svc = setup(&dir);
        let results = svc.search_keys("NONEXISTENT").unwrap();
        assert!(results.is_empty());
    }
}
