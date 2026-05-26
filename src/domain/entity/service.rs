use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use super::secret::Secret;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Service {
    pub name: String,
    pub secrets: HashMap<String, Secret>,
}

impl Service {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            secrets: HashMap::new(),
        }
    }

    pub fn set_secret(&mut self, secret: Secret) {
        self.secrets.insert(secret.key.clone(), secret);
    }

    pub fn get_secret(&self, key: &str) -> Option<&Secret> {
        self.secrets.get(key)
    }

    pub fn list_keys(&self) -> Vec<&String> {
        self.secrets.keys().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_new_empty() {
        let svc = Service::new("api");
        assert_eq!(svc.name, "api");
        assert!(svc.secrets.is_empty());
    }

    #[test]
    fn test_service_set_and_get() {
        let mut svc = Service::new("api");
        svc.set_secret(Secret::new("KEY", "val"));
        assert_eq!(svc.get_secret("KEY").unwrap().value, "val");
    }

    #[test]
    fn test_service_list_keys() {
        let mut svc = Service::new("api");
        svc.set_secret(Secret::new("A", "1"));
        svc.set_secret(Secret::new("B", "2"));
        let mut keys = svc.list_keys();
        keys.sort();
        assert_eq!(keys, vec!["A", "B"]);
    }
}
