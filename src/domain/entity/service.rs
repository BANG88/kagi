use super::secret::Secret;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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
}
