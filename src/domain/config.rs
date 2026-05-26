use std::collections::HashMap;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct KagiConfig {
    pub version: String,
    pub services: HashMap<String, ServiceConfig>,
    #[serde(default)]
    pub settings: Settings,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ServiceConfig {
    pub file: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    #[serde(default = "default_true")]
    pub nested: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            nested: true,
        }
    }
}

fn default_true() -> bool {
    true
}

impl KagiConfig {
    pub fn new(version: impl Into<String>) -> Self {
        Self {
            version: version.into(),
            services: HashMap::new(),
            settings: Settings::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default_nested() {
        let config = KagiConfig::new("1");
        assert!(config.settings.nested);
    }

    #[test]
    fn test_config_deserialize_missing_settings() {
        let json = r#"{"version":"1","services":{}}"#;
        let config: KagiConfig = serde_json::from_str(json).unwrap();
        assert!(config.settings.nested);
    }

    #[test]
    fn test_config_deserialize_explicit_false() {
        let json = r#"{"version":"1","services":{},"settings":{"nested":false}}"#;
        let config: KagiConfig = serde_json::from_str(json).unwrap();
        assert!(!config.settings.nested);
    }
}
