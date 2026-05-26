use std::collections::HashMap;
use serde::{Deserialize, Serialize};

pub const KAGI_CONFIG_FILE: &str = "kagi.json";

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
#[serde(untagged)]
pub enum NestedMode {
    Bool(bool),
    Paths(Vec<String>),
}

impl NestedMode {
    pub fn is_allowed(&self, relative_path: &str) -> bool {
        match self {
            NestedMode::Bool(v) => *v,
            NestedMode::Paths(paths) => {
                let rel = relative_path.replace('\\', "/").trim_end_matches('/').to_string();
                paths.iter().any(|p| {
                    let p_norm = p.replace('\\', "/").trim_end_matches('/').to_string();
                    rel == p_norm || rel.starts_with(&(p_norm.clone() + "/"))
                })
            }
        }
    }
}

impl Default for NestedMode {
    fn default() -> Self {
        NestedMode::Bool(true)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    #[serde(default)]
    pub nested: NestedMode,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            nested: NestedMode::default(),
        }
    }
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
        assert!(matches!(config.settings.nested, NestedMode::Bool(true)));
    }

    #[test]
    fn test_config_deserialize_missing_settings() {
        let json = r#"{"version":"1","services":{}}"#;
        let config: KagiConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(config.settings.nested, NestedMode::Bool(true)));
    }

    #[test]
    fn test_config_deserialize_explicit_false() {
        let json = r#"{"version":"1","services":{},"settings":{"nested":false}}"#;
        let config: KagiConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(config.settings.nested, NestedMode::Bool(false)));
    }

    #[test]
    fn test_config_deserialize_nested_paths() {
        let json = r#"{"version":"1","services":{},"settings":{"nested":["api","web/frontend"]}}"#;
        let config: KagiConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(config.settings.nested, NestedMode::Paths(_)));
        let paths = match &config.settings.nested {
            NestedMode::Paths(p) => p.clone(),
            _ => panic!("expected paths"),
        };
        assert_eq!(paths, vec!["api", "web/frontend"]);
    }

    #[test]
    fn test_nested_mode_is_allowed_bool_true() {
        let mode = NestedMode::Bool(true);
        assert!(mode.is_allowed("api/src"));
    }

    #[test]
    fn test_nested_mode_is_allowed_bool_false() {
        let mode = NestedMode::Bool(false);
        assert!(!mode.is_allowed("api/src"));
    }

    #[test]
    fn test_nested_mode_is_allowed_paths_exact() {
        let mode = NestedMode::Paths(vec!["api".into()]);
        assert!(mode.is_allowed("api"));
    }

    #[test]
    fn test_nested_mode_is_allowed_paths_prefix() {
        let mode = NestedMode::Paths(vec!["api".into(), "web/frontend".into()]);
        assert!(mode.is_allowed("api/src"));
        assert!(mode.is_allowed("web/frontend/routes"));
        assert!(!mode.is_allowed("admin"));
    }

    #[test]
    fn test_nested_mode_is_allowed_paths_with_slashes() {
        let mode = NestedMode::Paths(vec!["a/b/folder".into()]);
        assert!(mode.is_allowed("a/b/folder"));
        assert!(mode.is_allowed("a/b/folder/sub"));
        assert!(!mode.is_allowed("a/b/other"));
    }
}
