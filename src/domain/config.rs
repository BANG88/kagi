use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub const KAGI_CONFIG_FILE: &str = "kagi.json";
pub const DEFAULT_ENV_NAME: &str = "development";
pub const STANDARD_ENV_NAMES: &[&str] = &["development", "test", "production"];

fn default_env_name() -> String {
    DEFAULT_ENV_NAME.to_string()
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct KagiConfig {
    pub version: String,
    pub project_id: String,
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
                let rel = relative_path
                    .replace('\\', "/")
                    .trim_end_matches('/')
                    .to_string();
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
        NestedMode::Bool(false)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct Settings {
    #[serde(default)]
    pub nested: NestedMode,
    #[serde(default)]
    pub envs: Vec<String>,
    #[serde(default = "default_env_name")]
    pub default_env: String,
}

impl KagiConfig {
    #[cfg(test)]
    pub fn new(version: impl Into<String>, project_id: impl Into<String>) -> Self {
        Self {
            version: version.into(),
            project_id: project_id.into(),
            services: HashMap::new(),
            settings: Settings {
                default_env: DEFAULT_ENV_NAME.to_string(),
                ..Settings::default()
            },
        }
    }

    pub fn new_with_settings(
        version: impl Into<String>,
        project_id: impl Into<String>,
        nested: NestedMode,
        envs: Vec<String>,
    ) -> Self {
        Self {
            version: version.into(),
            project_id: project_id.into(),
            services: HashMap::new(),
            settings: Settings {
                nested,
                envs,
                default_env: DEFAULT_ENV_NAME.to_string(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default_nested() {
        let config = KagiConfig::new("2", "kgp_test");
        assert!(matches!(config.settings.nested, NestedMode::Bool(false)));
    }

    #[test]
    fn test_config_deserialize_missing_settings() {
        let json = r#"{"version":"2","project_id":"kgp_test","services":{}}"#;
        let config: KagiConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(config.settings.nested, NestedMode::Bool(false)));
    }

    #[test]
    fn test_config_deserialize_explicit_false() {
        let json =
            r#"{"version":"2","project_id":"kgp_test","services":{},"settings":{"nested":false}}"#;
        let config: KagiConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(config.settings.nested, NestedMode::Bool(false)));
    }

    #[test]
    fn test_config_deserialize_nested_paths() {
        let json = r#"{"version":"2","project_id":"kgp_test","services":{},"settings":{"nested":["api","web/frontend"]}}"#;
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
