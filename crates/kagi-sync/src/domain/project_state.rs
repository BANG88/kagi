use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProjectState {
    pub project_id: String,
    pub revision: i64,
    pub kagi_json: String,
    pub access_json: String,
    pub files: Vec<ProjectFile>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProjectFile {
    pub path: String,
    pub content: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
}

#[cfg(feature = "server")]
pub fn validate_file_path(path: &str) -> Result<(), &'static str> {
    if path.starts_with('/') || path.contains("\\") || path.contains("..") {
        return Err("absolute or parent-relative path");
    }
    for part in path.split('/') {
        if part.is_empty() || part == "." || part == ".." {
            return Err("invalid path segment");
        }
    }
    if !path.starts_with("secrets/") || !path.ends_with(".enc") {
        return Err("path must start with secrets/ and end with .enc");
    }
    Ok(())
}

#[cfg(all(test, feature = "server"))]
mod tests {
    use super::*;

    #[test]
    fn test_validate_file_path_valid() {
        assert!(validate_file_path("secrets/api/development.enc").is_ok());
        assert!(validate_file_path("secrets/web/production.enc").is_ok());
    }

    #[test]
    fn test_validate_file_path_rejects_absolute() {
        assert_eq!(
            validate_file_path("/etc/passwd"),
            Err("absolute or parent-relative path")
        );
    }

    #[test]
    fn test_validate_file_path_rejects_backslash() {
        assert_eq!(
            validate_file_path("secrets\\windows.enc"),
            Err("absolute or parent-relative path")
        );
    }

    #[test]
    fn test_validate_file_path_rejects_parent_relative() {
        assert_eq!(
            validate_file_path("secrets/../other.env"),
            Err("absolute or parent-relative path")
        );
    }

    #[test]
    fn test_validate_file_path_rejects_dot_segment() {
        assert_eq!(
            validate_file_path("secrets/./development.enc"),
            Err("invalid path segment")
        );
    }

    #[test]
    fn test_validate_file_path_rejects_empty_segment() {
        assert_eq!(
            validate_file_path("secrets//development.enc"),
            Err("invalid path segment")
        );
    }

    #[test]
    fn test_validate_file_path_rejects_wrong_prefix() {
        assert_eq!(
            validate_file_path("config/development.enc"),
            Err("path must start with secrets/ and end with .enc")
        );
    }

    #[test]
    fn test_validate_file_path_rejects_wrong_suffix() {
        assert_eq!(
            validate_file_path("secrets/api/development.txt"),
            Err("path must start with secrets/ and end with .enc")
        );
    }
}
