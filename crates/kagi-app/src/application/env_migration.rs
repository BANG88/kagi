use std::path::{Path, PathBuf};

pub const DEFAULT_ENV_SCAN_DEPTH: usize = 4;

#[derive(Debug)]
pub struct EnvFileCandidate {
    pub path: PathBuf,
    pub service_path: Option<String>,
    pub service_name: Option<String>,
    pub env_name: String,
    pub is_template: bool,
}

/// Scan for high-confidence .env files up to 4 directories deep.
pub fn scan_env_files(root_dir: &Path, configured_envs: &[String]) -> Vec<EnvFileCandidate> {
    let mut candidates = Vec::new();
    let walk = ignore::WalkBuilder::new(root_dir)
        .max_depth(Some(DEFAULT_ENV_SCAN_DEPTH + 1))
        .hidden(false)
        .standard_filters(false)
        .build();

    for result in walk {
        let entry = match result {
            Ok(e) => e,
            Err(_) => continue,
        };
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("");
        let Some((env_name, is_template)) = classify_env_file(file_name, configured_envs) else {
            continue;
        };
        // Skip .env files inside common non-project directories
        if is_in_skipped_dir(path, root_dir) {
            continue;
        }
        let service_path = infer_service_path(path, root_dir);
        let service_name = service_path.as_deref().map(service_name_from_path);
        candidates.push(EnvFileCandidate {
            path: path.to_path_buf(),
            service_path,
            service_name,
            env_name,
            is_template,
        });
    }

    candidates.sort_by(|a, b| a.path.cmp(&b.path));
    candidates
}

fn is_in_skipped_dir(path: &Path, root_dir: &Path) -> bool {
    let skipped = [
        "node_modules",
        ".git",
        "target",
        "dist",
        "build",
        ".next",
        "out",
        "vendor",
    ];
    for component in path.strip_prefix(root_dir).unwrap_or(path).components() {
        if let std::path::Component::Normal(name) = component {
            let name = name.to_string_lossy();
            if skipped.iter().any(|s| name == *s) {
                return true;
            }
        }
    }
    false
}

fn classify_env_file(file_name: &str, configured_envs: &[String]) -> Option<(String, bool)> {
    if file_name == ".env" {
        return Some((kagi_domain::config::DEFAULT_ENV_NAME.to_string(), false));
    }

    let suffix = file_name.strip_prefix(".env.")?;
    if matches!(suffix, "example" | "sample" | "template") {
        return Some((kagi_domain::config::DEFAULT_ENV_NAME.to_string(), true));
    }

    if configured_envs.iter().any(|env| env == suffix) {
        return Some((suffix.to_string(), false));
    }

    None
}

fn infer_service_path(file_path: &Path, root_dir: &Path) -> Option<String> {
    let parent = file_path.parent()?;
    if parent == root_dir {
        return None;
    }
    let relative = parent.strip_prefix(root_dir).ok()?;
    let parts: Vec<String> = relative
        .components()
        .filter_map(|part| part.as_os_str().to_str().map(str::to_string))
        .collect();
    if parts.is_empty() {
        None
    } else {
        Some(parts.join("/"))
    }
}

pub fn service_name_from_path(path: &str) -> String {
    path.replace('\\', "/")
        .split('/')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("-")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_scan_finds_root_env() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join(".env"), "KEY=val\n").unwrap();
        let found = scan_env_files(dir.path(), &["development".to_string()]);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].service_name, None);
        assert_eq!(found[0].env_name, "development");
    }

    #[test]
    fn test_scan_finds_hidden_env_files() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join(".env"), "KEY=val\n").unwrap();
        fs::create_dir(dir.path().join("api")).unwrap();
        fs::write(dir.path().join("api/.env"), "KEY=val\n").unwrap();
        let found = scan_env_files(dir.path(), &["development".to_string()]);
        assert_eq!(
            found.len(),
            2,
            "should find both .env files, got: {found:?}",
        );
    }

    #[test]
    fn test_scan_finds_nested_env() {
        let dir = TempDir::new().unwrap();
        fs::create_dir(dir.path().join("api")).unwrap();
        fs::write(dir.path().join("api/.env"), "KEY=val\n").unwrap();
        let found = scan_env_files(dir.path(), &["development".to_string()]);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].service_name, Some("api".to_string()));
        assert_eq!(found[0].service_path, Some("api".to_string()));
    }

    #[test]
    fn test_scan_finds_monorepo_env() {
        let dir = TempDir::new().unwrap();
        fs::create_dir_all(dir.path().join("apps/api")).unwrap();
        fs::write(dir.path().join("apps/api/.env.dev"), "KEY=val\n").unwrap();
        let found = scan_env_files(dir.path(), &["development".to_string(), "dev".to_string()]);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].service_path, Some("apps/api".to_string()));
        assert_eq!(found[0].service_name, Some("apps-api".to_string()));
        assert_eq!(found[0].env_name, "dev");
    }

    #[test]
    fn test_scan_respects_max_depth() {
        let dir = TempDir::new().unwrap();
        fs::create_dir_all(dir.path().join("a/b/c")).unwrap();
        fs::write(dir.path().join("a/.env"), "KEY=val\n").unwrap();
        fs::write(dir.path().join("a/b/.env"), "KEY=val\n").unwrap();
        fs::write(dir.path().join("a/b/c/.env"), "KEY=val\n").unwrap();
        fs::create_dir_all(dir.path().join("a/b/c/d")).unwrap();
        fs::write(dir.path().join("a/b/c/d/.env"), "KEY=val\n").unwrap();
        let found = scan_env_files(dir.path(), &["development".to_string()]);
        let paths: Vec<_> = found.iter().map(|c| c.path.clone()).collect();
        assert!(paths.contains(&dir.path().join("a/.env")));
        assert!(paths.contains(&dir.path().join("a/b/.env")));
        assert!(paths.contains(&dir.path().join("a/b/c/.env")));
        assert!(paths.contains(&dir.path().join("a/b/c/d/.env")));
    }

    #[test]
    fn test_scan_skips_common_non_project_dirs() {
        let dir = TempDir::new().unwrap();
        fs::create_dir_all(dir.path().join("node_modules/some-pkg")).unwrap();
        fs::write(dir.path().join("node_modules/some-pkg/.env"), "KEY=val\n").unwrap();
        fs::create_dir_all(dir.path().join(".git/hooks")).unwrap();
        fs::write(dir.path().join(".git/hooks/.env"), "KEY=val\n").unwrap();
        fs::create_dir_all(dir.path().join("target/debug")).unwrap();
        fs::write(dir.path().join("target/debug/.env"), "KEY=val\n").unwrap();
        fs::write(dir.path().join(".env"), "KEY=val\n").unwrap();
        let found = scan_env_files(dir.path(), &["development".to_string()]);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].service_name, None);
    }

    #[test]
    fn test_scan_skips_env_example() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join(".env"), "KEY=val\n").unwrap();
        fs::write(dir.path().join(".env.example"), "KEY=\n").unwrap();
        fs::write(dir.path().join(".env.local"), "KEY=val\n").unwrap();
        let found = scan_env_files(dir.path(), &["development".to_string()]);
        assert_eq!(found.len(), 2);
        assert!(found.iter().any(|candidate| candidate.is_template));
    }

    #[test]
    fn test_scan_skips_deep_env() {
        let dir = TempDir::new().unwrap();
        fs::create_dir_all(dir.path().join("a/b/c/d/e")).unwrap();
        fs::write(dir.path().join("a/b/c/d/e/.env"), "KEY=val\n").unwrap();
        let found = scan_env_files(dir.path(), &["development".to_string()]);
        assert!(found.is_empty(), "should not find .env at depth > 4");
    }
}
