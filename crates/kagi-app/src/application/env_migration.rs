use std::path::{Path, PathBuf};

#[derive(Debug)]
pub struct EnvFileCandidate {
    pub path: PathBuf,
    pub service_name: Option<String>,
}

/// Scan for .env files up to 3 levels deep, respecting .gitignore.
pub fn scan_env_files(root_dir: &Path) -> Vec<EnvFileCandidate> {
    let mut candidates = Vec::new();
    let walk = ignore::WalkBuilder::new(root_dir)
        .max_depth(Some(4)) // root + 3 levels deep
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
        if path.file_name() != Some(std::ffi::OsStr::new(".env")) {
            continue;
        }
        // Skip .env files inside common non-project directories
        if is_in_skipped_dir(path, root_dir) {
            continue;
        }
        let service_name = infer_service_name(path, root_dir);
        candidates.push(EnvFileCandidate {
            path: path.to_path_buf(),
            service_name,
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

fn infer_service_name(file_path: &Path, root_dir: &Path) -> Option<String> {
    let parent = file_path.parent()?;
    if parent == root_dir {
        return None;
    }
    parent
        .file_name()
        .map(|name| name.to_string_lossy().to_string())
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
        let found = scan_env_files(dir.path());
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].service_name, None);
    }

    #[test]
    fn test_scan_finds_hidden_env_files() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join(".env"), "KEY=val\n").unwrap();
        fs::create_dir(dir.path().join("api")).unwrap();
        fs::write(dir.path().join("api/.env"), "KEY=val\n").unwrap();
        let found = scan_env_files(dir.path());
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
        let found = scan_env_files(dir.path());
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].service_name, Some("api".to_string()));
    }

    #[test]
    fn test_scan_respects_max_depth() {
        let dir = TempDir::new().unwrap();
        fs::create_dir_all(dir.path().join("a/b/c")).unwrap();
        fs::write(dir.path().join("a/.env"), "KEY=val\n").unwrap();
        fs::write(dir.path().join("a/b/.env"), "KEY=val\n").unwrap();
        fs::write(dir.path().join("a/b/c/.env"), "KEY=val\n").unwrap();
        let found = scan_env_files(dir.path());
        let paths: Vec<_> = found.iter().map(|c| c.path.clone()).collect();
        assert!(paths.contains(&dir.path().join("a/.env")));
        assert!(paths.contains(&dir.path().join("a/b/.env")));
        assert!(paths.contains(&dir.path().join("a/b/c/.env")));
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
        let found = scan_env_files(dir.path());
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].service_name, None);
    }

    #[test]
    fn test_scan_skips_env_example() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join(".env"), "KEY=val\n").unwrap();
        fs::write(dir.path().join(".env.example"), "KEY=\n").unwrap();
        fs::write(dir.path().join(".env.local"), "KEY=val\n").unwrap();
        let found = scan_env_files(dir.path());
        assert_eq!(found.len(), 1);
    }

    #[test]
    fn test_scan_skips_deep_env() {
        let dir = TempDir::new().unwrap();
        fs::create_dir_all(dir.path().join("a/b/c/d")).unwrap();
        fs::write(dir.path().join("a/b/c/d/.env"), "KEY=val\n").unwrap();
        let found = scan_env_files(dir.path());
        assert!(found.is_empty(), "should not find .env at depth > 3");
    }
}
