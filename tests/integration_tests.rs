use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::Value;
use std::path::Path;
use tempfile::TempDir;

#[cfg(windows)]
fn shell_print_literal(value: &str) -> Vec<String> {
    vec![
        "cmd".into(),
        "/C".into(),
        format!("<nul set /p dummy={}", value),
    ]
}

#[cfg(not(windows))]
fn shell_print_literal(value: &str) -> Vec<String> {
    vec!["sh".into(), "-c".into(), format!("printf {}", value)]
}

#[cfg(windows)]
fn shell_print_env(name: &str) -> Vec<String> {
    vec![
        "cmd".into(),
        "/C".into(),
        format!("<nul set /p dummy=%{}%", name),
    ]
}

#[cfg(not(windows))]
fn shell_print_env(name: &str) -> Vec<String> {
    vec!["sh".into(), "-c".into(), format!("printf %s \"${}\"", name)]
}

fn assert_run_env(current_dir: &Path, scope: &[&str], key: &str, expected: &str) {
    let mut cmd = Command::cargo_bin("kagi").unwrap();
    cmd.current_dir(current_dir);
    let mut args = vec!["run".to_string()];
    args.extend(scope.iter().map(|part| part.to_string()));
    args.extend(shell_print_env(key));
    cmd.args(args);
    cmd.assert()
        .success()
        .stdout(predicate::eq(expected.to_string()));
}

#[test]
fn test_init() {
    let dir = TempDir::new().unwrap();
    let mut cmd = Command::cargo_bin("kagi").unwrap();
    cmd.current_dir(&dir);
    cmd.arg("init");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("kagi:"))
        .stdout(predicate::str::contains("Initialized"));
    assert!(dir.path().join(".kagi/kagi.json").exists());
    assert!(dir.path().join(".kagi/key/master.key").exists());

    let config: Value =
        serde_json::from_str(&std::fs::read_to_string(dir.path().join(".kagi/kagi.json")).unwrap())
            .unwrap();
    assert_eq!(config["settings"]["nested"], false);
}

#[test]
fn test_init_nested_enables_inference() {
    let dir = TempDir::new().unwrap();
    let mut cmd = Command::cargo_bin("kagi").unwrap();
    cmd.current_dir(&dir);
    cmd.args(["init", "--nested"]);
    cmd.assert().success();

    let config: Value =
        serde_json::from_str(&std::fs::read_to_string(dir.path().join(".kagi/kagi.json")).unwrap())
            .unwrap();
    assert_eq!(config["settings"]["nested"], true);
}

#[test]
fn test_init_does_not_create_gitignore_outside_git_repo() {
    let dir = TempDir::new().unwrap();
    let mut cmd = Command::cargo_bin("kagi").unwrap();
    cmd.current_dir(&dir);
    cmd.arg("init");
    cmd.assert().success();
    assert!(!dir.path().join(".gitignore").exists());
}

#[test]
fn test_root_command_prints_help_successfully() {
    let mut cmd = Command::cargo_bin("kagi").unwrap();
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("|___/   鍵"))
        .stdout(predicate::str::contains("Core Flow"))
        .stdout(predicate::str::contains("Usage"));
}

#[test]
fn test_set_and_get() {
    let dir = TempDir::new().unwrap();

    let mut cmd = Command::cargo_bin("kagi").unwrap();
    cmd.current_dir(&dir);
    cmd.arg("init");
    cmd.assert().success();

    let mut cmd = Command::cargo_bin("kagi").unwrap();
    cmd.current_dir(&dir);
    cmd.args(["set", "api", "KEY", "val"]);
    cmd.assert().success();

    assert_run_env(dir.path(), &["api"], "KEY", "val");
}

#[test]
fn test_set_preserves_special_characters_when_passed_as_one_argument() {
    let dir = TempDir::new().unwrap();
    let value = r#"postgres://u:p@localhost/db?sslmode=disable&name="dev app" $literal"#;

    let mut cmd = Command::cargo_bin("kagi").unwrap();
    cmd.current_dir(&dir);
    cmd.arg("init");
    cmd.assert().success();

    let mut cmd = Command::cargo_bin("kagi").unwrap();
    cmd.current_dir(&dir);
    cmd.args(["set", "dev", "DATABASE_URL", value]);
    cmd.assert().success();

    assert_run_env(dir.path(), &["dev"], "DATABASE_URL", value);
}

#[test]
fn test_set_does_not_print_secret_value() {
    let dir = TempDir::new().unwrap();

    let mut cmd = Command::cargo_bin("kagi").unwrap();
    cmd.current_dir(&dir);
    cmd.arg("init");
    cmd.assert().success();

    let mut cmd = Command::cargo_bin("kagi").unwrap();
    cmd.current_dir(&dir);
    cmd.args(["set", "api", "API_KEY", "super_secret"]);
    let assert = cmd.assert().success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(
        stdout.contains("api.API_KEY"),
        "expected key in set output: {}",
        stdout
    );
    assert!(
        !stdout.contains("super_secret"),
        "set output leaked secret: {}",
        stdout
    );
}

#[test]
fn test_get_blocks_non_interactive_by_default() {
    let dir = TempDir::new().unwrap();

    let mut cmd = Command::cargo_bin("kagi").unwrap();
    cmd.current_dir(&dir);
    cmd.arg("init");
    cmd.assert().success();

    let mut cmd = Command::cargo_bin("kagi").unwrap();
    cmd.current_dir(&dir);
    cmd.args(["set", "api", "KEY", "val"]);
    cmd.assert().success();

    let mut cmd = Command::cargo_bin("kagi").unwrap();
    cmd.current_dir(&dir);
    cmd.args(["get", "api", "KEY"]);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("requires an interactive terminal"));
}

#[test]
fn test_list() {
    let dir = TempDir::new().unwrap();

    let mut cmd = Command::cargo_bin("kagi").unwrap();
    cmd.current_dir(&dir);
    cmd.arg("init");
    cmd.assert().success();

    let mut cmd = Command::cargo_bin("kagi").unwrap();
    cmd.current_dir(&dir);
    cmd.args(["set", "api", "KEY", "val"]);
    cmd.assert().success();

    let mut cmd = Command::cargo_bin("kagi").unwrap();
    cmd.current_dir(&dir);
    cmd.args(["list"]);
    let assert = cmd.assert().success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(
        stdout.contains("api"),
        "expected api in list output: {}",
        stdout
    );

    let mut cmd = Command::cargo_bin("kagi").unwrap();
    cmd.current_dir(&dir);
    cmd.args(["list", "api"]);
    let assert = cmd.assert().success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(
        stdout.contains("Key"),
        "expected table header in list api: {}",
        stdout
    );
    assert!(
        stdout.contains("Value"),
        "expected table header in list api: {}",
        stdout
    );
    assert!(
        stdout.contains("KEY"),
        "expected KEY in list api: {}",
        stdout
    );
    assert!(
        stdout.contains("********"),
        "expected masked value in list api: {}",
        stdout
    );
    assert!(
        !stdout.contains("val"),
        "list should not reveal values by default: {}",
        stdout
    );
}

#[test]
fn test_export_blocks_non_interactive() {
    let dir = TempDir::new().unwrap();

    let mut cmd = Command::cargo_bin("kagi").unwrap();
    cmd.current_dir(&dir);
    cmd.arg("init");
    cmd.assert().success();

    let mut cmd = Command::cargo_bin("kagi").unwrap();
    cmd.current_dir(&dir);
    cmd.args(["set", "api", "KEY", "val"]);
    cmd.assert().success();

    let mut cmd = Command::cargo_bin("kagi").unwrap();
    cmd.current_dir(&dir);
    cmd.args(["export", "api"]);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("requires an interactive terminal"));
}

#[test]
fn test_encrypted_store_uses_versioned_xchacha_format() {
    let dir = TempDir::new().unwrap();

    let mut cmd = Command::cargo_bin("kagi").unwrap();
    cmd.current_dir(&dir);
    cmd.arg("init");
    cmd.assert().success();

    let mut cmd = Command::cargo_bin("kagi").unwrap();
    cmd.current_dir(&dir);
    cmd.args(["set", "api", "KEY", "val"]);
    cmd.assert().success();

    let content = std::fs::read_to_string(dir.path().join(".kagi/services/api.enc")).unwrap();
    let json: Value = serde_json::from_str(&content).unwrap();
    assert_eq!(json["version"], 1);
    assert_eq!(json["algorithm"], "XCHACHA20-POLY1305");
    assert!(json["aad"].as_str().unwrap().len() > 10);
    assert!(!content.contains("\"val\""));
}

#[test]
fn test_import_from_file() {
    let dir = TempDir::new().unwrap();

    let mut cmd = Command::cargo_bin("kagi").unwrap();
    cmd.current_dir(&dir);
    cmd.arg("init");
    cmd.assert().success();

    std::fs::write(
        dir.path().join("dev.env"),
        "API_KEY=secret\nDB_URL=postgres://localhost\n",
    )
    .unwrap();

    let mut cmd = Command::cargo_bin("kagi").unwrap();
    cmd.current_dir(&dir);
    cmd.args(["import", "api", "--file", "dev.env"]);
    cmd.assert().success();

    assert_run_env(dir.path(), &["api"], "API_KEY", "secret");
    assert_run_env(dir.path(), &["api"], "DB_URL", "postgres://localhost");
}

#[test]
fn test_import_force_overwrites() {
    let dir = TempDir::new().unwrap();

    let mut cmd = Command::cargo_bin("kagi").unwrap();
    cmd.current_dir(&dir);
    cmd.arg("init");
    cmd.assert().success();

    std::fs::write(dir.path().join("first.env"), "API_KEY=old_value\n").unwrap();
    std::fs::write(
        dir.path().join("second.env"),
        "API_KEY=new_value\nEXTRA_KEY=extra\n",
    )
    .unwrap();

    let mut cmd = Command::cargo_bin("kagi").unwrap();
    cmd.current_dir(&dir);
    cmd.args(["import", "api", "--file", "first.env"]);
    cmd.assert().success();

    assert_run_env(dir.path(), &["api"], "API_KEY", "old_value");

    let mut cmd = Command::cargo_bin("kagi").unwrap();
    cmd.current_dir(&dir);
    cmd.args(["import", "api", "--file", "second.env", "--force"]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("overwritten"));

    assert_run_env(dir.path(), &["api"], "API_KEY", "new_value");
    assert_run_env(dir.path(), &["api"], "EXTRA_KEY", "extra");
}

#[test]
fn test_sync_from_example() {
    let dir = TempDir::new().unwrap();

    let mut cmd = Command::cargo_bin("kagi").unwrap();
    cmd.current_dir(&dir);
    cmd.arg("init");
    cmd.assert().success();

    std::fs::write(
        dir.path().join(".env.example"),
        "DATABASE_URL=postgres://localhost\n# WEBHOOK_SECRET=\nDEBUG=true\n",
    )
    .unwrap();

    let mut cmd = Command::cargo_bin("kagi").unwrap();
    cmd.current_dir(&dir);
    cmd.arg("sync");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("kagi: synced"));

    assert_run_env(dir.path(), &["dev"], "DATABASE_URL", "postgres://localhost");
    assert_run_env(dir.path(), &["dev"], "WEBHOOK_SECRET", "");
    assert_run_env(dir.path(), &["test"], "DEBUG", "true");
}

#[test]
fn test_sync_skips_existing_keys() {
    let dir = TempDir::new().unwrap();

    let mut cmd = Command::cargo_bin("kagi").unwrap();
    cmd.current_dir(&dir);
    cmd.arg("init");
    cmd.assert().success();

    std::fs::write(dir.path().join(".env.example"), "API_KEY=default\n").unwrap();

    let mut cmd = Command::cargo_bin("kagi").unwrap();
    cmd.current_dir(&dir);
    cmd.args(["set", "dev", "API_KEY", "custom"]);
    cmd.assert().success();

    let mut cmd = Command::cargo_bin("kagi").unwrap();
    cmd.current_dir(&dir);
    cmd.arg("sync");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("skipped"));

    assert_run_env(dir.path(), &["dev"], "API_KEY", "custom");
}

#[test]
fn test_nested_disabled_uses_parent_without_inference() {
    let dir = TempDir::new().unwrap();

    let mut cmd = Command::cargo_bin("kagi").unwrap();
    cmd.current_dir(&dir);
    cmd.arg("init");
    cmd.assert().success();

    let child = dir.path().join("api");
    std::fs::create_dir(&child).unwrap();

    let mut cmd = Command::cargo_bin("kagi").unwrap();
    cmd.current_dir(&child);
    cmd.arg("list");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("no services found"));

    let mut cmd = Command::cargo_bin("kagi").unwrap();
    cmd.current_dir(&child);
    let mut args = vec!["run".to_string()];
    args.extend(shell_print_literal("ok"));
    cmd.args(args);
    cmd.assert()
        .success()
        .stdout("ok")
        .stderr(predicate::str::contains(
            "no environment or service scope specified",
        ));
}

#[test]
fn test_nested_selective_paths() {
    let dir = TempDir::new().unwrap();

    // Init in parent with selective nested paths
    let mut cmd = Command::cargo_bin("kagi").unwrap();
    cmd.current_dir(&dir);
    cmd.arg("init");
    cmd.assert().success();

    let kagi_json = dir.path().join(".kagi/kagi.json");
    std::fs::write(
        &kagi_json,
        r#"{"version":"1","services":{},"settings":{"nested":["api"]}}"#,
    )
    .unwrap();

    // Allowed child path
    let api_dir = dir.path().join("api/src");
    std::fs::create_dir_all(&api_dir).unwrap();
    let mut cmd = Command::cargo_bin("kagi").unwrap();
    cmd.current_dir(&api_dir);
    cmd.arg("list");
    cmd.assert().success();

    // Disallowed child path still uses the parent .kagi, but does not infer "web".
    let web_dir = dir.path().join("web");
    std::fs::create_dir(&web_dir).unwrap();
    let mut cmd = Command::cargo_bin("kagi").unwrap();
    cmd.current_dir(&web_dir);
    cmd.arg("list");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("no services found"));
}

#[test]
fn test_set_infers_service_from_nested_dir() {
    let dir = TempDir::new().unwrap();

    let mut cmd = Command::cargo_bin("kagi").unwrap();
    cmd.current_dir(&dir);
    cmd.arg("init");
    cmd.assert().success();

    let kagi_json = dir.path().join(".kagi/kagi.json");
    std::fs::write(
        &kagi_json,
        r#"{"version":"1","services":{},"settings":{"nested":true}}"#,
    )
    .unwrap();

    let api_dir = dir.path().join("api");
    std::fs::create_dir_all(&api_dir).unwrap();

    let mut cmd = Command::cargo_bin("kagi").unwrap();
    cmd.current_dir(&api_dir);
    cmd.args(["set", "KEY", "val"]);
    cmd.assert().success();

    assert_run_env(&api_dir, &[], "KEY", "val");
}

#[test]
fn test_get_infers_service_from_nested_dir() {
    let dir = TempDir::new().unwrap();

    let mut cmd = Command::cargo_bin("kagi").unwrap();
    cmd.current_dir(&dir);
    cmd.arg("init");
    cmd.assert().success();

    let kagi_json = dir.path().join(".kagi/kagi.json");
    std::fs::write(
        &kagi_json,
        r#"{"version":"1","services":{},"settings":{"nested":true}}"#,
    )
    .unwrap();

    let api_dir = dir.path().join("api");
    std::fs::create_dir_all(&api_dir).unwrap();

    let mut cmd = Command::cargo_bin("kagi").unwrap();
    cmd.current_dir(&api_dir);
    cmd.args(["set", "KEY", "val"]);
    cmd.assert().success();

    assert_run_env(&api_dir, &[], "KEY", "val");
}

#[test]
fn test_export_inferred_scope_blocks_non_interactive() {
    let dir = TempDir::new().unwrap();

    let mut cmd = Command::cargo_bin("kagi").unwrap();
    cmd.current_dir(&dir);
    cmd.arg("init");
    cmd.assert().success();

    let kagi_json = dir.path().join(".kagi/kagi.json");
    std::fs::write(
        &kagi_json,
        r#"{"version":"1","services":{},"settings":{"nested":true}}"#,
    )
    .unwrap();

    let api_dir = dir.path().join("api");
    std::fs::create_dir_all(&api_dir).unwrap();

    let mut cmd = Command::cargo_bin("kagi").unwrap();
    cmd.current_dir(&api_dir);
    cmd.args(["set", "KEY", "val"]);
    cmd.assert().success();

    let mut cmd = Command::cargo_bin("kagi").unwrap();
    cmd.current_dir(&api_dir);
    cmd.arg("export");
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("requires an interactive terminal"));
}

#[test]
fn test_nested_env_scope_keeps_service_shorthand() {
    let dir = TempDir::new().unwrap();

    let mut cmd = Command::cargo_bin("kagi").unwrap();
    cmd.current_dir(&dir);
    cmd.arg("init");
    cmd.assert().success();

    let kagi_json = dir.path().join(".kagi/kagi.json");
    std::fs::write(
        &kagi_json,
        r#"{"version":"1","services":{},"settings":{"nested":true}}"#,
    )
    .unwrap();

    let api_dir = dir.path().join("api");
    std::fs::create_dir_all(&api_dir).unwrap();

    let mut cmd = Command::cargo_bin("kagi").unwrap();
    cmd.current_dir(&api_dir);
    cmd.args(["set", "dev", "KEY", "val"]);
    cmd.assert().success();

    assert_run_env(&api_dir, &["dev"], "KEY", "val");

    assert!(dir.path().join(".kagi/services/api/dev.enc").exists());
}

#[test]
fn test_nested_run_prefers_command_shorthand_over_root_scope_name() {
    let dir = TempDir::new().unwrap();

    let mut cmd = Command::cargo_bin("kagi").unwrap();
    cmd.current_dir(&dir);
    cmd.arg("init");
    cmd.assert().success();

    let kagi_json = dir.path().join(".kagi/kagi.json");
    std::fs::write(
        &kagi_json,
        r#"{"version":"1","services":{},"settings":{"nested":true}}"#,
    )
    .unwrap();

    let shell = shell_print_env("KEY");
    let mut cmd = Command::cargo_bin("kagi").unwrap();
    cmd.current_dir(&dir);
    cmd.args(["set", shell[0].as_str(), "KEY", "root"]);
    cmd.assert().success();

    let api_dir = dir.path().join("api");
    std::fs::create_dir_all(&api_dir).unwrap();

    let mut cmd = Command::cargo_bin("kagi").unwrap();
    cmd.current_dir(&api_dir);
    cmd.args(["set", "KEY", "nested"]);
    cmd.assert().success();

    let mut cmd = Command::cargo_bin("kagi").unwrap();
    cmd.current_dir(&api_dir);
    let mut args = vec!["run".to_string()];
    args.extend(shell);
    cmd.args(args);
    cmd.assert().success().stdout("nested");
}

#[test]
fn test_nested_run_without_existing_scope_runs_without_env() {
    let dir = TempDir::new().unwrap();

    let mut cmd = Command::cargo_bin("kagi").unwrap();
    cmd.current_dir(&dir);
    cmd.arg("init");
    cmd.assert().success();

    let kagi_json = dir.path().join(".kagi/kagi.json");
    std::fs::write(
        &kagi_json,
        r#"{"version":"1","services":{},"settings":{"nested":true}}"#,
    )
    .unwrap();

    let api_dir = dir.path().join("api");
    std::fs::create_dir_all(&api_dir).unwrap();

    let mut cmd = Command::cargo_bin("kagi").unwrap();
    cmd.current_dir(&api_dir);
    let mut args = vec!["run".to_string()];
    args.extend(shell_print_literal("ok"));
    cmd.args(args);
    cmd.assert()
        .success()
        .stdout("ok")
        .stderr(predicate::str::contains(
            "no secrets found for inferred scope",
        ));
}

#[test]
fn test_explicit_service_overrides_inference() {
    let dir = TempDir::new().unwrap();

    let mut cmd = Command::cargo_bin("kagi").unwrap();
    cmd.current_dir(&dir);
    cmd.arg("init");
    cmd.assert().success();

    let kagi_json = dir.path().join(".kagi/kagi.json");
    std::fs::write(
        &kagi_json,
        r#"{"version":"1","services":{},"settings":{"nested":true}}"#,
    )
    .unwrap();

    let api_dir = dir.path().join("api");
    std::fs::create_dir_all(&api_dir).unwrap();

    // Set secret for 'web' service while in api/ directory
    let mut cmd = Command::cargo_bin("kagi").unwrap();
    cmd.current_dir(&api_dir);
    cmd.args(["set", "--service", "web", "KEY", "val"]);
    cmd.assert().success();

    // Verify it's under 'web', not 'api'
    assert_run_env(dir.path(), &["web"], "KEY", "val");
}

#[test]
fn test_set_requires_service_when_no_inference() {
    let dir = TempDir::new().unwrap();

    let mut cmd = Command::cargo_bin("kagi").unwrap();
    cmd.current_dir(&dir);
    cmd.arg("init");
    cmd.assert().success();

    // In root directory (no nested inference), omitting service should fail
    let mut cmd = Command::cargo_bin("kagi").unwrap();
    cmd.current_dir(&dir);
    cmd.args(["set", "KEY", "val"]);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Usage:"));
}
