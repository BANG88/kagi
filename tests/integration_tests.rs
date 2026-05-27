use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::Value;
use std::path::Path;
use tempfile::TempDir;

const KEYRING_SERVICE: &str = "dev.kagi.kagi";

fn kagi_bin() -> Command {
    let mut cmd = Command::cargo_bin("kagi").unwrap();
    cmd.env("KAGI_DISABLE_KEYRING", "1");
    cmd.env(
        "KAGI_HOME",
        std::env::temp_dir().join("kagi-integration-tests"),
    );
    cmd
}

fn kagi_bin_with_keyring(xdg_data_home: &Path) -> Command {
    let mut cmd = Command::cargo_bin("kagi").unwrap();
    cmd.env_remove("KAGI_DISABLE_KEYRING");
    cmd.env_remove("KAGI_HOME");
    cmd.env("XDG_DATA_HOME", xdg_data_home);
    cmd
}

struct KeyringCleanup {
    project_id: String,
}

impl Drop for KeyringCleanup {
    fn drop(&mut self) {
        if keyring::use_native_store(false).is_ok()
            && let Ok(entry) = keyring_core::Entry::new(KEYRING_SERVICE, &self.project_id)
        {
            let _ = entry.delete_credential();
        }
    }
}

fn set_nested_config(kagi_json: &Path, nested: Value) {
    let mut config: Value =
        serde_json::from_str(&std::fs::read_to_string(kagi_json).unwrap()).unwrap();
    config["settings"]["nested"] = nested;
    std::fs::write(kagi_json, serde_json::to_string_pretty(&config).unwrap()).unwrap();
}

#[cfg(windows)]
fn shell_print_literal(value: &str) -> Vec<String> {
    vec![
        "powershell".into(),
        "-NoProfile".into(),
        "-Command".into(),
        format!("[Console]::Write({:?})", value),
    ]
}

#[cfg(not(windows))]
fn shell_print_literal(value: &str) -> Vec<String> {
    vec!["sh".into(), "-c".into(), format!("printf {}", value)]
}

#[cfg(windows)]
fn shell_print_env(name: &str) -> Vec<String> {
    vec![
        "powershell".into(),
        "-NoProfile".into(),
        "-Command".into(),
        format!("[Console]::Write($env:{})", name),
    ]
}

#[cfg(not(windows))]
fn shell_print_env(name: &str) -> Vec<String> {
    vec!["sh".into(), "-c".into(), format!("printf %s \"${}\"", name)]
}

fn assert_run_env(current_dir: &Path, scope: &[&str], key: &str, expected: &str) {
    let mut cmd = kagi_bin();
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
#[ignore = "requires a real unlocked OS keychain/session"]
fn test_os_keychain_project_key_survives_local_data_loss() {
    let dir = TempDir::new().unwrap();
    let xdg = TempDir::new().unwrap();
    std::fs::create_dir(dir.path().join("api")).unwrap();

    let mut init = kagi_bin_with_keyring(xdg.path());
    init.current_dir(&dir);
    init.args(["init", "--nested", "--envs"]);
    init.assert().success();

    let config: Value =
        serde_json::from_str(&std::fs::read_to_string(dir.path().join(".kagi/kagi.json")).unwrap())
            .unwrap();
    let project_id = config["project_id"].as_str().unwrap().to_string();
    let _cleanup = KeyringCleanup { project_id };

    let mut set = kagi_bin_with_keyring(xdg.path());
    set.current_dir(&dir);
    set.args(["set", "api", "MESSAGE", "from-keychain"]);
    set.assert().success();

    assert!(xdg.path().join("kagi/identities/default.agekey").exists());
    assert!(!xdg.path().join("kagi/projects").exists());

    let mut run = kagi_bin_with_keyring(xdg.path());
    run.current_dir(dir.path().join("api"));
    run.args(["run"]);
    run.args(shell_print_env("MESSAGE"));
    run.assert()
        .success()
        .stdout(predicate::eq("from-keychain"));

    std::fs::remove_dir_all(xdg.path().join("kagi")).unwrap();

    let mut run_without_local_data = kagi_bin_with_keyring(xdg.path());
    run_without_local_data.current_dir(dir.path().join("api"));
    run_without_local_data.args(["run"]);
    run_without_local_data.args(shell_print_env("MESSAGE"));
    run_without_local_data
        .assert()
        .success()
        .stdout(predicate::eq("from-keychain"));

    assert!(!xdg.path().join("kagi/projects").exists());
}

#[test]
fn test_init() {
    let dir = TempDir::new().unwrap();
    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.arg("init");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("kagi:"))
        .stdout(predicate::str::contains("Initialized"));
    assert!(dir.path().join(".kagi/kagi.json").exists());
    assert!(dir.path().join(".kagi/access.json").exists());
    assert!(dir.path().join(".kagi/secrets").exists());
    assert!(!dir.path().join(".kagi/access").exists());
    assert!(!dir.path().join(".kagi/members").exists());

    let config: Value =
        serde_json::from_str(&std::fs::read_to_string(dir.path().join(".kagi/kagi.json")).unwrap())
            .unwrap();
    assert!(config["project_id"].as_str().unwrap().starts_with("kgp_"));
    assert_eq!(config["settings"]["nested"], false);
    assert_eq!(
        config["settings"]["envs"],
        serde_json::json!(["development"])
    );
}

#[test]
fn test_init_envs_configures_defaults_without_creating_service_scopes() {
    let dir = TempDir::new().unwrap();
    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.args(["init", "--envs", "development,test,production"]);
    cmd.assert().success();

    let config: Value =
        serde_json::from_str(&std::fs::read_to_string(dir.path().join(".kagi/kagi.json")).unwrap())
            .unwrap();
    assert_eq!(
        config["settings"]["envs"],
        serde_json::json!(["development", "test", "production"])
    );
    assert!(config["services"].as_object().unwrap().is_empty());
    assert!(!dir.path().join(".kagi/secrets/development.enc").exists());
}

#[test]
fn test_init_envs_without_values_uses_standard_envs() {
    let dir = TempDir::new().unwrap();
    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.arg("init").arg("--envs");
    cmd.assert().success();

    let config: Value =
        serde_json::from_str(&std::fs::read_to_string(dir.path().join(".kagi/kagi.json")).unwrap())
            .unwrap();
    assert_eq!(
        config["settings"]["envs"],
        serde_json::json!(["development", "test", "production"])
    );
}

#[test]
fn test_init_nested_enables_inference() {
    let dir = TempDir::new().unwrap();
    let mut cmd = kagi_bin();
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
    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.arg("init");
    cmd.assert().success();
    assert!(!dir.path().join(".gitignore").exists());
}

#[test]
fn test_init_updates_gitignore_for_shareable_kagi_directory() {
    let dir = TempDir::new().unwrap();
    std::fs::create_dir(dir.path().join(".git")).unwrap();
    std::fs::create_dir(dir.path().join("tests")).unwrap();
    std::fs::write(
        dir.path().join(".gitignore"),
        ".kagi/\n/tests/.kagi/\n/target\n",
    )
    .unwrap();

    let mut cmd = kagi_bin();
    cmd.current_dir(dir.path().join("tests"));
    cmd.arg("init");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Commit .kagi/"));

    let gitignore = std::fs::read_to_string(dir.path().join(".gitignore")).unwrap();
    assert!(gitignore.contains("/target"));
    assert!(gitignore.contains(".env"));
    assert!(gitignore.contains(".env.*"));
    assert!(!gitignore.contains("tests/.kagi/local/"));
    assert!(!gitignore.contains("tests/.kagi/*.key"));
    assert!(
        !gitignore
            .lines()
            .any(|line| matches!(line.trim(), ".kagi/" | "/tests/.kagi/"))
    );
}

#[test]
fn test_root_command_prints_help_successfully() {
    let mut cmd = kagi_bin();
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("|___/   鍵"))
        .stdout(predicate::str::contains("Core Flow"))
        .stdout(predicate::str::contains("Usage"));
}

#[test]
fn test_set_and_get() {
    let dir = TempDir::new().unwrap();

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.arg("init");
    cmd.assert().success();

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.args(["set", "api", "KEY", "val"]);
    cmd.assert().success();

    assert_run_env(dir.path(), &["api"], "KEY", "val");
}

#[test]
fn test_set_preserves_special_characters_when_passed_as_one_argument() {
    let dir = TempDir::new().unwrap();
    let value = r#"postgres://u:p@localhost/db?sslmode=disable&name="dev app" $literal"#;

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.arg("init");
    cmd.assert().success();

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.args(["set", "development", "DATABASE_URL", value]);
    cmd.assert().success();

    assert_run_env(dir.path(), &["development"], "DATABASE_URL", value);
}

#[test]
fn test_set_does_not_print_secret_value() {
    let dir = TempDir::new().unwrap();

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.arg("init");
    cmd.assert().success();

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.args(["set", "api", "API_KEY", "super_secret"]);
    let assert = cmd.assert().success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(
        stdout.contains("api/development.API_KEY"),
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

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.arg("init");
    cmd.assert().success();

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.args(["set", "api", "KEY", "val"]);
    cmd.assert().success();

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.args(["get", "api", "KEY"]);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("requires an interactive terminal"));
}

#[test]
fn test_get_show_blocks_non_interactive() {
    let dir = TempDir::new().unwrap();

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.arg("init");
    cmd.assert().success();

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.args(["set", "api", "KEY", "val"]);
    cmd.assert().success();

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.args(["get", "api", "--show"]);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("requires an interactive terminal"));
}

#[test]
fn test_get_show_values_flag_does_not_exist() {
    let dir = TempDir::new().unwrap();

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.args(["get", "api", "--show-values"]);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("unexpected argument"));
}

#[test]
fn test_get_lists_masked_service_envs_and_keys() {
    let dir = TempDir::new().unwrap();

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.arg("init");
    cmd.assert().success();

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.args(["set", "api", "KEY", "val"]);
    cmd.assert().success();

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.args(["get"]);
    let assert = cmd.assert().success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(
        stdout.contains("api"),
        "expected api in get output: {}",
        stdout
    );
    assert!(
        stdout.contains("  development"),
        "expected development env under api: {}",
        stdout
    );
    assert!(
        stdout.contains("Key"),
        "expected table header in get output: {}",
        stdout
    );
    assert!(
        stdout.contains("Value"),
        "expected table header in get output: {}",
        stdout
    );
    assert!(
        stdout.contains("KEY"),
        "expected KEY in get output: {}",
        stdout
    );
    assert!(
        stdout.contains("********"),
        "expected masked value in get output: {}",
        stdout
    );
    assert!(
        !stdout.contains("val"),
        "get should not reveal values by default: {}",
        stdout
    );

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.args(["get", "api"]);
    let assert = cmd.assert().success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(
        stdout.contains("api\n  development"),
        "expected service/env layout in get api: {}",
        stdout
    );
    assert!(
        stdout.contains("Key"),
        "expected table header in get api: {}",
        stdout
    );
    assert!(
        stdout.contains("Value"),
        "expected table header in get api: {}",
        stdout
    );
    assert!(
        stdout.contains("KEY"),
        "expected KEY in get api: {}",
        stdout
    );
    assert!(
        stdout.contains("********"),
        "expected masked value in get api: {}",
        stdout
    );
    assert!(
        !stdout.contains("val"),
        "get should not reveal values by default: {}",
        stdout
    );

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.args(["list"]);
    cmd.assert().failure();
}

#[test]
fn test_join_and_member_approve_flow() {
    let dir = TempDir::new().unwrap();

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.arg("init");
    cmd.assert().success();

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.args(["join", "--name", "alice"]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("created join request"))
        .stdout(predicate::str::contains("kagi member approve"));

    let access_path = dir.path().join(".kagi/access.json");
    let access: Value =
        serde_json::from_str(&std::fs::read_to_string(&access_path).unwrap()).unwrap();
    let request = access["members"]
        .as_array()
        .unwrap()
        .iter()
        .find(|member| member["status"] == "pending")
        .unwrap();
    let member_id = request["member_id"].as_str().unwrap().to_string();
    assert_eq!(request["name"], "alice");
    assert_eq!(request["status"], "pending");

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.args(["member", "list"]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Members"))
        .stdout(predicate::str::contains("Join Requests"))
        .stdout(predicate::str::contains("alice"));

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.args(["member", "approve", &member_id]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("approved member"));

    let access: Value =
        serde_json::from_str(&std::fs::read_to_string(&access_path).unwrap()).unwrap();
    let member = access["members"]
        .as_array()
        .unwrap()
        .iter()
        .find(|member| member["member_id"] == member_id)
        .unwrap();
    assert_eq!(member["status"], "active");
    assert!(member["wrapped_key"].as_str().unwrap().len() > 20);
}

#[test]
fn test_multiple_join_requests_can_be_pending_together() {
    let dir = TempDir::new().unwrap();

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.arg("init");
    cmd.assert().success();

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.args(["join", "--name", "alice"]);
    cmd.assert().success();

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.args(["join", "--name", "bob"]);
    cmd.assert().success();

    let access: Value = serde_json::from_str(
        &std::fs::read_to_string(dir.path().join(".kagi/access.json")).unwrap(),
    )
    .unwrap();
    let pending: Vec<_> = access["members"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|member| member["status"] == "pending")
        .collect();
    assert_eq!(pending.len(), 2);
    assert!(pending.iter().any(|member| member["name"] == "alice"));
    assert!(pending.iter().any(|member| member["name"] == "bob"));
}

#[test]
fn test_member_remove_requires_interactive_confirmation() {
    let dir = TempDir::new().unwrap();

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.arg("init");
    cmd.assert().success();

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.args(["member", "remove", "kgm_fake"]);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("requires an interactive terminal"));
}

#[test]
fn test_team_doctor_and_key_commands_do_not_exist() {
    let mut cmd = kagi_bin();
    cmd.arg("team");
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("unrecognized subcommand"));

    let mut cmd = kagi_bin();
    cmd.arg("doctor");
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("unrecognized subcommand"));

    let mut cmd = kagi_bin();
    cmd.arg("key");
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("unrecognized subcommand"));
}

#[test]
fn test_export_blocks_non_interactive() {
    let dir = TempDir::new().unwrap();

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.arg("init");
    cmd.assert().success();

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.args(["set", "api", "KEY", "val"]);
    cmd.assert().success();

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.args(["export", "api"]);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("requires an interactive terminal"));
}

#[test]
fn test_export_service_env_shorthand_blocks_non_interactive() {
    let dir = TempDir::new().unwrap();

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.args(["init", "--envs", "development,production"]);
    cmd.assert().success();

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.args(["set", "api", "production", "KEY", "val"]);
    cmd.assert().success();

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.args(["export", "api", "production"]);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("requires an interactive terminal"));
}

#[test]
fn test_export_service_all_envs_blocks_non_interactive() {
    let dir = TempDir::new().unwrap();

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.args(["init", "--envs", "development,production"]);
    cmd.assert().success();

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.args(["set", "api", "production", "KEY", "val"]);
    cmd.assert().success();

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.args(["export", "api"]);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("requires an interactive terminal"));
}

#[test]
fn test_export_service_all_envs_requires_out_even_after_confirmation_guard() {
    let dir = TempDir::new().unwrap();

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.args(["init", "--envs", "development,production"]);
    cmd.assert().success();

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.args(["set", "api", "production", "KEY", "val"]);
    cmd.assert().success();

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.args(["export", "api", "--out", "envs"]);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("requires an interactive terminal"));
}

#[test]
fn test_encrypted_store_uses_versioned_xchacha_format() {
    let dir = TempDir::new().unwrap();

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.arg("init");
    cmd.assert().success();

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.args(["set", "api", "KEY", "val"]);
    cmd.assert().success();

    let content =
        std::fs::read_to_string(dir.path().join(".kagi/secrets/api/development.enc")).unwrap();
    let json: Value = serde_json::from_str(&content).unwrap();
    assert_eq!(json["version"], 1);
    assert_eq!(json["algorithm"], "XCHACHA20-POLY1305");
    assert!(json["aad"].as_str().unwrap().len() > 10);
    assert!(!content.contains("\"val\""));
}

#[test]
fn test_import_from_file() {
    let dir = TempDir::new().unwrap();

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.arg("init");
    cmd.assert().success();

    std::fs::write(
        dir.path().join("development.env"),
        "API_KEY=secret\nDB_URL=postgres://localhost\n",
    )
    .unwrap();

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.args(["import", "api", "--file", "development.env"]);
    cmd.assert().success();

    assert_run_env(dir.path(), &["api"], "API_KEY", "secret");
    assert_run_env(dir.path(), &["api"], "DB_URL", "postgres://localhost");
}

#[test]
fn test_import_service_env_shorthand() {
    let dir = TempDir::new().unwrap();

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.args(["init", "--envs", "development,production"]);
    cmd.assert().success();

    std::fs::write(dir.path().join("production.env"), "API_KEY=secret\n").unwrap();

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.args(["import", "api", "production", "--file", "production.env"]);
    cmd.assert().success();

    assert_run_env(dir.path(), &["api", "production"], "API_KEY", "secret");
}

#[test]
fn test_import_force_overwrites() {
    let dir = TempDir::new().unwrap();

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.arg("init");
    cmd.assert().success();

    std::fs::write(dir.path().join("first.env"), "API_KEY=old_value\n").unwrap();
    std::fs::write(
        dir.path().join("second.env"),
        "API_KEY=new_value\nEXTRA_KEY=extra\n",
    )
    .unwrap();

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.args(["import", "api", "--file", "first.env"]);
    cmd.assert().success();

    assert_run_env(dir.path(), &["api"], "API_KEY", "old_value");

    let mut cmd = kagi_bin();
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

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.arg("init");
    cmd.assert().success();

    std::fs::write(
        dir.path().join(".env.example"),
        "DATABASE_URL=postgres://localhost\n# WEBHOOK_SECRET=\nDEBUG=true\n",
    )
    .unwrap();

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.arg("sync");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("kagi: synced"));

    assert_run_env(
        dir.path(),
        &["development"],
        "DATABASE_URL",
        "postgres://localhost",
    );
    assert_run_env(dir.path(), &["development"], "WEBHOOK_SECRET", "");
    assert_run_env(dir.path(), &["test"], "DEBUG", "true");
}

#[test]
fn test_sync_skips_existing_keys() {
    let dir = TempDir::new().unwrap();

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.arg("init");
    cmd.assert().success();

    std::fs::write(dir.path().join(".env.example"), "API_KEY=default\n").unwrap();

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.args(["set", "development", "API_KEY", "custom"]);
    cmd.assert().success();

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.arg("sync");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("skipped"));

    assert_run_env(dir.path(), &["development"], "API_KEY", "custom");
}

#[test]
fn test_nested_disabled_uses_parent_without_inference() {
    let dir = TempDir::new().unwrap();

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.arg("init");
    cmd.assert().success();

    let child = dir.path().join("api");
    std::fs::create_dir(&child).unwrap();

    let mut cmd = kagi_bin();
    cmd.current_dir(&child);
    cmd.arg("get");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("no services found"));

    let mut cmd = kagi_bin();
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
    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.arg("init");
    cmd.assert().success();

    let kagi_json = dir.path().join(".kagi/kagi.json");
    set_nested_config(&kagi_json, serde_json::json!(["api"]));

    // Allowed child path
    let api_dir = dir.path().join("api/src");
    std::fs::create_dir_all(&api_dir).unwrap();
    let mut cmd = kagi_bin();
    cmd.current_dir(&api_dir);
    cmd.arg("get");
    cmd.assert().success();

    // Disallowed child path still uses the parent .kagi, but does not infer "web".
    let web_dir = dir.path().join("web");
    std::fs::create_dir(&web_dir).unwrap();
    let mut cmd = kagi_bin();
    cmd.current_dir(&web_dir);
    cmd.arg("get");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("no services found"));
}

#[test]
fn test_set_infers_service_from_nested_dir() {
    let dir = TempDir::new().unwrap();

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.arg("init");
    cmd.assert().success();

    let kagi_json = dir.path().join(".kagi/kagi.json");
    set_nested_config(&kagi_json, serde_json::json!(true));

    let api_dir = dir.path().join("api");
    std::fs::create_dir_all(&api_dir).unwrap();

    let mut cmd = kagi_bin();
    cmd.current_dir(&api_dir);
    cmd.args(["set", "KEY", "val"]);
    cmd.assert().success();

    assert_run_env(&api_dir, &[], "KEY", "val");
}

#[test]
fn test_get_infers_service_from_nested_dir() {
    let dir = TempDir::new().unwrap();

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.arg("init");
    cmd.assert().success();

    let kagi_json = dir.path().join(".kagi/kagi.json");
    set_nested_config(&kagi_json, serde_json::json!(true));

    let api_dir = dir.path().join("api");
    std::fs::create_dir_all(&api_dir).unwrap();

    let mut cmd = kagi_bin();
    cmd.current_dir(&api_dir);
    cmd.args(["set", "KEY", "val"]);
    cmd.assert().success();

    assert_run_env(&api_dir, &[], "KEY", "val");
}

#[test]
fn test_export_inferred_scope_blocks_non_interactive() {
    let dir = TempDir::new().unwrap();

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.arg("init");
    cmd.assert().success();

    let kagi_json = dir.path().join(".kagi/kagi.json");
    set_nested_config(&kagi_json, serde_json::json!(true));

    let api_dir = dir.path().join("api");
    std::fs::create_dir_all(&api_dir).unwrap();

    let mut cmd = kagi_bin();
    cmd.current_dir(&api_dir);
    cmd.args(["set", "KEY", "val"]);
    cmd.assert().success();

    let mut cmd = kagi_bin();
    cmd.current_dir(&api_dir);
    cmd.arg("export");
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("requires an interactive terminal"));
}

#[test]
fn test_nested_env_scope_keeps_service_shorthand() {
    let dir = TempDir::new().unwrap();

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.arg("init");
    cmd.assert().success();

    let kagi_json = dir.path().join(".kagi/kagi.json");
    set_nested_config(&kagi_json, serde_json::json!(true));

    let api_dir = dir.path().join("api");
    std::fs::create_dir_all(&api_dir).unwrap();

    let mut cmd = kagi_bin();
    cmd.current_dir(&api_dir);
    cmd.args(["set", "development", "KEY", "val"]);
    cmd.assert().success();

    assert_run_env(&api_dir, &["development"], "KEY", "val");

    assert!(
        dir.path()
            .join(".kagi/secrets/api/development.enc")
            .exists()
    );
}

#[test]
fn test_service_defaults_to_development_and_precreates_configured_envs() {
    let dir = TempDir::new().unwrap();

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.args(["init", "--envs", "development,test,production"]);
    cmd.assert().success();

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.args(["set", "--service", "api", "KEY", "val"]);
    cmd.assert().success();

    assert_run_env(dir.path(), &["api"], "KEY", "val");
    assert!(
        dir.path()
            .join(".kagi/secrets/api/development.enc")
            .exists()
    );
    assert!(dir.path().join(".kagi/secrets/api/test.enc").exists());
    assert!(dir.path().join(".kagi/secrets/api/production.enc").exists());
}

#[test]
fn test_root_service_env_shorthand() {
    let dir = TempDir::new().unwrap();

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.args(["init", "--envs", "development,test,production"]);
    cmd.assert().success();

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.args(["set", "api", "production", "KEY", "production-value"]);
    cmd.assert().success();

    assert_run_env(
        dir.path(),
        &["api", "production"],
        "KEY",
        "production-value",
    );
}

#[test]
fn test_env_add_and_rename_updates_service_envs() {
    let dir = TempDir::new().unwrap();

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.args(["init", "--envs", "development,test"]);
    cmd.assert().success();

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.args(["set", "api", "KEY", "development-value"]);
    cmd.assert().success();

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.args(["env", "add", "staging"]);
    cmd.assert().success();
    assert!(dir.path().join(".kagi/secrets/api/staging.enc").exists());

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.args(["set", "api", "staging", "KEY", "staging-value"]);
    cmd.assert().success();

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.args(["env", "rename", "staging", "qa"]);
    cmd.assert().success();

    assert!(!dir.path().join(".kagi/secrets/api/staging.enc").exists());
    assert!(dir.path().join(".kagi/secrets/api/qa.enc").exists());
    assert_run_env(dir.path(), &["api", "qa"], "KEY", "staging-value");
}

#[test]
fn test_get_service_groups_environment_scopes() {
    let dir = TempDir::new().unwrap();

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.args(["init", "--envs", "development,production"]);
    cmd.assert().success();

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.args(["set", "api", "production", "KEY", "production-value"]);
    cmd.assert().success();

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.args(["get", "api"]);
    let assert = cmd.assert().success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(
        stdout.contains("api\n  development"),
        "expected api/development layout: {}",
        stdout
    );
    assert!(
        stdout.contains("  production"),
        "expected api/production layout: {}",
        stdout
    );
    assert!(stdout.contains("KEY"), "expected key: {}", stdout);
    assert!(
        !stdout.contains("production-value"),
        "get should mask values by default: {}",
        stdout
    );
}

#[test]
fn test_env_del_requires_interactive_confirmation() {
    let dir = TempDir::new().unwrap();

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.args(["init", "--envs", "development,staging"]);
    cmd.assert().success();

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.args(["env", "del", "staging"]);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("requires an interactive terminal"));
}

#[test]
fn test_env_add_rejects_existing_service_name() {
    let dir = TempDir::new().unwrap();

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.arg("init");
    cmd.assert().success();

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.args(["set", "api", "KEY", "value"]);
    cmd.assert().success();

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.args(["env", "add", "api"]);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("conflicts with existing service"));
}

#[test]
fn test_nested_run_prefers_command_shorthand_over_root_scope_name() {
    let dir = TempDir::new().unwrap();

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.arg("init");
    cmd.assert().success();

    let kagi_json = dir.path().join(".kagi/kagi.json");
    set_nested_config(&kagi_json, serde_json::json!(true));

    let shell = shell_print_env("KEY");
    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.args(["set", shell[0].as_str(), "KEY", "root"]);
    cmd.assert().success();

    let api_dir = dir.path().join("api");
    std::fs::create_dir_all(&api_dir).unwrap();

    let mut cmd = kagi_bin();
    cmd.current_dir(&api_dir);
    cmd.args(["set", "KEY", "nested"]);
    cmd.assert().success();

    let mut cmd = kagi_bin();
    cmd.current_dir(&api_dir);
    let mut args = vec!["run".to_string()];
    args.extend(shell);
    cmd.args(args);
    cmd.assert().success().stdout("nested");
}

#[test]
fn test_nested_run_without_existing_scope_runs_without_env() {
    let dir = TempDir::new().unwrap();

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.arg("init");
    cmd.assert().success();

    let kagi_json = dir.path().join(".kagi/kagi.json");
    set_nested_config(&kagi_json, serde_json::json!(true));

    let api_dir = dir.path().join("api");
    std::fs::create_dir_all(&api_dir).unwrap();

    let mut cmd = kagi_bin();
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

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.arg("init");
    cmd.assert().success();

    let kagi_json = dir.path().join(".kagi/kagi.json");
    set_nested_config(&kagi_json, serde_json::json!(true));

    let api_dir = dir.path().join("api");
    std::fs::create_dir_all(&api_dir).unwrap();

    // Set secret for 'web' service while in api/ directory
    let mut cmd = kagi_bin();
    cmd.current_dir(&api_dir);
    cmd.args(["set", "--service", "web", "KEY", "val"]);
    cmd.assert().success();

    // Verify it's under 'web', not 'api'
    assert_run_env(dir.path(), &["web"], "KEY", "val");
}

#[test]
fn test_set_requires_service_when_no_inference() {
    let dir = TempDir::new().unwrap();

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.arg("init");
    cmd.assert().success();

    // In root directory (no nested inference), omitting service should fail
    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.args(["set", "KEY", "val"]);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Usage:"));
}
