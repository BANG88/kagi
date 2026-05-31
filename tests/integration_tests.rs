use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::Value;
use std::fs;
#[cfg(feature = "server")]
use std::io::{Read, Write};
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

#[cfg(feature = "server")]
fn kagi_bin_with_home(home: &Path) -> Command {
    let mut cmd = Command::cargo_bin("kagi").unwrap();
    cmd.env("KAGI_DISABLE_KEYRING", "1");
    cmd.env("KAGI_HOME", home);
    cmd
}

#[cfg(feature = "server")]
struct ServerGuard {
    child: std::process::Child,
    _dir: TempDir,
}

#[cfg(feature = "server")]
impl Drop for ServerGuard {
    fn drop(&mut self) {
        if let Err(e) = self.child.kill() {
            eprintln!("Warning: failed to kill server process: {e}");
        }
        let _ = self.child.wait();
    }
}

#[cfg(feature = "server")]
fn parse_port_from_line(line: &str) -> Option<u16> {
    let prefix = "kagi: listening on http://";
    let start = line.find(prefix)?;
    let rest = &line[start + prefix.len()..];
    let colon = rest.rfind(':')?;
    let port_str = &rest[colon + 1..];
    port_str.parse().ok()
}

#[cfg(feature = "server")]
fn spawn_server() -> (ServerGuard, String, u16) {
    let server_dir = TempDir::new().unwrap();
    let db_path = server_dir.path().join("server.db");
    let key_path = server_dir.path().join("server.key");

    let mut cmd = std::process::Command::new(
        std::env::var("CARGO_BIN_EXE_kagi").expect("CARGO_BIN_EXE_kagi not set"),
    );
    cmd.env("KAGI_DISABLE_KEYRING", "1");
    cmd.env("KAGI_HOME", server_dir.path().join("kagi-home"));
    cmd.env("RUST_LOG", "info");
    cmd.args([
        "serve",
        "--bind",
        "127.0.0.1:0",
        "--db",
        db_path.to_str().unwrap(),
        "--key-file",
        key_path.to_str().unwrap(),
    ]);
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());

    let mut child = cmd.spawn().expect("failed to spawn kagi serve");

    // Drain stderr in a background thread early to prevent pipe buffer fill-up
    let stderr = child.stderr.take().unwrap();
    std::thread::spawn(move || {
        let mut reader = std::io::BufReader::new(stderr);
        for _ in std::io::BufRead::lines(&mut reader) {}
    });

    let stdout = child.stdout.take().unwrap();
    let reader = std::io::BufReader::new(stdout);
    let (line_tx, line_rx) = std::sync::mpsc::channel();

    std::thread::spawn(move || {
        let mut reader = reader;
        for line in std::io::BufRead::lines(&mut reader).map_while(Result::ok) {
            let _ = line_tx.send(line);
        }
    });

    let mut token = String::new();
    let mut port: Option<u16> = None;
    let timeout = std::time::Duration::from_secs(10);
    let start = std::time::Instant::now();

    while token.is_empty() || port.is_none() {
        if start.elapsed() > timeout {
            let _ = child.kill();
            panic!(
                "server startup timed out after {}s (token_found={}, port_found={})",
                timeout.as_secs(),
                !token.is_empty(),
                port.is_some()
            );
        }

        match line_rx.recv_timeout(std::time::Duration::from_millis(100)) {
            Ok(line) => {
                if line.contains("generated admin token:") {
                    token = line
                        .split("generated admin token:")
                        .nth(1)
                        .unwrap()
                        .trim()
                        .to_string();
                }
                if let Some(p) = parse_port_from_line(&line) {
                    port = Some(p);
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                let _ = child.kill();
                panic!("server stdout closed unexpectedly before startup completed");
            }
        }
    }

    let port = port.unwrap();

    // Verify HTTP readiness by performing a simple GET request
    let mut ready = false;
    for _ in 0..50 {
        std::thread::sleep(std::time::Duration::from_millis(100));
        if let Ok(mut stream) = std::net::TcpStream::connect(format!("127.0.0.1:{port}"))
            && stream
                .write_all(b"GET /v1/server-key HTTP/1.1\r\nHost: localhost\r\n\r\n")
                .is_ok()
        {
            let mut buf = [0u8; 12];
            if stream.read(&mut buf).is_ok() && buf.starts_with(b"HTTP/1.1") {
                ready = true;
                break;
            }
        }
    }

    if !ready {
        let _ = child.kill();
        panic!("server did not become HTTP-ready on port {port} within 5 seconds");
    }

    (
        ServerGuard {
            child,
            _dir: server_dir,
        },
        token,
        port,
    )
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
    let assert = cmd
        .assert()
        .success()
        .stdout(predicate::str::contains("|___/   K"))
        .stdout(predicate::str::contains("Core Flow"))
        .stdout(predicate::str::contains("Usage"));
    #[cfg(feature = "server")]
    let assert = assert.stdout(predicate::str::contains(
        "remote login, register, sync, and administer remotes",
    ));
    #[cfg(not(feature = "server"))]
    let assert = assert.stdout(predicate::str::contains("remote login").not());
    assert
        .stdout(predicate::str::contains("  push").not())
        .stdout(predicate::str::contains("  pull").not())
        .stdout(predicate::str::contains("  status").not())
        .stdout(predicate::str::contains("  project").not());
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
        "expected key in set output: {stdout}"
    );
    assert!(
        !stdout.contains("super_secret"),
        "set output leaked secret: {stdout}"
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
        "expected api in get output: {stdout}"
    );
    assert!(
        stdout.contains("  development"),
        "expected development env under api: {stdout}"
    );
    assert!(
        stdout.contains("Key"),
        "expected table header in get output: {stdout}"
    );
    assert!(
        stdout.contains("Value"),
        "expected table header in get output: {stdout}"
    );
    assert!(
        stdout.contains("KEY"),
        "expected KEY in get output: {stdout}"
    );
    assert!(
        stdout.contains("********"),
        "expected masked value in get output: {stdout}"
    );
    assert!(
        !stdout.contains("val"),
        "get should not reveal values by default: {stdout}"
    );

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.args(["get", "api"]);
    let assert = cmd.assert().success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(
        stdout.contains("api\n  development"),
        "expected service/env layout in get api: {stdout}"
    );
    assert!(
        stdout.contains("Key"),
        "expected table header in get api: {stdout}"
    );
    assert!(
        stdout.contains("Value"),
        "expected table header in get api: {stdout}"
    );
    assert!(stdout.contains("KEY"), "expected KEY in get api: {stdout}");
    assert!(
        stdout.contains("********"),
        "expected masked value in get api: {stdout}"
    );
    assert!(
        !stdout.contains("val"),
        "get should not reveal values by default: {stdout}"
    );

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.args(["list"]);
    cmd.assert().failure();
}

#[test]
fn test_member_request_and_approve_flow() {
    let dir = TempDir::new().unwrap();

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.arg("init");
    cmd.assert().success();

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.args(["member", "request", "--name", "alice"]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("created member request"))
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
        .stdout(predicate::str::contains("Member Requests"))
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
fn test_multiple_member_requests_can_be_pending_together() {
    let dir = TempDir::new().unwrap();

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.arg("init");
    cmd.assert().success();

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.args(["member", "request", "--name", "alice"]);
    cmd.assert().success();

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.args(["member", "request", "--name", "bob"]);
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
    cmd.arg("key");
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("unrecognized subcommand"));
}

#[test]
fn test_unset_requires_interactive() {
    let dir = TempDir::new().unwrap();
    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.arg("init");
    cmd.assert().success();

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.args(["unset", "api", "KEY"]);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("requires an interactive terminal"));
}

#[test]
fn test_unset_rejects_non_key_selection() {
    let dir = TempDir::new().unwrap();
    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.arg("init");
    cmd.assert().success();

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.args(["unset", "api"]);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Unset only supports a single key"));
}

#[test]
fn test_doctor_reports_issues_on_uninitialized_dir() {
    let dir = TempDir::new().unwrap();
    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.arg("doctor");
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("No .kagi directory found"));
}

#[test]
fn test_doctor_passes_on_healthy_project() {
    let dir = TempDir::new().unwrap();
    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.arg("init");
    cmd.assert().success();

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.arg("doctor");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("all checks passed"));
}

#[test]
fn test_doctor_fix_requires_interactive() {
    let dir = TempDir::new().unwrap();
    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.arg("init");
    cmd.assert().success();

    // Create a fake rotation journal in the correct path so --fix has something to recover
    let kagi_json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(dir.path().join(".kagi/kagi.json")).unwrap())
            .unwrap();
    let project_id = kagi_json["project_id"].as_str().unwrap().to_string();
    let access_json = std::fs::read_to_string(dir.path().join(".kagi/access.json")).unwrap();
    let journal = serde_json::json!({
        "version": 1,
        "project_id": project_id,
        "access_json": access_json,
        "files": {}
    });
    let kagi_home = std::env::temp_dir().join("kagi-integration-tests");
    let journal_dir = kagi_home.join("projects");
    std::fs::create_dir_all(&journal_dir).unwrap();
    let journal_path = journal_dir.join(format!("{project_id}.rotation.json"));
    std::fs::write(
        &journal_path,
        serde_json::to_string_pretty(&journal).unwrap(),
    )
    .unwrap();

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.args(["doctor", "--fix"]);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("requires an interactive terminal"));
}

#[test]
fn test_search_finds_keys() {
    let dir = TempDir::new().unwrap();
    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.arg("init");
    cmd.assert().success();

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.args(["set", "api", "DB_HOST", "localhost"]);
    cmd.assert().success();

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.args(["search", "DB"]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("DB_HOST"));
}

#[test]
fn test_search_no_matches() {
    let dir = TempDir::new().unwrap();
    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.arg("init");
    cmd.assert().success();

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.args(["search", "NONEXISTENT"]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("no matches found"));
}

#[test]
fn test_search_values_blocks_non_interactive() {
    let dir = TempDir::new().unwrap();
    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.arg("init");
    cmd.assert().success();

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.args(["search", "--values", "localhost"]);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("requires an interactive terminal"));
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
fn test_import_conflict_without_force_does_not_overwrite_non_interactive() {
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

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.args(["import", "api", "--file", "second.env"]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("aborted."));

    assert_run_env(dir.path(), &["api"], "API_KEY", "old_value");

    let mut cmd = kagi_bin();
    cmd.current_dir(dir.path());
    cmd.args(["run", "api", "sh", "-c", "test -z \"${EXTRA_KEY+x}\""]);
    cmd.assert().success();
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
        "expected api/development layout: {stdout}"
    );
    assert!(
        stdout.contains("  production"),
        "expected api/production layout: {stdout}"
    );
    assert!(stdout.contains("KEY"), "expected key: {stdout}");
    assert!(
        !stdout.contains("production-value"),
        "get should mask values by default: {stdout}"
    );
}

#[test]
fn test_env_list_shows_configured_envs() {
    let dir = TempDir::new().unwrap();

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.args(["init", "--envs", "development,staging,production"]);
    cmd.assert().success();

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.args(["env", "list"]);
    let assert = cmd.assert().success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(
        stdout.contains("development"),
        "expected development: {stdout}"
    );
    assert!(stdout.contains("staging"), "expected staging: {stdout}");
    assert!(
        stdout.contains("production"),
        "expected production: {stdout}"
    );
}

#[test]
fn test_env_remove_requires_interactive_confirmation() {
    let dir = TempDir::new().unwrap();

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.args(["init", "--envs", "development,staging"]);
    cmd.assert().success();

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.args(["env", "remove", "staging"]);
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

#[test]
fn test_set_with_description_stores_it() {
    let dir = TempDir::new().unwrap();

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.arg("init");
    cmd.assert().success();

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.args([
        "set",
        "api",
        "DB_URL",
        "postgres://localhost",
        "--desc",
        "Database connection string",
    ]);
    cmd.assert().success();

    // Verify the value is stored correctly by running it
    assert_run_env(dir.path(), &["api"], "DB_URL", "postgres://localhost");
}

#[test]
fn test_import_captures_description_from_comment() {
    let dir = TempDir::new().unwrap();

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.arg("init");
    cmd.assert().success();

    std::fs::write(
        dir.path().join("api.env"),
        "# API key for staging\nAPI_KEY=secret\n# Database URL\nDB_URL=postgres://localhost\n",
    )
    .unwrap();

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.args(["import", "api", "--file", "api.env"]);
    cmd.assert().success();

    // Verify the values were imported by running them
    assert_run_env(dir.path(), &["api"], "API_KEY", "secret");
    assert_run_env(dir.path(), &["api"], "DB_URL", "postgres://localhost");
}

#[test]
#[cfg(feature = "server")]
fn test_server_member_join_approve_flow() {
    let (_server, admin_token, port) = spawn_server();
    let server_url = format!("http://127.0.0.1:{port}");

    let project_dir = TempDir::new().unwrap();
    let kagi_home = TempDir::new().unwrap();

    let mut cmd = kagi_bin_with_home(kagi_home.path());
    cmd.current_dir(&project_dir);
    cmd.arg("init");
    cmd.assert().success();

    let mut cmd = kagi_bin_with_home(kagi_home.path());
    cmd.current_dir(&project_dir);
    cmd.args(["remote", "register", "--remote", &server_url]);
    cmd.assert().success();

    let kagi_json_path = project_dir.path().join(".kagi/kagi.json");
    let config: Value =
        serde_json::from_str(&std::fs::read_to_string(&kagi_json_path).unwrap()).unwrap();
    let project_id = config["project_id"].as_str().unwrap().to_string();

    let mut cmd = kagi_bin_with_home(kagi_home.path());
    cmd.current_dir(&project_dir);
    cmd.env("KAGI_ADMIN_TOKEN", &admin_token);
    cmd.args(["remote", "approve", "--remote", &server_url, &project_id]);
    cmd.assert().success();

    let mut cmd = kagi_bin_with_home(kagi_home.path());
    cmd.current_dir(&project_dir);
    cmd.args(["remote", "pull"]);
    cmd.assert().success();

    let mut cmd = kagi_bin_with_home(kagi_home.path());
    cmd.current_dir(&project_dir);
    cmd.args(["member", "request", "--name", "alice"]);
    cmd.assert().success();

    let mut cmd = kagi_bin_with_home(kagi_home.path());
    cmd.current_dir(&project_dir);
    cmd.args(["member", "list"]);
    let assert = cmd.assert().success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(stdout.contains("alice"));
    assert!(stdout.contains("pending"));

    let access_path = project_dir.path().join(".kagi/access.json");
    let access: Value =
        serde_json::from_str(&std::fs::read_to_string(&access_path).unwrap()).unwrap();
    let pending = access["members"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["status"] == "pending")
        .unwrap();
    let member_id = pending["member_id"].as_str().unwrap().to_string();

    let mut cmd = kagi_bin_with_home(kagi_home.path());
    cmd.current_dir(&project_dir);
    cmd.args(["member", "approve", &member_id]);
    cmd.assert().success();

    let mut cmd = kagi_bin_with_home(kagi_home.path());
    cmd.current_dir(&project_dir);
    cmd.args(["remote", "push"]);
    cmd.assert().success();

    let mut cmd = kagi_bin_with_home(kagi_home.path());
    cmd.current_dir(&project_dir);
    cmd.args(["member", "list"]);
    let assert = cmd.assert().success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(stdout.contains("alice"));
    assert!(stdout.contains("active"));

    let access: Value =
        serde_json::from_str(&std::fs::read_to_string(&access_path).unwrap()).unwrap();
    let member = access["members"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["member_id"] == member_id)
        .unwrap();
    assert_eq!(member["status"], "active");
    assert!(
        member["wrapped_key"].as_str().unwrap().len() > 20,
        "expected wrapped_key to be present"
    );
}

#[test]
#[cfg(feature = "server")]
fn test_server_push_pull_status() {
    let (_server, admin_token, port) = spawn_server();
    let server_url = format!("http://127.0.0.1:{port}");

    let project_dir = TempDir::new().unwrap();
    let kagi_home = TempDir::new().unwrap();

    let mut cmd = kagi_bin_with_home(kagi_home.path());
    cmd.current_dir(&project_dir);
    cmd.arg("init");
    cmd.assert().success();

    let mut cmd = kagi_bin_with_home(kagi_home.path());
    cmd.current_dir(&project_dir);
    cmd.args(["remote", "register", "--remote", &server_url]);
    cmd.assert().success();

    let config: Value = serde_json::from_str(
        &std::fs::read_to_string(project_dir.path().join(".kagi/kagi.json")).unwrap(),
    )
    .unwrap();
    let project_id = config["project_id"].as_str().unwrap().to_string();

    let mut cmd = kagi_bin_with_home(kagi_home.path());
    cmd.current_dir(&project_dir);
    cmd.env("KAGI_ADMIN_TOKEN", &admin_token);
    cmd.args(["remote", "approve", "--remote", &server_url, &project_id]);
    cmd.assert().success();

    let mut cmd = kagi_bin_with_home(kagi_home.path());
    cmd.current_dir(&project_dir);
    cmd.args(["remote", "pull"]);
    cmd.assert().success();

    let mut cmd = kagi_bin_with_home(kagi_home.path());
    cmd.current_dir(&project_dir);
    cmd.args(["set", "api", "KEY", "val"]);
    cmd.assert().success();

    let mut cmd = kagi_bin_with_home(kagi_home.path());
    cmd.current_dir(&project_dir);
    cmd.args(["remote", "push"]);
    let assert = cmd.assert().success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(stdout.contains("kagi: pushed revision"));

    let mut cmd = kagi_bin_with_home(kagi_home.path());
    cmd.current_dir(&project_dir);
    cmd.args(["remote", "pull"]);
    let assert = cmd.assert().success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(stdout.contains("kagi: pulled revision"));

    let mut cmd = kagi_bin_with_home(kagi_home.path());
    cmd.current_dir(&project_dir);
    cmd.args(["remote", "status"]);
    let assert = cmd.assert().success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(
        stdout.contains("equal"),
        "expected status to show equal: {stdout}"
    );

    let mut cmd = kagi_bin_with_home(kagi_home.path());
    cmd.current_dir(&project_dir);
    cmd.args(["set", "api", "KEY", "val2"]);
    cmd.assert().success();

    let mut cmd = kagi_bin_with_home(kagi_home.path());
    cmd.current_dir(&project_dir);
    cmd.args(["remote", "push"]);
    cmd.assert().success();

    let mut cmd = kagi_bin_with_home(kagi_home.path());
    cmd.current_dir(&project_dir);
    cmd.args(["remote", "status"]);
    let assert = cmd.assert().success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(
        stdout.contains("equal"),
        "expected status to show equal after re-push: {stdout}"
    );
}

#[cfg(feature = "server")]
fn copy_dir_all(src: &Path, dst: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        if ty.is_dir() {
            copy_dir_all(&entry.path(), &dst.join(entry.file_name()))?;
        } else {
            std::fs::copy(entry.path(), dst.join(entry.file_name()))?;
        }
    }
    Ok(())
}

#[test]
#[cfg(feature = "server")]
fn test_server_cross_checkout_join_request_visible() {
    let (_server, admin_token, port) = spawn_server();
    let server_url = format!("http://127.0.0.1:{port}");

    let owner_dir = TempDir::new().unwrap();
    let owner_home = TempDir::new().unwrap();
    let joiner_dir = TempDir::new().unwrap();
    let joiner_home = TempDir::new().unwrap();

    let mut cmd = kagi_bin_with_home(owner_home.path());
    cmd.current_dir(&owner_dir);
    cmd.arg("init");
    cmd.assert().success();

    let mut cmd = kagi_bin_with_home(owner_home.path());
    cmd.current_dir(&owner_dir);
    cmd.args(["remote", "register", "--remote", &server_url]);
    cmd.assert().success();

    let kagi_json_path = owner_dir.path().join(".kagi/kagi.json");
    let config: Value =
        serde_json::from_str(&std::fs::read_to_string(&kagi_json_path).unwrap()).unwrap();
    let project_id = config["project_id"].as_str().unwrap().to_string();

    let mut cmd = kagi_bin_with_home(owner_home.path());
    cmd.current_dir(&owner_dir);
    cmd.env("KAGI_ADMIN_TOKEN", &admin_token);
    cmd.args(["remote", "approve", "--remote", &server_url, &project_id]);
    cmd.assert().success();

    let mut cmd = kagi_bin_with_home(owner_home.path());
    cmd.current_dir(&owner_dir);
    cmd.args(["remote", "pull"]);
    cmd.assert().success();

    let mut cmd = kagi_bin_with_home(owner_home.path());
    cmd.current_dir(&owner_dir);
    cmd.args(["remote", "push"]);
    cmd.assert().success();

    copy_dir_all(
        &owner_dir.path().join(".kagi"),
        &joiner_dir.path().join(".kagi"),
    )
    .unwrap();
    copy_dir_all(
        &owner_home.path().join(format!("projects/{project_id}")),
        &joiner_home.path().join(format!("projects/{project_id}")),
    )
    .unwrap();

    let mut cmd = kagi_bin_with_home(joiner_home.path());
    cmd.current_dir(&joiner_dir);
    cmd.args(["member", "request", "--name", "alice"]);
    cmd.assert().success();

    let joiner_access_path = joiner_dir.path().join(".kagi/access.json");
    let access: Value =
        serde_json::from_str(&std::fs::read_to_string(&joiner_access_path).unwrap()).unwrap();
    let pending = access["members"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["status"] == "pending")
        .unwrap();
    let member_id = pending["member_id"].as_str().unwrap().to_string();

    let owner_access_path = owner_dir.path().join(".kagi/access.json");
    let owner_access: Value =
        serde_json::from_str(&std::fs::read_to_string(&owner_access_path).unwrap()).unwrap();
    assert!(
        owner_access["members"]
            .as_array()
            .unwrap()
            .iter()
            .all(|m| m["member_id"] != member_id),
        "owner checkout should not have the joiner's pending member locally before listing"
    );

    let mut cmd = kagi_bin_with_home(owner_home.path());
    cmd.current_dir(&owner_dir);
    cmd.args(["member", "list"]);
    let assert = cmd.assert().success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(
        stdout.contains("alice"),
        "expected alice in member list: {stdout}"
    );
    assert!(
        stdout.contains("pending"),
        "expected pending status: {stdout}"
    );

    let owner_access_after_list: Value =
        serde_json::from_str(&std::fs::read_to_string(&owner_access_path).unwrap()).unwrap();
    assert!(
        owner_access_after_list["members"]
            .as_array()
            .unwrap()
            .iter()
            .all(|m| m["member_id"] != member_id),
        "member list should not persist the server member request locally: {owner_access_after_list}"
    );

    let mut cmd = kagi_bin_with_home(owner_home.path());
    cmd.current_dir(&owner_dir);
    cmd.args(["member", "approve", &member_id]);
    let assert = cmd.assert().success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(
        stdout.contains("Token will be activated"),
        "expected server-mode approval output: {stdout}"
    );

    let access_after_approve: Value =
        serde_json::from_str(&std::fs::read_to_string(&owner_access_path).unwrap()).unwrap();
    let member_after_approve = access_after_approve["members"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["member_id"] == member_id)
        .unwrap();
    let approved_signing_public_key = member_after_approve["signing_public_key"].as_str();
    assert!(
        approved_signing_public_key.is_some_and(|key| key.len() > 20),
        "expected signing_public_key immediately after approve, got member: {member_after_approve}, access: {access_after_approve}"
    );

    let mut cmd = kagi_bin_with_home(owner_home.path());
    cmd.current_dir(&owner_dir);
    cmd.args(["remote", "push"]);
    cmd.assert().success();

    let mut cmd = kagi_bin_with_home(owner_home.path());
    cmd.current_dir(&owner_dir);
    cmd.args(["member", "list"]);
    let assert = cmd.assert().success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(
        stdout.contains("alice"),
        "expected alice after push: {stdout}"
    );
    assert!(
        stdout.contains("active"),
        "expected active status after push: {stdout}"
    );

    let access: Value =
        serde_json::from_str(&std::fs::read_to_string(&owner_access_path).unwrap()).unwrap();
    let member = access["members"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["member_id"] == member_id)
        .unwrap();
    assert_eq!(member["status"], "active");
    assert!(
        member["wrapped_key"].as_str().unwrap().len() > 20,
        "expected wrapped_key to be present"
    );
    assert!(
        member["wrapped_token"].as_str().unwrap().len() > 20,
        "expected wrapped_token to be present"
    );
    let signing_public_key = member["signing_public_key"].as_str();
    assert!(
        signing_public_key.is_some_and(|key| key.len() > 20),
        "expected signing_public_key to be present, got member: {member}"
    );

    let mut cmd = kagi_bin_with_home(joiner_home.path());
    cmd.current_dir(&joiner_dir);
    cmd.args(["remote", "pull"]);
    cmd.assert().success();

    let mut cmd = kagi_bin_with_home(joiner_home.path());
    cmd.current_dir(&joiner_dir);
    cmd.args(["set", "api", "ALICE_KEY", "alice"]);
    cmd.assert().success();

    let mut cmd = kagi_bin_with_home(joiner_home.path());
    cmd.current_dir(&joiner_dir);
    cmd.args(["remote", "push"]);
    cmd.assert().success();
}

#[test]
#[cfg(feature = "server")]
fn test_server_pull_blocks_with_pending_approval() {
    let (_server, admin_token, port) = spawn_server();
    let server_url = format!("http://127.0.0.1:{port}");

    let project_dir = TempDir::new().unwrap();
    let kagi_home = TempDir::new().unwrap();

    let mut cmd = kagi_bin_with_home(kagi_home.path());
    cmd.current_dir(&project_dir);
    cmd.arg("init");
    cmd.assert().success();

    let mut cmd = kagi_bin_with_home(kagi_home.path());
    cmd.current_dir(&project_dir);
    cmd.args(["remote", "register", "--remote", &server_url]);
    cmd.assert().success();

    let kagi_json_path = project_dir.path().join(".kagi/kagi.json");
    let config: Value =
        serde_json::from_str(&std::fs::read_to_string(&kagi_json_path).unwrap()).unwrap();
    let project_id = config["project_id"].as_str().unwrap().to_string();

    let mut cmd = kagi_bin_with_home(kagi_home.path());
    cmd.current_dir(&project_dir);
    cmd.env("KAGI_ADMIN_TOKEN", &admin_token);
    cmd.args(["remote", "approve", "--remote", &server_url, &project_id]);
    cmd.assert().success();

    let mut cmd = kagi_bin_with_home(kagi_home.path());
    cmd.current_dir(&project_dir);
    cmd.args(["remote", "pull"]);
    cmd.assert().success();

    let mut cmd = kagi_bin_with_home(kagi_home.path());
    cmd.current_dir(&project_dir);
    cmd.args(["member", "request", "--name", "bob"]);
    cmd.assert().success();

    let access_path = project_dir.path().join(".kagi/access.json");
    let access: Value =
        serde_json::from_str(&std::fs::read_to_string(&access_path).unwrap()).unwrap();
    let pending = access["members"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["status"] == "pending")
        .unwrap();
    let member_id = pending["member_id"].as_str().unwrap().to_string();

    let mut cmd = kagi_bin_with_home(kagi_home.path());
    cmd.current_dir(&project_dir);
    cmd.args(["member", "approve", &member_id]);
    cmd.assert().success();

    // Create a second checkout and push to make the server ahead
    let project_dir2 = TempDir::new().unwrap();
    let kagi_home2 = TempDir::new().unwrap();
    copy_dir_all(project_dir.path(), project_dir2.path()).unwrap();
    copy_dir_all(kagi_home.path(), kagi_home2.path()).unwrap();

    let mut cmd = kagi_bin_with_home(kagi_home2.path());
    cmd.current_dir(&project_dir2);
    cmd.args(["set", "api", "KEY", "val"]);
    cmd.assert().success();

    let mut cmd = kagi_bin_with_home(kagi_home2.path());
    cmd.current_dir(&project_dir2);
    cmd.args(["remote", "push"]);
    cmd.assert().success();

    // In the original, pull should fail because remote is ahead and local has pending approval
    let mut cmd = kagi_bin_with_home(kagi_home.path());
    cmd.current_dir(&project_dir);
    cmd.args(["remote", "pull"]);
    let assert = cmd.assert().failure();
    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
    assert!(
        stderr.contains("Cannot pull while member approval metadata is pending"),
        "expected pull guard error, got: {stderr}"
    );

    // Verify the pending approval metadata is still present after the failed pull
    let local_data_dir = kagi_home.path().join("projects");
    let project_dir_entry = std::fs::read_dir(&local_data_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .find(|e| e.file_type().unwrap().is_dir())
        .unwrap();
    let meta_path = project_dir_entry.path().join("remote.json");
    let meta: Value = serde_json::from_str(&std::fs::read_to_string(&meta_path).unwrap()).unwrap();
    let has_pending = meta["pending_accepted_member_ids"]
        .as_array()
        .map(|arr| !arr.is_empty())
        .unwrap_or(false);
    assert!(
        has_pending,
        "expected pending approval metadata to survive the failed pull"
    );
}

#[test]
fn test_completions_generates_shell_script() {
    let mut cmd = kagi_bin();
    cmd.args(["completions", "bash"]);
    cmd.assert()
        .success()
        .stdout(predicates::str::contains("_kagi"));
}

#[test]
fn test_completions_rejects_unknown_shell() {
    let mut cmd = kagi_bin();
    cmd.args(["completions", "unknown_shell"]);
    cmd.assert()
        .failure()
        .stderr(predicates::str::contains("unsupported shell"));
}

#[test]
fn test_init_detects_env_files_in_non_interactive() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join(".env"), "ROOT_KEY=root\n").unwrap();
    fs::create_dir(dir.path().join("api")).unwrap();
    fs::write(dir.path().join("api/.env"), "API_KEY=api\n").unwrap();

    let mut cmd = kagi_bin();
    cmd.current_dir(dir.path());
    cmd.args(["init", "--envs", "development,test"]);
    let assert = cmd.assert().success();
    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
    assert!(
        stderr.contains("found 2 .env file(s)"),
        "expected note about found .env files in non-interactive mode, got: {stderr}"
    );
}

#[test]
fn test_init_no_migrate_skips_env_files() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join(".env"), "ROOT_KEY=root\n").unwrap();

    let mut cmd = kagi_bin();
    cmd.current_dir(dir.path());
    cmd.args(["init", "--no-migrate"]);
    let assert = cmd.assert().success();
    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
    assert!(
        !stderr.contains(".env file(s)"),
        "expected no migration note with --no-migrate"
    );
}

#[test]
fn test_env_list_plain_outputs_text() {
    let dir = TempDir::new().unwrap();

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.args(["init", "--envs", "development,staging"]);
    cmd.assert().success();

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.args(["env", "list", "--plain"]);
    let assert = cmd.assert().success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(
        stdout.contains("development"),
        "expected development: {stdout}"
    );
    assert!(stdout.contains("staging"), "expected staging: {stdout}");
}

#[test]
fn test_search_plain_outputs_text() {
    let dir = TempDir::new().unwrap();

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.arg("init");
    cmd.assert().success();

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.args(["set", "api", "HOST", "localhost"]);
    cmd.assert().success();

    let mut cmd = kagi_bin();
    cmd.current_dir(&dir);
    cmd.args(["search", "--plain", "HOST"]);
    let assert = cmd.assert().success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(
        stdout.contains("api/development.HOST"),
        "expected match: {stdout}"
    );
}
