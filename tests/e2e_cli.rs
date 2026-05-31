use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
#[cfg(unix)]
use std::path::Path;
use tempfile::TempDir;

fn kagi_bin(kagi_home: &str) -> Command {
    let mut cmd = Command::cargo_bin("kagi").unwrap();
    cmd.env("KAGI_DISABLE_KEYRING", "1");
    cmd.env("KAGI_HOME", kagi_home);
    cmd
}

fn setup_kagi_home() -> TempDir {
    TempDir::new().unwrap()
}

#[cfg(unix)]
fn run_kagi_interactive(
    kagi_home: &str,
    current_dir: &Path,
    args: &[&str],
    inputs: &[&str],
) -> (std::process::ExitStatus, String) {
    let bin_path = std::env::var("CARGO_BIN_EXE_kagi")
        .unwrap_or_else(|_| assert_cmd::cargo_bin!("kagi").to_string_lossy().to_string());

    const PTY_RUNNER: &str = r#"
import os
import pty
import select
import subprocess
import sys

master, slave = pty.openpty()
child = subprocess.Popen(sys.argv[1:], stdin=slave, stdout=slave, stderr=subprocess.STDOUT, close_fds=True)
os.close(slave)

inputs = os.environ.get("KAGI_E2E_INPUTS", "")
for line in inputs.split("\n"):
    if line:
        os.write(master, line.encode())
        os.write(master, b"\n")

while True:
    ready, _, _ = select.select([master], [], [], 0.05)
    if ready:
        try:
            data = os.read(master, 4096)
        except OSError:
            break
        if not data:
            break
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()
    if child.poll() is not None:
        while True:
            ready, _, _ = select.select([master], [], [], 0)
            if not ready:
                break
            try:
                data = os.read(master, 4096)
            except OSError:
                break
            if not data:
                break
            sys.stdout.buffer.write(data)
            sys.stdout.buffer.flush()
        break

os.close(master)
sys.exit(child.wait())
"#;

    let mut cmd = std::process::Command::new("python3");
    cmd.arg("-c").arg(PTY_RUNNER).arg(&bin_path).args(args);
    cmd.env("KAGI_DISABLE_KEYRING", "1")
        .env("KAGI_HOME", kagi_home)
        .env("KAGI_E2E_INPUTS", inputs.join("\n"))
        .current_dir(current_dir)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    let output = cmd.output().expect("failed to run pty helper");
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    (output.status, text)
}

#[test]
fn test_e2e_init_set_get_doctor_backup_restore() {
    let home = setup_kagi_home();
    let home_path = home.path().to_str().unwrap().to_string();
    let project_dir = TempDir::new().unwrap();
    let project_path = project_dir.path();

    // 1. init
    let mut cmd = kagi_bin(&home_path);
    cmd.current_dir(project_path);
    cmd.args(["init", "--envs", "dev,staging,prod"]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Initialized .kagi/"));

    let kagi_dir = project_path.join(".kagi");
    assert!(kagi_dir.exists());
    assert!(kagi_dir.join("kagi.json").exists());
    assert!(kagi_dir.join("access.json").exists());
    assert!(kagi_dir.join("secrets").exists());

    // 2. set secrets
    let mut cmd = kagi_bin(&home_path);
    cmd.current_dir(project_path);
    cmd.args(["set", "api", "dev", "URL", "http://localhost:3000"]);
    cmd.assert().success();

    let mut cmd = kagi_bin(&home_path);
    cmd.current_dir(project_path);
    cmd.args([
        "set",
        "api",
        "staging",
        "URL",
        "https://staging.example.com",
    ]);
    cmd.assert().success();

    let mut cmd = kagi_bin(&home_path);
    cmd.current_dir(project_path);
    cmd.args(["set", "db", "prod", "HOST", "db.production.local"]);
    cmd.assert().success();

    // 3. get (masked)
    let mut cmd = kagi_bin(&home_path);
    cmd.current_dir(project_path);
    cmd.args(["get", "api"]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("api"))
        .stdout(predicate::str::contains("dev"))
        .stdout(predicate::str::contains("staging"))
        .stdout(predicate::str::contains("URL"))
        .stdout(predicate::str::contains("********"));

    // 4. get with scope
    let mut cmd = kagi_bin(&home_path);
    cmd.current_dir(project_path);
    cmd.args(["get", "api", "dev"]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("URL"))
        .stdout(predicate::str::contains("********"));

    // 5. search
    let mut cmd = kagi_bin(&home_path);
    cmd.current_dir(project_path);
    cmd.args(["search", "URL"]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("api/dev.URL"))
        .stdout(predicate::str::contains("api/staging.URL"))
        .stdout(predicate::str::contains("********"));

    // 6. doctor
    let mut cmd = kagi_bin(&home_path);
    cmd.current_dir(project_path);
    cmd.args(["doctor"]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Kagi Doctor"))
        .stdout(predicate::str::contains("all checks passed"));

    // 7. backup
    let backup_dir = project_path.join("test-backup");
    let mut cmd = kagi_bin(&home_path);
    cmd.current_dir(project_path);
    cmd.args(["backup", "--out", backup_dir.to_str().unwrap()]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("backup created"));

    assert!(backup_dir.join("kagi").exists());
    assert!(backup_dir.join("manifest.json").exists());
    assert!(backup_dir.join("checksums.json").exists());

    let manifest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(backup_dir.join("manifest.json")).unwrap())
            .unwrap();
    assert_eq!(manifest["version"].as_u64(), Some(1));
    let home_files = manifest["home_files"].as_array().unwrap();
    // Only identities should be backed up (not other projects' data)
    assert!(home_files.iter().all(|v| {
        let s = v.as_str().unwrap();
        s == "identities" || s == "admins" || s.starts_with("projects/")
    }));

    // 8. restore to new directory
    let restore_dir = TempDir::new().unwrap();
    let mut cmd = kagi_bin(&home_path);
    cmd.current_dir(restore_dir.path());
    cmd.args(["restore", "--from", backup_dir.to_str().unwrap(), "--force"]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("restored from backup"));

    assert!(restore_dir.path().join(".kagi").exists());

    // 9. doctor on restored project
    let mut cmd = kagi_bin(&home_path);
    cmd.current_dir(restore_dir.path());
    cmd.args(["doctor"]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("all checks passed"));

    // 10. get on restored project
    let mut cmd = kagi_bin(&home_path);
    cmd.current_dir(restore_dir.path());
    cmd.args(["get", "api", "dev"]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("URL"))
        .stdout(predicate::str::contains("********"));

    // 11. env list
    let mut cmd = kagi_bin(&home_path);
    cmd.current_dir(project_path);
    cmd.args(["env", "list"]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("development"))
        .stdout(predicate::str::contains("dev"))
        .stdout(predicate::str::contains("staging"))
        .stdout(predicate::str::contains("prod"));

    // 12. member list
    let mut cmd = kagi_bin(&home_path);
    cmd.current_dir(project_path);
    cmd.args(["member", "list"]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Members"))
        .stdout(predicate::str::contains("active"));

    // 13. unset blocks non-interactive
    let mut cmd = kagi_bin(&home_path);
    cmd.current_dir(project_path);
    cmd.args(["unset", "api", "dev", "URL"]);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("requires an interactive terminal"));

    // 14. export blocks non-interactive
    let mut cmd = kagi_bin(&home_path);
    cmd.current_dir(project_path);
    cmd.args(["export", "api", "dev", "--out", "/tmp/test.env"]);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("requires an interactive terminal"));

    // 15. backup destination inside source tree is rejected
    let mut cmd = kagi_bin(&home_path);
    cmd.current_dir(project_path);
    cmd.args([
        "backup",
        "--out",
        kagi_dir.join("bad-backup").to_str().unwrap(),
    ]);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("inside the source tree"));

    // 16. restore with path traversal in manifest is rejected
    let manifest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(backup_dir.join("manifest.json")).unwrap())
            .unwrap();
    let mut bad_manifest = manifest.clone();
    bad_manifest["home_files"] = serde_json::json!(["../etc/passwd"]);
    let bad_manifest_str = serde_json::to_string_pretty(&bad_manifest).unwrap();
    fs::write(backup_dir.join("manifest.json"), &bad_manifest_str).unwrap();

    // Update checksums to match modified manifest
    use sha2::Digest;
    let mut checksums: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(backup_dir.join("checksums.json")).unwrap())
            .unwrap();
    let new_hash = hex::encode(sha2::Sha256::digest(bad_manifest_str.as_bytes()));
    if let Some(obj) = checksums.as_object_mut() {
        obj.insert("manifest.json".to_string(), serde_json::json!(new_hash));
    }
    fs::write(
        backup_dir.join("checksums.json"),
        serde_json::to_string_pretty(&checksums).unwrap(),
    )
    .unwrap();

    let restore_dir2 = TempDir::new().unwrap();
    let mut cmd = kagi_bin(&home_path);
    cmd.current_dir(restore_dir2.path());
    cmd.args(["restore", "--from", backup_dir.to_str().unwrap(), "--force"]);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("invalid path in backup manifest"));
}

#[cfg(feature = "server")]
#[test]
fn test_e2e_server_full_remote_workflow() {
    use std::io::{Read, Write};

    let home = setup_kagi_home();
    let home_path = home.path().to_str().unwrap().to_string();
    let project_dir = TempDir::new().unwrap();
    let project_path = project_dir.path();

    // init project with remote
    let mut cmd = kagi_bin(&home_path);
    cmd.current_dir(project_path);
    cmd.args(["init", "--envs", "dev"]);
    cmd.assert().success();

    // set a secret
    let mut cmd = kagi_bin(&home_path);
    cmd.current_dir(project_path);
    cmd.args(["set", "api", "dev", "KEY", "value123"]);
    cmd.assert().success();

    // read project_id from kagi.json
    let kagi_json: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(project_path.join(".kagi/kagi.json")).unwrap())
            .unwrap();
    let project_id = kagi_json["project_id"].as_str().unwrap().to_string();

    // spawn server
    let server_dir = TempDir::new().unwrap();
    let db_path = server_dir.path().join("server.db");
    let key_path = server_dir.path().join("server.key");

    let mut serve_cmd = std::process::Command::new(assert_cmd::cargo_bin!("kagi"));
    serve_cmd.env("KAGI_DISABLE_KEYRING", "1");
    serve_cmd.env("KAGI_HOME", server_dir.path().join("kagi-home"));
    serve_cmd.args([
        "serve",
        "--bind",
        "127.0.0.1:0",
        "--db",
        db_path.to_str().unwrap(),
        "--key-file",
        key_path.to_str().unwrap(),
    ]);
    serve_cmd.stdout(std::process::Stdio::piped());
    serve_cmd.stderr(std::process::Stdio::piped());

    let mut child = serve_cmd.spawn().expect("failed to spawn kagi serve");

    // drain stderr
    let stderr = child.stderr.take().unwrap();
    std::thread::spawn(move || {
        let mut reader = std::io::BufReader::new(stderr);
        for _ in std::io::BufRead::lines(&mut reader) {}
    });

    let stdout = child.stdout.take().unwrap();
    let reader = std::io::BufReader::new(stdout);
    let (line_tx, line_rx) = std::sync::mpsc::channel();

    std::thread::spawn(move || {
        for line in std::io::BufRead::lines(reader).map_while(Result::ok) {
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
            panic!("server startup timed out");
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
                if let Some(p) = line.rfind(":")
                    && (line.contains("listening on http://")
                        || line.contains("running on http://"))
                {
                    let port_str = &line[p + 1..];
                    port = port_str.parse().ok();
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
            Err(_) => {
                let _ = child.kill();
                panic!("server stdout closed unexpectedly");
            }
        }
    }

    let port = port.unwrap();
    let base_url = format!("http://127.0.0.1:{port}");

    // wait for HTTP readiness
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
    assert!(ready, "server did not become HTTP-ready");

    // 1. remote login with admin token
    let mut cmd = kagi_bin(&home_path);
    cmd.current_dir(project_path);
    cmd.args(["remote", "login", "--remote", &base_url, "--token", &token]);
    cmd.assert().success();

    // 2. project join (register project on server)
    let mut cmd = kagi_bin(&home_path);
    cmd.current_dir(project_path);
    cmd.args(["project", "join", "--remote", &base_url]);
    cmd.assert().success();

    // 3. project approve (admin approves the project)
    let mut cmd = kagi_bin(&home_path);
    cmd.current_dir(project_path);
    cmd.args(["project", "approve", "--remote", &base_url, &project_id]);
    cmd.assert().success();

    // 4. pull to exchange claim_secret for project token
    let mut cmd = kagi_bin(&home_path);
    cmd.current_dir(project_path);
    cmd.args(["pull"]);
    cmd.assert().success();

    // 5. push project state to server
    let mut cmd = kagi_bin(&home_path);
    cmd.current_dir(project_path);
    cmd.args(["push"]);
    cmd.assert().success();

    // 6. pull project state from server
    let mut cmd = kagi_bin(&home_path);
    cmd.current_dir(project_path);
    cmd.args(["pull"]);
    cmd.assert().success();

    // 7. status compare
    let mut cmd = kagi_bin(&home_path);
    cmd.current_dir(project_path);
    cmd.args(["status"]);
    cmd.assert().success();

    // 8. token list (should show project tokens)
    let mut cmd = kagi_bin(&home_path);
    cmd.current_dir(project_path);
    cmd.args(["token", "list"]);
    cmd.assert().success();

    // 9. remote audit (should show push/pull events)
    let mut cmd = kagi_bin(&home_path);
    cmd.current_dir(project_path);
    cmd.args(["remote", "audit", "--limit", "10"]);
    cmd.assert().success();

    // 10. /v1/metrics with admin token returns data
    let body = http_get_json(&format!("{base_url}/v1/metrics"), Some(&token));
    assert!(body["active_admins"].is_number());
    assert!(body["active_projects"].is_number());
    assert!(body["active_tokens"].is_number());
    assert!(body["db_size"].is_number());

    // 11. /v1/metrics without token returns 401
    let body = http_get_json(&format!("{base_url}/v1/metrics"), None);
    assert!(!body["ok"].as_bool().unwrap_or(true));
    assert_eq!(body["error"]["code"].as_str(), Some("auth_failed"));

    // cleanup
    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn test_e2e_local_advanced() {
    let home = setup_kagi_home();
    let home_path = home.path().to_str().unwrap().to_string();
    let project_dir = TempDir::new().unwrap();
    let project_path = project_dir.path();

    // 1. init
    let mut cmd = kagi_bin(&home_path);
    cmd.current_dir(project_path);
    cmd.args(["init", "--envs", "dev,test"]);
    cmd.assert().success();

    // 2. set some secrets
    let mut cmd = kagi_bin(&home_path);
    cmd.current_dir(project_path);
    cmd.args(["set", "api", "dev", "HOST", "localhost"]);
    cmd.assert().success();

    let mut cmd = kagi_bin(&home_path);
    cmd.current_dir(project_path);
    cmd.args(["set", "api", "dev", "PORT", "3000"]);
    cmd.assert().success();

    // 3. import from .env file
    let env_file = project_path.join(".env");
    fs::write(&env_file, "DEBUG=true\nSECRET=imported123\n").unwrap();
    let mut cmd = kagi_bin(&home_path);
    cmd.current_dir(project_path);
    cmd.args(["import", "api", "dev", "--file", env_file.to_str().unwrap()]);
    cmd.assert().success();

    // 4. import --force overwrites existing
    let mut cmd = kagi_bin(&home_path);
    cmd.current_dir(project_path);
    cmd.args([
        "import",
        "api",
        "dev",
        "--file",
        env_file.to_str().unwrap(),
        "--force",
    ]);
    cmd.assert().success();

    // 5. sync from .env.example
    let example_file = project_path.join(".env.example");
    fs::write(&example_file, "API_KEY=\n# some comment\nNEW_VAR=\n").unwrap();
    let mut cmd = kagi_bin(&home_path);
    cmd.current_dir(project_path);
    cmd.args([
        "sync",
        "--service",
        "api",
        "--example",
        example_file.to_str().unwrap(),
        "--envs",
        "dev,test",
    ]);
    cmd.assert().success();

    // 6. env add
    let mut cmd = kagi_bin(&home_path);
    cmd.current_dir(project_path);
    cmd.args(["env", "add", "staging"]);
    cmd.assert().success();

    // 7. env rename
    let mut cmd = kagi_bin(&home_path);
    cmd.current_dir(project_path);
    cmd.args(["env", "rename", "test", "testing"]);
    cmd.assert().success();

    // 8. env del blocks non-interactive
    let mut cmd = kagi_bin(&home_path);
    cmd.current_dir(project_path);
    cmd.args(["env", "del", "testing"]);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("requires an interactive terminal"));

    // 9. member join (creates a pending request)
    let mut cmd = kagi_bin(&home_path);
    cmd.current_dir(project_path);
    cmd.args(["member", "join", "--name", "Alice"]);
    cmd.assert().success();

    // 10. member list shows pending request
    let mut cmd = kagi_bin(&home_path);
    cmd.current_dir(project_path);
    cmd.args(["member", "list"]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("pending"));

    // Read the member_id from access.json
    let access_json: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(project_path.join(".kagi/access.json")).unwrap())
            .unwrap();
    let pending_member = access_json["members"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["status"] == "pending")
        .unwrap();
    let pending_member_id = pending_member["member_id"].as_str().unwrap().to_string();

    // 11. member approve
    let mut cmd = kagi_bin(&home_path);
    cmd.current_dir(project_path);
    cmd.args(["member", "approve", &pending_member_id]);
    cmd.assert().success();

    // 12. member list shows active member
    let mut cmd = kagi_bin(&home_path);
    cmd.current_dir(project_path);
    cmd.args(["member", "list"]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("active"));

    // 13. member del blocks non-interactive
    let mut cmd = kagi_bin(&home_path);
    cmd.current_dir(project_path);
    cmd.args(["member", "del", &pending_member_id]);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("requires an interactive terminal"));

    // 14. run command with injected env vars
    let mut cmd = kagi_bin(&home_path);
    cmd.current_dir(project_path);
    cmd.args(["run", "api", "dev", "sh", "-c", "echo $HOST"]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("localhost"));

    // 15. search --values blocks non-interactive
    let mut cmd = kagi_bin(&home_path);
    cmd.current_dir(project_path);
    cmd.args(["search", "--values", "HOST"]);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("requires an interactive terminal"));

    // 16. doctor --fix blocks non-interactive when journal exists
    let kagi_json: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(project_path.join(".kagi/kagi.json")).unwrap())
            .unwrap();
    let project_id = kagi_json["project_id"].as_str().unwrap().to_string();
    let access_json = fs::read_to_string(project_path.join(".kagi/access.json")).unwrap();
    let journal = serde_json::json!({
        "version": 1,
        "project_id": project_id,
        "access_json": access_json,
        "files": {}
    });
    // rotation journal is stored in KAGI_HOME/projects/{project_id}.rotation.json
    let journal_dir = std::path::Path::new(&home_path).join("projects");
    fs::create_dir_all(&journal_dir).unwrap();
    let journal_path = journal_dir.join(format!("{project_id}.rotation.json"));
    fs::write(
        &journal_path,
        serde_json::to_string_pretty(&journal).unwrap(),
    )
    .unwrap();
    let mut cmd = kagi_bin(&home_path);
    cmd.current_dir(project_path);
    cmd.args(["doctor", "--fix"]);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("requires an interactive terminal"));

    // 17. get shows api with dev env
    let mut cmd = kagi_bin(&home_path);
    cmd.current_dir(project_path);
    cmd.args(["get", "api"]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("api"))
        .stdout(predicate::str::contains("dev"))
        .stdout(predicate::str::contains("staging"));
}

#[cfg(feature = "server")]
#[test]
fn test_e2e_server_advanced() {
    use std::io::{Read, Write};

    let home = setup_kagi_home();
    let home_path = home.path().to_str().unwrap().to_string();
    let project_dir = TempDir::new().unwrap();
    let project_path = project_dir.path();

    // init project
    let mut cmd = kagi_bin(&home_path);
    cmd.current_dir(project_path);
    cmd.args(["init", "--envs", "dev"]);
    cmd.assert().success();

    // set a secret
    let mut cmd = kagi_bin(&home_path);
    cmd.current_dir(project_path);
    cmd.args(["set", "api", "dev", "KEY", "value123"]);
    cmd.assert().success();

    // read project_id
    let kagi_json: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(project_path.join(".kagi/kagi.json")).unwrap())
            .unwrap();
    let project_id = kagi_json["project_id"].as_str().unwrap().to_string();

    // spawn server
    let server_dir = TempDir::new().unwrap();
    let db_path = server_dir.path().join("server.db");
    let key_path = server_dir.path().join("server.key");

    let mut serve_cmd = std::process::Command::new(assert_cmd::cargo_bin!("kagi"));
    serve_cmd.env("KAGI_DISABLE_KEYRING", "1");
    serve_cmd.env("KAGI_HOME", server_dir.path().join("kagi-home"));
    serve_cmd.args([
        "serve",
        "--bind",
        "127.0.0.1:0",
        "--db",
        db_path.to_str().unwrap(),
        "--key-file",
        key_path.to_str().unwrap(),
    ]);
    serve_cmd.stdout(std::process::Stdio::piped());
    serve_cmd.stderr(std::process::Stdio::piped());

    let mut child = serve_cmd.spawn().expect("failed to spawn kagi serve");

    let stderr = child.stderr.take().unwrap();
    std::thread::spawn(move || {
        let mut reader = std::io::BufReader::new(stderr);
        for _ in std::io::BufRead::lines(&mut reader) {}
    });

    let stdout = child.stdout.take().unwrap();
    let reader = std::io::BufReader::new(stdout);
    let (line_tx, line_rx) = std::sync::mpsc::channel();

    std::thread::spawn(move || {
        for line in std::io::BufRead::lines(reader).map_while(Result::ok) {
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
            panic!("server startup timed out");
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
                if let Some(p) = line.rfind(":")
                    && (line.contains("listening on http://")
                        || line.contains("running on http://"))
                {
                    let port_str = &line[p + 1..];
                    port = port_str.parse().ok();
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
            Err(_) => {
                let _ = child.kill();
                panic!("server stdout closed unexpectedly");
            }
        }
    }

    let port = port.unwrap();
    let base_url = format!("http://127.0.0.1:{port}");

    // wait for HTTP readiness
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
    assert!(ready, "server did not become HTTP-ready");

    // 1. remote login
    let mut cmd = kagi_bin(&home_path);
    cmd.current_dir(project_path);
    cmd.args(["remote", "login", "--remote", &base_url, "--token", &token]);
    cmd.assert().success();

    // 2. project join
    let mut cmd = kagi_bin(&home_path);
    cmd.current_dir(project_path);
    cmd.args(["project", "join", "--remote", &base_url]);
    cmd.assert().success();

    // 3. project approve
    let mut cmd = kagi_bin(&home_path);
    cmd.current_dir(project_path);
    cmd.args(["project", "approve", "--remote", &base_url, &project_id]);
    cmd.assert().success();

    // 4. pull to get token
    let mut cmd = kagi_bin(&home_path);
    cmd.current_dir(project_path);
    cmd.args(["pull"]);
    cmd.assert().success();

    // 5. push
    let mut cmd = kagi_bin(&home_path);
    cmd.current_dir(project_path);
    cmd.args(["push"]);
    cmd.assert().success();

    // 6. project list (admin)
    let mut cmd = kagi_bin(&home_path);
    cmd.current_dir(project_path);
    cmd.args(["project", "list", "--remote", &base_url]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains(&project_id));

    // 7. token list (shows at least one token)
    let mut cmd = kagi_bin(&home_path);
    cmd.current_dir(project_path);
    cmd.args(["token", "list", "--remote", &base_url]);
    cmd.assert().success();

    // 8. token revoke (server echoes back requested token_ids)
    let mut cmd = kagi_bin(&home_path);
    cmd.current_dir(project_path);
    cmd.args(["token", "revoke", "--remote", &base_url, "some_token_id"]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("revoked"))
        .stdout(predicate::str::contains("some_token_id"));

    // 9. project del (admin)
    let mut cmd = kagi_bin(&home_path);
    cmd.current_dir(project_path);
    cmd.args(["project", "del", "--remote", &base_url, &project_id]);
    cmd.assert().success();

    // cleanup
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(feature = "server")]
fn http_get_json(url: &str, token: Option<&str>) -> serde_json::Value {
    let mut cmd = std::process::Command::new("curl");
    cmd.args(["-s", "-w", "\\n%{http_code}", url]);
    if let Some(t) = token {
        cmd.arg("-H").arg(format!("Authorization: Bearer {t}"));
    }
    let output = cmd.output().expect("curl failed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let lines: Vec<&str> = stdout.lines().collect();
    let body = lines.first().unwrap_or(&"{}");
    serde_json::from_str(body).unwrap_or_else(|_| panic!("failed to parse JSON from {url}: {body}"))
}

#[cfg(unix)]
#[test]
fn test_e2e_interactive_unset() {
    let home = setup_kagi_home();
    let home_path = home.path().to_str().unwrap().to_string();
    let project_dir = TempDir::new().unwrap();
    let project_path = project_dir.path();

    let mut cmd = kagi_bin(&home_path);
    cmd.current_dir(project_path);
    cmd.args(["init", "--envs", "dev"]);
    cmd.assert().success();

    let mut cmd = kagi_bin(&home_path);
    cmd.current_dir(project_path);
    cmd.args(["set", "api", "dev", "KEY", "value123"]);
    cmd.assert().success();

    let (status, output) = run_kagi_interactive(
        &home_path,
        project_path,
        &["unset", "api", "dev", "KEY"],
        &["y"],
    );
    assert!(status.success(), "unset failed: {output}");
    assert!(output.contains("unset"));

    // Verify the key is gone
    let mut cmd = kagi_bin(&home_path);
    cmd.current_dir(project_path);
    cmd.args(["get", "api", "dev"]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("KEY").not());
}

#[cfg(unix)]
#[test]
fn test_e2e_interactive_env_del() {
    let home = setup_kagi_home();
    let home_path = home.path().to_str().unwrap().to_string();
    let project_dir = TempDir::new().unwrap();
    let project_path = project_dir.path();

    let mut cmd = kagi_bin(&home_path);
    cmd.current_dir(project_path);
    cmd.args(["init", "--envs", "dev,test"]);
    cmd.assert().success();

    let mut cmd = kagi_bin(&home_path);
    cmd.current_dir(project_path);
    cmd.args(["set", "api", "dev", "KEY", "value123"]);
    cmd.assert().success();

    let mut cmd = kagi_bin(&home_path);
    cmd.current_dir(project_path);
    cmd.args(["set", "api", "test", "KEY", "value456"]);
    cmd.assert().success();

    let (status, output) = run_kagi_interactive(
        &home_path,
        project_path,
        &["env", "del", "test", "--plain"],
        &["test"],
    );
    assert!(status.success(), "env del failed: {output}");
    assert!(output.contains("deleted environment"));

    // Verify test env is gone
    let mut cmd = kagi_bin(&home_path);
    cmd.current_dir(project_path);
    cmd.args(["env", "list"]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("test").not());
}

#[cfg(unix)]
#[test]
fn test_e2e_interactive_import_cancel_does_not_write() {
    let home = setup_kagi_home();
    let home_path = home.path().to_str().unwrap().to_string();
    let project_dir = TempDir::new().unwrap();
    let project_path = project_dir.path();

    let mut cmd = kagi_bin(&home_path);
    cmd.current_dir(project_path);
    cmd.args(["init", "--envs", "dev"]);
    cmd.assert().success();

    let env_file = project_path.join(".env");
    fs::write(&env_file, "API_KEY=secret\n").unwrap();

    let (status, output) = run_kagi_interactive(
        &home_path,
        project_path,
        &["import", "api", "dev", "--file", env_file.to_str().unwrap()],
        &["n"],
    );
    assert!(status.success(), "import cancel failed: {output}");
    assert!(output.contains("aborted."));

    let mut cmd = kagi_bin(&home_path);
    cmd.current_dir(project_path);
    cmd.args(["run", "api", "dev", "sh", "-c", "test -z \"${API_KEY+x}\""]);
    cmd.assert().success();
}

#[cfg(unix)]
#[test]
fn test_e2e_interactive_member_del() {
    let home = setup_kagi_home();
    let home_path = home.path().to_str().unwrap().to_string();
    let project_dir = TempDir::new().unwrap();
    let project_path = project_dir.path();

    let mut cmd = kagi_bin(&home_path);
    cmd.current_dir(project_path);
    cmd.args(["init", "--envs", "dev"]);
    cmd.assert().success();

    // Create a join request
    let mut cmd = kagi_bin(&home_path);
    cmd.current_dir(project_path);
    cmd.args(["member", "join", "--name", "Alice"]);
    cmd.assert().success();

    let access_json: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(project_path.join(".kagi/access.json")).unwrap())
            .unwrap();
    let pending_member = access_json["members"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["status"] == "pending")
        .unwrap();
    let pending_member_id = pending_member["member_id"].as_str().unwrap().to_string();

    // Approve the join request
    let mut cmd = kagi_bin(&home_path);
    cmd.current_dir(project_path);
    cmd.args(["member", "approve", &pending_member_id]);
    cmd.assert().success();

    // Now remove the member interactively
    let (status, output) = run_kagi_interactive(
        &home_path,
        project_path,
        &["member", "del", &pending_member_id],
        &[&pending_member_id],
    );
    assert!(status.success(), "member del failed: {output}");
    assert!(output.contains("removed member"));

    // Verify the member is marked as removed
    let mut cmd = kagi_bin(&home_path);
    cmd.current_dir(project_path);
    cmd.args(["member", "list"]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("removed"));
}

#[cfg(unix)]
#[test]
fn test_e2e_interactive_search_values() {
    let home = setup_kagi_home();
    let home_path = home.path().to_str().unwrap().to_string();
    let project_dir = TempDir::new().unwrap();
    let project_path = project_dir.path();

    let mut cmd = kagi_bin(&home_path);
    cmd.current_dir(project_path);
    cmd.args(["init", "--envs", "dev"]);
    cmd.assert().success();

    let mut cmd = kagi_bin(&home_path);
    cmd.current_dir(project_path);
    cmd.args(["set", "api", "dev", "HOST", "localhost"]);
    cmd.assert().success();

    let (status, output) = run_kagi_interactive(
        &home_path,
        project_path,
        &["search", "--values", "--plain", "localhost"],
        &["y"],
    );
    assert!(status.success(), "search --values --plain failed: {output}");
    assert!(output.contains("api/dev.HOST"));
}

#[cfg(unix)]
#[test]
fn test_e2e_interactive_doctor_fix() {
    let home = setup_kagi_home();
    let home_path = home.path().to_str().unwrap().to_string();
    let project_dir = TempDir::new().unwrap();
    let project_path = project_dir.path();

    let mut cmd = kagi_bin(&home_path);
    cmd.current_dir(project_path);
    cmd.args(["init", "--envs", "dev"]);
    cmd.assert().success();

    let kagi_json: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(project_path.join(".kagi/kagi.json")).unwrap())
            .unwrap();
    let project_id = kagi_json["project_id"].as_str().unwrap().to_string();
    let access_json = fs::read_to_string(project_path.join(".kagi/access.json")).unwrap();
    let journal = serde_json::json!({
        "version": 1,
        "project_id": project_id,
        "access_json": access_json,
        "files": {}
    });
    // rotation journal is stored in KAGI_HOME/projects/{project_id}.rotation.json
    let journal_dir = std::path::Path::new(&home_path).join("projects");
    fs::create_dir_all(&journal_dir).unwrap();
    let journal_path = journal_dir.join(format!("{project_id}.rotation.json"));
    fs::write(
        &journal_path,
        serde_json::to_string_pretty(&journal).unwrap(),
    )
    .unwrap();

    let (status, output) = run_kagi_interactive(
        &home_path,
        project_path,
        &["doctor", "--fix", "--plain"],
        &["y"],
    );
    assert!(status.success(), "doctor --fix failed: {output}");
    assert!(output.contains("recovered pending rotation"));
    assert!(!journal_path.exists());
}

#[cfg(unix)]
#[test]
fn test_e2e_interactive_init_migration() {
    let home = setup_kagi_home();
    let home_path = home.path().to_str().unwrap().to_string();
    let project_dir = TempDir::new().unwrap();
    let project_path = project_dir.path();

    fs::write(project_path.join(".env"), "ROOT_KEY=root\n").unwrap();
    fs::create_dir(project_path.join("api")).unwrap();
    fs::write(project_path.join("api/.env"), "API_KEY=api\n").unwrap();

    let (status, output) =
        run_kagi_interactive(&home_path, project_path, &["init", "--envs", "dev"], &["y"]);
    assert!(status.success(), "init with migration failed: {output}");
    assert!(
        output.contains("migrated"),
        "expected migration output, got: {output}"
    );
    assert!(
        output.contains(".env"),
        "expected .env file path in output, got: {output}"
    );
    assert!(
        output.contains("api/.env"),
        "expected api .env file path in output, got: {output}"
    );
}
