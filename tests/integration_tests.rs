use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

#[test]
fn test_init() {
    let dir = TempDir::new().unwrap();
    let mut cmd = Command::cargo_bin("kagi").unwrap();
    cmd.current_dir(&dir);
    cmd.arg("init");
    cmd.assert().success().stdout(predicate::str::contains("Initialized"));
    assert!(dir.path().join(".kagi/kagi.json").exists());
    assert!(dir.path().join(".kagi/key/master.key").exists());
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

    let mut cmd = Command::cargo_bin("kagi").unwrap();
    cmd.current_dir(&dir);
    cmd.args(["get", "api", "KEY"]);
    cmd.assert().success().stdout("val\n");
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
    assert!(stdout.contains("api"), "expected api in list output: {}", stdout);
    assert!(stdout.contains("dev"), "expected dev in list output: {}", stdout);
    assert!(stdout.contains("test"), "expected test in list output: {}", stdout);
    assert!(stdout.contains("staging"), "expected staging in list output: {}", stdout);
    assert!(stdout.contains("prod"), "expected prod in list output: {}", stdout);

    let mut cmd = Command::cargo_bin("kagi").unwrap();
    cmd.current_dir(&dir);
    cmd.args(["list", "api"]);
    let assert = cmd.assert().success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(stdout.contains("Key"), "expected table header in list api: {}", stdout);
    assert!(stdout.contains("Value"), "expected table header in list api: {}", stdout);
    assert!(stdout.contains("KEY"), "expected KEY in list api: {}", stdout);
    assert!(stdout.contains("val"), "expected val in list api: {}", stdout);
}

#[test]
fn test_export() {
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
    cmd.assert().success().stdout("KEY=val\n");
}

#[test]
fn test_import_from_file() {
    let dir = TempDir::new().unwrap();

    let mut cmd = Command::cargo_bin("kagi").unwrap();
    cmd.current_dir(&dir);
    cmd.arg("init");
    cmd.assert().success();

    std::fs::write(dir.path().join("dev.env"), "API_KEY=secret\nDB_URL=postgres://localhost\n").unwrap();

    let mut cmd = Command::cargo_bin("kagi").unwrap();
    cmd.current_dir(&dir);
    cmd.args(["import", "api", "--file", "dev.env"]);
    cmd.assert().success();

    let mut cmd = Command::cargo_bin("kagi").unwrap();
    cmd.current_dir(&dir);
    cmd.args(["get", "api", "API_KEY"]);
    cmd.assert().success().stdout("secret\n");

    let mut cmd = Command::cargo_bin("kagi").unwrap();
    cmd.current_dir(&dir);
    cmd.args(["get", "api", "DB_URL"]);
    cmd.assert().success().stdout("postgres://localhost\n");
}

#[test]
fn test_import_force_overwrites() {
    let dir = TempDir::new().unwrap();

    let mut cmd = Command::cargo_bin("kagi").unwrap();
    cmd.current_dir(&dir);
    cmd.arg("init");
    cmd.assert().success();

    std::fs::write(dir.path().join("first.env"), "API_KEY=old_value\n").unwrap();
    std::fs::write(dir.path().join("second.env"), "API_KEY=new_value\nEXTRA_KEY=extra\n").unwrap();

    let mut cmd = Command::cargo_bin("kagi").unwrap();
    cmd.current_dir(&dir);
    cmd.args(["import", "api", "--file", "first.env"]);
    cmd.assert().success();

    let mut cmd = Command::cargo_bin("kagi").unwrap();
    cmd.current_dir(&dir);
    cmd.args(["get", "api", "API_KEY"]);
    cmd.assert().success().stdout("old_value\n");

    let mut cmd = Command::cargo_bin("kagi").unwrap();
    cmd.current_dir(&dir);
    cmd.args(["import", "api", "--file", "second.env", "--force"]);
    cmd.assert().success().stdout(predicate::str::contains("overwritten"));

    let mut cmd = Command::cargo_bin("kagi").unwrap();
    cmd.current_dir(&dir);
    cmd.args(["get", "api", "API_KEY"]);
    cmd.assert().success().stdout("new_value\n");

    let mut cmd = Command::cargo_bin("kagi").unwrap();
    cmd.current_dir(&dir);
    cmd.args(["get", "api", "EXTRA_KEY"]);
    cmd.assert().success().stdout("extra\n");
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
    ).unwrap();

    let mut cmd = Command::cargo_bin("kagi").unwrap();
    cmd.current_dir(&dir);
    cmd.arg("sync");
    cmd.assert().success().stdout(predicate::str::contains("Synced"));

    let mut cmd = Command::cargo_bin("kagi").unwrap();
    cmd.current_dir(&dir);
    cmd.args(["get", "dev", "DATABASE_URL"]);
    cmd.assert().success().stdout("postgres://localhost\n");

    let mut cmd = Command::cargo_bin("kagi").unwrap();
    cmd.current_dir(&dir);
    cmd.args(["get", "dev", "WEBHOOK_SECRET"]);
    cmd.assert().success().stdout("\n");

    let mut cmd = Command::cargo_bin("kagi").unwrap();
    cmd.current_dir(&dir);
    cmd.args(["get", "test", "DEBUG"]);
    cmd.assert().success().stdout("true\n");
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
    cmd.assert().success().stdout(predicate::str::contains("skipped"));

    let mut cmd = Command::cargo_bin("kagi").unwrap();
    cmd.current_dir(&dir);
    cmd.args(["get", "dev", "API_KEY"]);
    cmd.assert().success().stdout("custom\n");
}

#[test]
fn test_nested_disabled_rejects_child_directory() {
    let dir = TempDir::new().unwrap();

    // Init in parent
    let mut cmd = Command::cargo_bin("kagi").unwrap();
    cmd.current_dir(&dir);
    cmd.arg("init");
    cmd.assert().success();

    // Disable nested
    let kagi_json = dir.path().join(".kagi/kagi.json");
    std::fs::write(&kagi_json, r#"{"version":"1","services":{},"settings":{"nested":false}}"#).unwrap();

    // Create child dir and try to use kagi
    let child = dir.path().join("api");
    std::fs::create_dir(&child).unwrap();
    let mut cmd = Command::cargo_bin("kagi").unwrap();
    cmd.current_dir(&child);
    cmd.arg("list");
    cmd.assert().failure().stderr(predicate::str::contains("not allowed"));
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
    std::fs::write(&kagi_json, r#"{"version":"1","services":{},"settings":{"nested":["api"]}}"#).unwrap();

    // Allowed child path
    let api_dir = dir.path().join("api/src");
    std::fs::create_dir_all(&api_dir).unwrap();
    let mut cmd = Command::cargo_bin("kagi").unwrap();
    cmd.current_dir(&api_dir);
    cmd.arg("list");
    cmd.assert().success();

    // Disallowed child path
    let web_dir = dir.path().join("web");
    std::fs::create_dir(&web_dir).unwrap();
    let mut cmd = Command::cargo_bin("kagi").unwrap();
    cmd.current_dir(&web_dir);
    cmd.arg("list");
    cmd.assert().failure().stderr(predicate::str::contains("not allowed"));
}

#[test]
fn test_set_infers_service_from_nested_dir() {
    let dir = TempDir::new().unwrap();

    let mut cmd = Command::cargo_bin("kagi").unwrap();
    cmd.current_dir(&dir);
    cmd.arg("init");
    cmd.assert().success();

    let kagi_json = dir.path().join(".kagi/kagi.json");
    std::fs::write(&kagi_json, r#"{"version":"1","services":{},"settings":{"nested":true}}"#).unwrap();

    let api_dir = dir.path().join("api");
    std::fs::create_dir_all(&api_dir).unwrap();

    let mut cmd = Command::cargo_bin("kagi").unwrap();
    cmd.current_dir(&api_dir);
    cmd.args(["set", "KEY", "val"]);
    cmd.assert().success();

    let mut cmd = Command::cargo_bin("kagi").unwrap();
    cmd.current_dir(&api_dir);
    cmd.args(["get", "KEY"]);
    cmd.assert().success().stdout("val\n");
}

#[test]
fn test_get_infers_service_from_nested_dir() {
    let dir = TempDir::new().unwrap();

    let mut cmd = Command::cargo_bin("kagi").unwrap();
    cmd.current_dir(&dir);
    cmd.arg("init");
    cmd.assert().success();

    let kagi_json = dir.path().join(".kagi/kagi.json");
    std::fs::write(&kagi_json, r#"{"version":"1","services":{},"settings":{"nested":true}}"#).unwrap();

    let api_dir = dir.path().join("api");
    std::fs::create_dir_all(&api_dir).unwrap();

    let mut cmd = Command::cargo_bin("kagi").unwrap();
    cmd.current_dir(&api_dir);
    cmd.args(["set", "api", "KEY", "val"]);
    cmd.assert().success();

    let mut cmd = Command::cargo_bin("kagi").unwrap();
    cmd.current_dir(&api_dir);
    cmd.args(["get", "KEY"]);
    cmd.assert().success().stdout("val\n");
}

#[test]
fn test_export_infers_service_from_nested_dir() {
    let dir = TempDir::new().unwrap();

    let mut cmd = Command::cargo_bin("kagi").unwrap();
    cmd.current_dir(&dir);
    cmd.arg("init");
    cmd.assert().success();

    let kagi_json = dir.path().join(".kagi/kagi.json");
    std::fs::write(&kagi_json, r#"{"version":"1","services":{},"settings":{"nested":true}}"#).unwrap();

    let api_dir = dir.path().join("api");
    std::fs::create_dir_all(&api_dir).unwrap();

    let mut cmd = Command::cargo_bin("kagi").unwrap();
    cmd.current_dir(&api_dir);
    cmd.args(["set", "api", "KEY", "val"]);
    cmd.assert().success();

    let mut cmd = Command::cargo_bin("kagi").unwrap();
    cmd.current_dir(&api_dir);
    cmd.arg("export");
    cmd.assert().success().stdout("KEY=val\n");
}

#[test]
fn test_explicit_service_overrides_inference() {
    let dir = TempDir::new().unwrap();

    let mut cmd = Command::cargo_bin("kagi").unwrap();
    cmd.current_dir(&dir);
    cmd.arg("init");
    cmd.assert().success();

    let kagi_json = dir.path().join(".kagi/kagi.json");
    std::fs::write(&kagi_json, r#"{"version":"1","services":{},"settings":{"nested":true}}"#).unwrap();

    let api_dir = dir.path().join("api");
    std::fs::create_dir_all(&api_dir).unwrap();

    // Set secret for 'web' service while in api/ directory
    let mut cmd = Command::cargo_bin("kagi").unwrap();
    cmd.current_dir(&api_dir);
    cmd.args(["set", "web", "KEY", "val"]);
    cmd.assert().success();

    // Verify it's under 'web', not 'api'
    let mut cmd = Command::cargo_bin("kagi").unwrap();
    cmd.current_dir(&api_dir);
    cmd.args(["get", "web", "KEY"]);
    cmd.assert().success().stdout("val\n");
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
    cmd.assert().failure().stderr(predicate::str::contains("Usage:"));
}
