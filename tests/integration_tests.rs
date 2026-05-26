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
