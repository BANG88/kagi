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
    assert!(dir.path().join(".kagi/config.json").exists());
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
    cmd.assert().success().stdout("api\n");

    let mut cmd = Command::cargo_bin("kagi").unwrap();
    cmd.current_dir(&dir);
    cmd.args(["list", "api"]);
    cmd.assert().success().stdout("KEY\n");
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
