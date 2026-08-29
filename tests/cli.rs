use std::fs;
use std::process::Command;

fn command(home: &std::path::Path) -> Command {
    let binary = env!("CARGO_BIN_EXE_juno");
    let mut command = Command::new(binary);
    command
        .env("HOME", home)
        .env("JUNO_CODEX_HOME", home.join("codex"))
        .env("JUNO_STATE_HOME", home.join("state"))
        .env("JUNO_INSTALL_BIN", home.join("bin/juno"))
        .env("JUNO_SOURCE_BIN", binary);
    command
}

#[test]
fn version_and_plan_interfaces_are_stable() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().canonicalize().unwrap();
    let version = command(&home).arg("version").output().unwrap();
    assert!(version.status.success());
    assert!(String::from_utf8_lossy(&version.stdout).starts_with("juno "));

    let plan = command(&home).arg("install").output().unwrap();
    assert!(plan.status.success());
    let output = String::from_utf8_lossy(&plan.stdout);
    assert!(output.contains("plan: "));
    assert!(output.contains("--allow-shared-files"));
    assert!(!home.join("bin/juno").exists());
    let repeated = command(&home).arg("install").output().unwrap();
    assert!(repeated.status.success());
    let first_id = output
        .lines()
        .find_map(|line| line.strip_prefix("plan: "))
        .unwrap();
    let second_output = String::from_utf8_lossy(&repeated.stdout);
    let second_id = second_output
        .lines()
        .find_map(|line| line.strip_prefix("plan: "))
        .unwrap();
    assert_eq!(first_id, second_id);
}

#[test]
fn yes_flag_is_rejected() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().canonicalize().unwrap();
    fs::create_dir_all(home.join("codex")).unwrap();
    let output = command(&home).args(["install", "--yes"]).output().unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("--yes is not supported"));
}

#[test]
fn options_are_scoped_to_their_commands() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().canonicalize().unwrap();
    for arguments in [
        vec!["doctor", "--apply", "abcd"],
        vec!["install", "--json"],
        vec!["update", "--strategy", "complete"],
        vec!["recover", "--strategy", "rollback", "--json"],
    ] {
        let output = command(&home).args(arguments).output().unwrap();
        assert!(!output.status.success());
    }
}
