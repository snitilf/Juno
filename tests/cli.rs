mod common;

use common::write_release_evidence;
use juno::Roots;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

fn command(home: &std::path::Path) -> Command {
    let binary = env!("CARGO_BIN_EXE_juno");
    let source_bin = home.join("bundle/juno");
    fs::create_dir_all(source_bin.parent().unwrap()).unwrap();
    fs::copy(binary, &source_bin).unwrap();
    fs::set_permissions(&source_bin, fs::Permissions::from_mode(0o755)).unwrap();
    let roots = Roots {
        codex_home: home.join("codex"),
        state_home: home.join("state"),
        install_bin: home.join("bin/juno"),
        source_bin: source_bin.clone(),
    };
    fs::create_dir_all(&roots.codex_home).unwrap();
    fs::create_dir_all(roots.install_bin.parent().unwrap()).unwrap();
    write_release_evidence(&roots);
    let mut command = Command::new(binary);
    command
        .env("HOME", home)
        .env("JUNO_CODEX_HOME", &roots.codex_home)
        .env("JUNO_STATE_HOME", &roots.state_home)
        .env("JUNO_INSTALL_BIN", &roots.install_bin)
        .env("JUNO_SOURCE_BIN", &roots.source_bin);
    command
}

#[test]
fn version_and_plan_interfaces_are_stable() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().canonicalize().unwrap();
    let version = command(&home).arg("version").output().unwrap();
    assert!(version.status.success());
    assert!(String::from_utf8_lossy(&version.stdout).starts_with("juno "));

    let mut plan_command = command(&home);
    let plan = plan_command.arg("install").output().unwrap();
    assert!(
        plan.status.success(),
        "{}",
        String::from_utf8_lossy(&plan.stderr)
    );
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
