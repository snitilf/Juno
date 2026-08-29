use juno::{LifecycleCommand, LifecycleOptions, RecoveryStrategy, Roots, execute_lifecycle};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::{Arc, Barrier};

fn fixture() -> (tempfile::TempDir, Roots) {
    let temp = tempfile::tempdir().unwrap();
    let base = temp.path().canonicalize().unwrap();
    let codex_home = base.join("codex");
    let state_home = base.join("state");
    let install_bin = base.join("bin/juno");
    let source_bin = base.join("bundle/juno");
    fs::create_dir_all(source_bin.parent().unwrap()).unwrap();
    fs::write(&source_bin, b"fake juno binary").unwrap();
    fs::set_permissions(&source_bin, fs::Permissions::from_mode(0o755)).unwrap();
    fs::create_dir_all(&codex_home).unwrap();
    (
        temp,
        Roots {
            codex_home,
            state_home,
            install_bin,
            source_bin,
        },
    )
}

fn plan_id(output: &str) -> &str {
    output
        .lines()
        .find_map(|line| line.strip_prefix("plan: "))
        .unwrap()
}

fn install(roots: &Roots) {
    let plan = execute_lifecycle(
        LifecycleCommand::Install,
        &LifecycleOptions::default(),
        roots,
    )
    .unwrap();
    execute_lifecycle(
        LifecycleCommand::Install,
        &LifecycleOptions {
            apply: Some(plan_id(&plan).to_string()),
            allow_shared_files: true,
            ..LifecycleOptions::default()
        },
        roots,
    )
    .unwrap();
}

#[test]
fn install_is_plan_first_and_preserves_shared_content() {
    let (_temp, roots) = fixture();
    fs::write(roots.codex_home.join("AGENTS.md"), "user instruction\n").unwrap();
    fs::write(
        roots.codex_home.join("config.toml"),
        "approval_policy = \"never\" # user\n",
    )
    .unwrap();

    let output = execute_lifecycle(
        LifecycleCommand::Install,
        &LifecycleOptions::default(),
        &roots,
    )
    .unwrap();
    let id = plan_id(&output).to_string();
    let plan: serde_json::Value = serde_json::from_slice(
        &fs::read(roots.state_home.join("plans").join(format!("{id}.json"))).unwrap(),
    )
    .unwrap();
    assert_eq!(plan["schema_version"], 1);
    assert_eq!(
        plan["source_bin"],
        roots.source_bin.to_string_lossy().as_ref()
    );
    assert_eq!(plan["binary_sha256"].as_str().unwrap().len(), 64);
    assert_eq!(plan["bundle_sha256"].as_str().unwrap().len(), 64);
    assert_eq!(plan["recovery_binary_sha256"], plan["binary_sha256"]);
    assert!(
        plan["backup_root_template"]
            .as_str()
            .unwrap()
            .ends_with("transactions/{PLAN_ID}/backups")
    );
    let agents_operation = plan["operations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|operation| operation["relative"] == "AGENTS.md")
        .unwrap();
    assert_eq!(agents_operation["expected"]["kind"], "regular");
    assert!(agents_operation["expected"]["uid"].is_number());
    assert!(agents_operation["expected"]["gid"].is_number());
    assert_eq!(
        fs::read_to_string(roots.codex_home.join("AGENTS.md")).unwrap(),
        "user instruction\n"
    );
    assert!(!roots.install_bin.exists());

    let blocked = execute_lifecycle(
        LifecycleCommand::Install,
        &LifecycleOptions {
            apply: Some(id.clone()),
            ..LifecycleOptions::default()
        },
        &roots,
    )
    .unwrap_err();
    assert!(blocked.to_string().contains("--allow-shared-files"));

    execute_lifecycle(
        LifecycleCommand::Install,
        &LifecycleOptions {
            apply: Some(id),
            allow_shared_files: true,
            ..LifecycleOptions::default()
        },
        &roots,
    )
    .unwrap();

    let instructions = fs::read_to_string(roots.codex_home.join("AGENTS.md")).unwrap();
    assert!(instructions.starts_with("user instruction\n"));
    assert!(instructions.contains("<!-- juno:begin -->"));
    let config = fs::read_to_string(roots.codex_home.join("config.toml")).unwrap();
    assert!(config.contains("approval_policy = \"never\" # user"));
    assert!(toml::from_str::<toml::Value>(&config).is_ok());
    assert_eq!(
        fs::read_dir(roots.codex_home.join("agents"))
            .unwrap()
            .count(),
        8
    );
    assert_eq!(
        fs::metadata(roots.codex_home.join("AGENTS.md"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o644
    );
    assert_eq!(fs::read(&roots.install_bin).unwrap(), b"fake juno binary");

    let doctor = execute_lifecycle(
        LifecycleCommand::Doctor,
        &LifecycleOptions {
            json: true,
            ..LifecycleOptions::default()
        },
        &roots,
    )
    .unwrap();
    let report: serde_json::Value = serde_json::from_str(&doctor).unwrap();
    assert_eq!(report["status"], "installed");
    assert_eq!(report["managed_files_drifted"].as_array().unwrap().len(), 0);
}

#[test]
fn nonempty_override_is_the_instruction_target() {
    let (_temp, roots) = fixture();
    fs::write(roots.codex_home.join("AGENTS.md"), "base\n").unwrap();
    fs::write(roots.codex_home.join("AGENTS.override.md"), "override\n").unwrap();
    let output = execute_lifecycle(
        LifecycleCommand::Install,
        &LifecycleOptions::default(),
        &roots,
    )
    .unwrap();
    let id = plan_id(&output).to_string();
    execute_lifecycle(
        LifecycleCommand::Install,
        &LifecycleOptions {
            apply: Some(id),
            allow_shared_files: true,
            ..LifecycleOptions::default()
        },
        &roots,
    )
    .unwrap();
    assert_eq!(
        fs::read_to_string(roots.codex_home.join("AGENTS.md")).unwrap(),
        "base\n"
    );
    assert!(
        fs::read_to_string(roots.codex_home.join("AGENTS.override.md"))
            .unwrap()
            .contains("<!-- juno:begin -->")
    );
}

#[test]
fn unknown_agent_collision_blocks_planning() {
    let (_temp, roots) = fixture();
    fs::create_dir_all(roots.codex_home.join("agents")).unwrap();
    fs::write(roots.codex_home.join("agents/scout.toml"), "user file").unwrap();
    let error = execute_lifecycle(
        LifecycleCommand::Install,
        &LifecycleOptions::default(),
        &roots,
    )
    .unwrap_err();
    assert!(error.to_string().contains("unknown collisions"));
    assert_eq!(
        fs::read_to_string(roots.codex_home.join("agents/scout.toml")).unwrap(),
        "user file"
    );
}

#[test]
fn no_test_path_points_at_a_real_codex_home() {
    let (_temp, roots) = fixture();
    assert_ne!(roots.codex_home, Path::new("/Users/snitil/.codex"));
    assert!(roots.codex_home.starts_with("/private/var/"));
}

#[test]
fn update_uses_the_new_bundle_and_uninstall_restores_the_baseline() {
    let (_temp, roots) = fixture();
    fs::write(roots.codex_home.join("AGENTS.md"), "user instruction\n").unwrap();
    fs::write(
        roots.codex_home.join("config.toml"),
        "approval_policy = \"never\" # user\n",
    )
    .unwrap();
    install(&roots);

    fs::write(&roots.source_bin, b"new fake juno binary").unwrap();
    let update_plan = execute_lifecycle(
        LifecycleCommand::Update,
        &LifecycleOptions::default(),
        &roots,
    )
    .unwrap();
    execute_lifecycle(
        LifecycleCommand::Update,
        &LifecycleOptions {
            apply: Some(plan_id(&update_plan).to_string()),
            ..LifecycleOptions::default()
        },
        &roots,
    )
    .unwrap();
    assert_eq!(
        fs::read(&roots.install_bin).unwrap(),
        b"new fake juno binary"
    );

    let uninstall_plan = execute_lifecycle(
        LifecycleCommand::Uninstall,
        &LifecycleOptions::default(),
        &roots,
    )
    .unwrap();
    execute_lifecycle(
        LifecycleCommand::Uninstall,
        &LifecycleOptions {
            apply: Some(plan_id(&uninstall_plan).to_string()),
            allow_shared_files: true,
            ..LifecycleOptions::default()
        },
        &roots,
    )
    .unwrap();
    assert_eq!(
        fs::read_to_string(roots.codex_home.join("AGENTS.md")).unwrap(),
        "user instruction\n"
    );
    assert_eq!(
        fs::read_to_string(roots.codex_home.join("config.toml")).unwrap(),
        "approval_policy = \"never\" # user\n"
    );
    assert!(!roots.install_bin.exists());
    assert!(!roots.state_home.join("manifest.json").exists());
}

#[test]
fn uninstall_preserves_later_shared_edits_and_modified_agents() {
    let (_temp, roots) = fixture();
    fs::write(roots.codex_home.join("AGENTS.md"), "before\n").unwrap();
    fs::write(roots.codex_home.join("config.toml"), "user_key = 1\n").unwrap();
    install(&roots);
    let mut instructions = fs::read_to_string(roots.codex_home.join("AGENTS.md")).unwrap();
    instructions.push_str("after\n");
    fs::write(roots.codex_home.join("AGENTS.md"), instructions).unwrap();
    let mut config = fs::read_to_string(roots.codex_home.join("config.toml")).unwrap();
    config.push_str("later_key = 2\n");
    fs::write(roots.codex_home.join("config.toml"), config).unwrap();
    fs::write(
        roots.codex_home.join("agents/executor.toml"),
        "changed by user\n",
    )
    .unwrap();

    let uninstall_plan = execute_lifecycle(
        LifecycleCommand::Uninstall,
        &LifecycleOptions::default(),
        &roots,
    )
    .unwrap();
    assert!(uninstall_plan.contains("conflicts: 1"));
    execute_lifecycle(
        LifecycleCommand::Uninstall,
        &LifecycleOptions {
            apply: Some(plan_id(&uninstall_plan).to_string()),
            allow_shared_files: true,
            ..LifecycleOptions::default()
        },
        &roots,
    )
    .unwrap();
    let instructions = fs::read_to_string(roots.codex_home.join("AGENTS.md")).unwrap();
    assert_eq!(instructions, "before\nafter\n");
    let config = fs::read_to_string(roots.codex_home.join("config.toml")).unwrap();
    assert!(config.contains("user_key = 1"));
    assert!(config.contains("later_key = 2"));
    assert!(!config.contains("model_reasoning_effort"));
    assert_eq!(
        fs::read_to_string(roots.codex_home.join("agents/executor.toml")).unwrap(),
        "changed by user\n"
    );
    assert!(roots.state_home.join("manifest.json").exists());
}

#[test]
fn interrupted_install_can_roll_back_from_an_approved_recovery_plan() {
    let (_temp, roots) = fixture();
    fs::write(roots.codex_home.join("AGENTS.md"), "before\n").unwrap();
    fs::write(roots.codex_home.join("config.toml"), "user_key = 1\n").unwrap();
    let install_plan = execute_lifecycle(
        LifecycleCommand::Install,
        &LifecycleOptions::default(),
        &roots,
    )
    .unwrap();
    let error = execute_lifecycle(
        LifecycleCommand::Install,
        &LifecycleOptions {
            apply: Some(plan_id(&install_plan).to_string()),
            allow_shared_files: true,
            fault_after: Some(2),
            ..LifecycleOptions::default()
        },
        &roots,
    )
    .unwrap_err();
    assert!(error.to_string().contains("injected transaction fault"));
    assert!(roots.state_home.join("journal.json").exists());
    assert!(
        execute_lifecycle(
            LifecycleCommand::Update,
            &LifecycleOptions::default(),
            &roots,
        )
        .unwrap_err()
        .to_string()
        .contains("requires recovery")
    );

    let recovery_plan = execute_lifecycle(
        LifecycleCommand::Recover {
            strategy: RecoveryStrategy::Rollback,
        },
        &LifecycleOptions::default(),
        &roots,
    )
    .unwrap();
    execute_lifecycle(
        LifecycleCommand::Recover {
            strategy: RecoveryStrategy::Rollback,
        },
        &LifecycleOptions {
            apply: Some(plan_id(&recovery_plan).to_string()),
            allow_shared_files: true,
            ..LifecycleOptions::default()
        },
        &roots,
    )
    .unwrap();
    assert_eq!(
        fs::read_to_string(roots.codex_home.join("AGENTS.md")).unwrap(),
        "before\n"
    );
    assert_eq!(
        fs::read_to_string(roots.codex_home.join("config.toml")).unwrap(),
        "user_key = 1\n"
    );
    assert!(!roots.state_home.join("journal.json").exists());
    assert!(!roots.state_home.join("manifest.json").exists());
}

#[test]
fn recovery_detects_a_completed_in_flight_swap() {
    let (_temp, roots) = fixture();
    fs::write(roots.codex_home.join("AGENTS.md"), "before\n").unwrap();
    let install_plan = execute_lifecycle(
        LifecycleCommand::Install,
        &LifecycleOptions::default(),
        &roots,
    )
    .unwrap();
    let error = execute_lifecycle(
        LifecycleCommand::Install,
        &LifecycleOptions {
            apply: Some(plan_id(&install_plan).to_string()),
            allow_shared_files: true,
            fault_during: Some(1),
            ..LifecycleOptions::default()
        },
        &roots,
    )
    .unwrap_err();
    assert!(error.to_string().contains("in-flight transaction fault"));
    let journal: serde_json::Value =
        serde_json::from_slice(&fs::read(roots.state_home.join("journal.json")).unwrap()).unwrap();
    assert_eq!(journal["applied"], 0);
    assert_eq!(journal["in_flight"], 0);
    assert!(
        fs::read_to_string(roots.codex_home.join("AGENTS.md"))
            .unwrap()
            .contains("<!-- juno:begin -->")
    );

    let recovery_plan = execute_lifecycle(
        LifecycleCommand::Recover {
            strategy: RecoveryStrategy::Rollback,
        },
        &LifecycleOptions::default(),
        &roots,
    )
    .unwrap();
    execute_lifecycle(
        LifecycleCommand::Recover {
            strategy: RecoveryStrategy::Rollback,
        },
        &LifecycleOptions {
            apply: Some(plan_id(&recovery_plan).to_string()),
            allow_shared_files: true,
            ..LifecycleOptions::default()
        },
        &roots,
    )
    .unwrap();
    assert_eq!(
        fs::read_to_string(roots.codex_home.join("AGENTS.md")).unwrap(),
        "before\n"
    );
}

#[test]
fn interrupted_install_can_complete_after_rollback_to_its_baseline() {
    let (_temp, roots) = fixture();
    fs::write(roots.codex_home.join("AGENTS.md"), "before\n").unwrap();
    let install_plan = execute_lifecycle(
        LifecycleCommand::Install,
        &LifecycleOptions::default(),
        &roots,
    )
    .unwrap();
    execute_lifecycle(
        LifecycleCommand::Install,
        &LifecycleOptions {
            apply: Some(plan_id(&install_plan).to_string()),
            allow_shared_files: true,
            fault_after: Some(1),
            ..LifecycleOptions::default()
        },
        &roots,
    )
    .unwrap_err();
    let journal: serde_json::Value =
        serde_json::from_slice(&fs::read(roots.state_home.join("journal.json")).unwrap()).unwrap();
    let recovery_binary = journal["recovery_binary"].as_str().unwrap().into();
    fs::remove_file(&roots.source_bin).unwrap();
    let recovery_roots = Roots {
        source_bin: recovery_binary,
        ..roots.clone()
    };

    let recovery_plan = execute_lifecycle(
        LifecycleCommand::Recover {
            strategy: RecoveryStrategy::Complete,
        },
        &LifecycleOptions::default(),
        &recovery_roots,
    )
    .unwrap();
    execute_lifecycle(
        LifecycleCommand::Recover {
            strategy: RecoveryStrategy::Complete,
        },
        &LifecycleOptions {
            apply: Some(plan_id(&recovery_plan).to_string()),
            allow_shared_files: true,
            ..LifecycleOptions::default()
        },
        &recovery_roots,
    )
    .unwrap();
    assert!(
        fs::read_to_string(roots.codex_home.join("AGENTS.md"))
            .unwrap()
            .contains("<!-- juno:begin -->")
    );
    assert!(roots.state_home.join("manifest.json").exists());
    assert!(!roots.state_home.join("journal.json").exists());
}

#[test]
fn interrupted_manifest_commit_restores_the_previous_manifest() {
    let (_temp, roots) = fixture();
    fs::write(roots.codex_home.join("AGENTS.md"), "before\n").unwrap();
    install(&roots);
    let manifest_before = fs::read(roots.state_home.join("manifest.json")).unwrap();
    fs::write(&roots.source_bin, b"new fake juno binary").unwrap();
    let update_plan = execute_lifecycle(
        LifecycleCommand::Update,
        &LifecycleOptions::default(),
        &roots,
    )
    .unwrap();
    let error = execute_lifecycle(
        LifecycleCommand::Update,
        &LifecycleOptions {
            apply: Some(plan_id(&update_plan).to_string()),
            fault_after_manifest: true,
            ..LifecycleOptions::default()
        },
        &roots,
    )
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("post-manifest transaction fault")
    );
    assert_ne!(
        fs::read(roots.state_home.join("manifest.json")).unwrap(),
        manifest_before
    );

    let recovery_plan = execute_lifecycle(
        LifecycleCommand::Recover {
            strategy: RecoveryStrategy::Rollback,
        },
        &LifecycleOptions::default(),
        &roots,
    )
    .unwrap();
    execute_lifecycle(
        LifecycleCommand::Recover {
            strategy: RecoveryStrategy::Rollback,
        },
        &LifecycleOptions {
            apply: Some(plan_id(&recovery_plan).to_string()),
            ..LifecycleOptions::default()
        },
        &roots,
    )
    .unwrap();
    assert_eq!(
        fs::read(roots.state_home.join("manifest.json")).unwrap(),
        manifest_before
    );
    assert_eq!(fs::read(&roots.install_bin).unwrap(), b"fake juno binary");
    assert!(!roots.state_home.join("journal.json").exists());
}

#[test]
fn recovery_conflicts_need_separate_overwrite_approval() {
    let (_temp, roots) = fixture();
    fs::write(roots.codex_home.join("AGENTS.md"), "before\n").unwrap();
    let install_plan = execute_lifecycle(
        LifecycleCommand::Install,
        &LifecycleOptions::default(),
        &roots,
    )
    .unwrap();
    execute_lifecycle(
        LifecycleCommand::Install,
        &LifecycleOptions {
            apply: Some(plan_id(&install_plan).to_string()),
            allow_shared_files: true,
            fault_after: Some(1),
            ..LifecycleOptions::default()
        },
        &roots,
    )
    .unwrap_err();
    fs::write(roots.codex_home.join("AGENTS.md"), "changed after crash\n").unwrap();
    let recovery_plan = execute_lifecycle(
        LifecycleCommand::Recover {
            strategy: RecoveryStrategy::Rollback,
        },
        &LifecycleOptions::default(),
        &roots,
    )
    .unwrap();
    assert!(recovery_plan.contains("conflicts: 1"));
    let error = execute_lifecycle(
        LifecycleCommand::Recover {
            strategy: RecoveryStrategy::Rollback,
        },
        &LifecycleOptions {
            apply: Some(plan_id(&recovery_plan).to_string()),
            allow_shared_files: true,
            ..LifecycleOptions::default()
        },
        &roots,
    )
    .unwrap_err();
    assert!(error.to_string().contains("--allow-conflict-overwrite"));
    execute_lifecycle(
        LifecycleCommand::Recover {
            strategy: RecoveryStrategy::Rollback,
        },
        &LifecycleOptions {
            apply: Some(plan_id(&recovery_plan).to_string()),
            allow_shared_files: true,
            allow_conflict_overwrite: true,
            ..LifecycleOptions::default()
        },
        &roots,
    )
    .unwrap();
    assert_eq!(
        fs::read_to_string(roots.codex_home.join("AGENTS.md")).unwrap(),
        "before\n"
    );
}

#[test]
fn concurrent_apply_attempts_do_not_corrupt_the_install() {
    let (_temp, roots) = fixture();
    fs::write(roots.codex_home.join("AGENTS.md"), "before\n").unwrap();
    let plan = execute_lifecycle(
        LifecycleCommand::Install,
        &LifecycleOptions::default(),
        &roots,
    )
    .unwrap();
    let id = plan_id(&plan).to_string();
    let barrier = Arc::new(Barrier::new(3));
    let handles = (0..2)
        .map(|_| {
            let roots = roots.clone();
            let id = id.clone();
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                execute_lifecycle(
                    LifecycleCommand::Install,
                    &LifecycleOptions {
                        apply: Some(id),
                        allow_shared_files: true,
                        ..LifecycleOptions::default()
                    },
                    &roots,
                )
            })
        })
        .collect::<Vec<_>>();
    barrier.wait();
    let results = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    let instructions = fs::read_to_string(roots.codex_home.join("AGENTS.md")).unwrap();
    assert_eq!(instructions.matches("<!-- juno:begin -->").count(), 1);
    assert!(!roots.state_home.join("journal.json").exists());
}
