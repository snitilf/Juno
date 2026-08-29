use crate::secure_fs::{FileState, SecureLock, SecureRoot, hex_sha256};
use crate::{Catalog, generate_assets};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::env;
use std::fs::OpenOptions;
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

const CATALOG_SOURCE: &str = include_str!("../config/model-catalog.toml");
const DEFAULT_DOC_LIMIT: usize = 32 * 1024;
const MAX_SHARED_FILE: u64 = 4 * 1024 * 1024;
const MAX_PLAN_FILE: u64 = 16 * 1024 * 1024;
const MAX_JOURNAL_FILE: u64 = 1024 * 1024;

#[derive(Clone, Debug)]
pub struct Roots {
    pub codex_home: PathBuf,
    pub state_home: PathBuf,
    pub install_bin: PathBuf,
    pub source_bin: PathBuf,
}

impl Roots {
    pub fn from_environment() -> Result<Self, CommandError> {
        let home =
            env::var_os("HOME").ok_or_else(|| CommandError::Usage("HOME is not set".into()))?;
        let home = PathBuf::from(home);
        let codex_home = env::var_os("JUNO_CODEX_HOME")
            .or_else(|| env::var_os("CODEX_HOME"))
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".codex"));
        let state_home = env::var_os("JUNO_STATE_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join("Library/Application Support/Juno"));
        let install_bin = env::var_os("JUNO_INSTALL_BIN")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".local/bin/juno"));
        let source_bin = env::var_os("JUNO_SOURCE_BIN")
            .map(PathBuf::from)
            .map(Ok)
            .unwrap_or_else(|| env::current_exe().map_err(CommandError::Io))?;
        Ok(Self {
            codex_home,
            state_home,
            install_bin,
            source_bin,
        })
    }
}

#[derive(Clone, Debug)]
pub enum LifecycleCommand {
    Install,
    Update,
    Uninstall,
    Recover { strategy: RecoveryStrategy },
    Doctor,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RecoveryStrategy {
    Complete,
    Rollback,
}

#[derive(Clone, Debug, Default)]
pub struct LifecycleOptions {
    pub apply: Option<String>,
    pub allow_shared_files: bool,
    pub allow_conflict_overwrite: bool,
    pub json: bool,
    #[doc(hidden)]
    pub fault_after: Option<usize>,
    #[doc(hidden)]
    pub fault_during: Option<usize>,
    #[doc(hidden)]
    pub fault_after_manifest: bool,
}

#[derive(Debug)]
pub enum CommandError {
    Usage(String),
    Blocked(String),
    Io(io::Error),
    Invalid(String),
}

impl std::fmt::Display for CommandError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Usage(message) => write!(formatter, "{message}"),
            Self::Blocked(message) => write!(formatter, "blocked: {message}"),
            Self::Io(error) => write!(formatter, "I/O error: {error}"),
            Self::Invalid(message) => write!(formatter, "invalid state: {message}"),
        }
    }
}

impl std::error::Error for CommandError {}

impl From<io::Error> for CommandError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct Plan {
    schema_version: u32,
    command: String,
    juno_version: String,
    binary_sha256: String,
    bundle_sha256: String,
    catalog_sha256: String,
    recovery_binary_sha256: String,
    backup_root_template: PathBuf,
    codex_home: PathBuf,
    state_home: PathBuf,
    install_bin: PathBuf,
    source_bin: PathBuf,
    operations: Vec<Operation>,
    conflicts: Vec<String>,
    recovery: Option<RecoveryAuthorization>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct RecoveryAuthorization {
    original_plan_id: String,
    strategy: RecoveryStrategy,
    journal_applied: usize,
    journal_in_flight: Option<usize>,
    effective_applied: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct Operation {
    action: OperationAction,
    root: OperationRoot,
    relative: PathBuf,
    expected: Option<FileState>,
    desired_sha256: String,
    mode: u32,
    shared: bool,
    content_utf8: Option<String>,
    source_path: Option<PathBuf>,
    original_utf8: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
enum OperationAction {
    Write,
    Remove,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
enum OperationRoot {
    Codex,
    Install,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct Manifest {
    schema_version: u32,
    juno_version: String,
    binary_sha256: String,
    bundle_sha256: String,
    catalog_sha256: String,
    files: BTreeMap<String, ManagedFile>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct ManagedFile {
    root: OperationRoot,
    relative: PathBuf,
    installed_sha256: String,
    original: Option<FileState>,
    original_utf8: Option<String>,
    installed_utf8: Option<String>,
    shared: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct Journal {
    schema_version: u32,
    plan_id: String,
    recovery_binary_sha256: String,
    recovery_binary: PathBuf,
    applied: usize,
    in_flight: Option<usize>,
    state: String,
    manifest_before: Option<FileState>,
    manifest_backup: Option<PathBuf>,
    manifest_after_sha256: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DoctorReport {
    pub status: String,
    pub codex_home: PathBuf,
    pub effective_instruction_file: PathBuf,
    pub instruction_bytes: usize,
    pub instruction_limit: usize,
    pub instruction_remaining: usize,
    pub current_chain_bytes: usize,
    pub current_chain_truncated: bool,
    pub journal_incomplete: bool,
    pub installed: bool,
    pub managed_files_ok: usize,
    pub managed_files_drifted: Vec<String>,
    pub strict_verification: String,
    pub compatibility: crate::CompatibilityReport,
}

pub fn execute_lifecycle(
    command: LifecycleCommand,
    options: &LifecycleOptions,
    roots: &Roots,
) -> Result<String, CommandError> {
    let state = SecureRoot::create(&roots.state_home)?;
    let journal_exists = state.inspect(Path::new("journal.json"))?.is_some();
    if journal_exists
        && !matches!(
            command,
            LifecycleCommand::Recover { .. } | LifecycleCommand::Doctor
        )
    {
        return Err(CommandError::Blocked(
            "an incomplete transaction requires recovery".into(),
        ));
    }

    match command {
        LifecycleCommand::Install => {
            if let Some(plan_id) = &options.apply {
                apply_plan(plan_id, "install", options, roots, &state)
            } else {
                create_desired_plan("install", false, roots, &state)
            }
        }
        LifecycleCommand::Doctor => {
            let report = doctor(roots, &state)?;
            if options.json {
                serde_json::to_string_pretty(&report)
                    .map_err(|error| CommandError::Invalid(error.to_string()))
            } else {
                Ok(format_doctor(&report))
            }
        }
        LifecycleCommand::Update => {
            if let Some(plan_id) = &options.apply {
                apply_plan(plan_id, "update", options, roots, &state)
            } else {
                create_desired_plan("update", true, roots, &state)
            }
        }
        LifecycleCommand::Uninstall => {
            if let Some(plan_id) = &options.apply {
                apply_plan(plan_id, "uninstall", options, roots, &state)
            } else {
                create_uninstall_plan(roots, &state)
            }
        }
        LifecycleCommand::Recover { strategy } => {
            if let Some(plan_id) = &options.apply {
                apply_recovery_plan(plan_id, options, roots, &state)
            } else {
                create_recovery_plan(strategy, roots, &state)
            }
        }
    }
}

pub(crate) fn ensure_verifier_allowed(roots: &Roots) -> Result<(), CommandError> {
    let state = SecureRoot::create(&roots.state_home)?;
    if state.inspect(Path::new("journal.json"))?.is_some() {
        return Err(CommandError::Blocked(
            "an incomplete transaction requires recovery".into(),
        ));
    }
    Ok(())
}

fn create_desired_plan(
    command: &str,
    require_manifest: bool,
    roots: &Roots,
    state: &SecureRoot,
) -> Result<String, CommandError> {
    let codex = SecureRoot::create(&roots.codex_home)?;
    let install_parent = roots
        .install_bin
        .parent()
        .ok_or_else(|| CommandError::Usage("installation path has no parent".into()))?;
    let install = SecureRoot::create(install_parent)?;
    let install_name = roots
        .install_bin
        .file_name()
        .ok_or_else(|| CommandError::Usage("installation path has no file name".into()))?;
    let source_binary = roots.source_bin.clone();
    let source_content = read_nofollow(&source_binary)?;
    let assets = generate_assets(CATALOG_SOURCE)
        .map_err(|error| CommandError::Invalid(error.to_string()))?;
    let catalog =
        Catalog::parse(CATALOG_SOURCE).map_err(|error| CommandError::Invalid(error.to_string()))?;
    let main = catalog
        .bindings
        .get("main")
        .ok_or_else(|| CommandError::Invalid("main binding is missing".into()))?;
    let main_model = &catalog
        .models
        .get(&main.model)
        .ok_or_else(|| CommandError::Invalid("main model is missing".into()))?
        .id;

    let mut operations = Vec::new();
    let mut conflicts = Vec::new();
    let manifest = read_manifest(state)?;
    if require_manifest && manifest.is_none() {
        return Err(CommandError::Blocked("Juno is not installed".into()));
    }
    let mut build = PlanBuild {
        manifest: &manifest,
        operations: &mut operations,
        conflicts: &mut conflicts,
    };

    let config_name = PathBuf::from("config.toml");
    let config_text = read_shared_utf8(&codex, &config_name, "Codex config")?.unwrap_or_default();
    let override_present = codex
        .inspect(Path::new("AGENTS.override.md"))?
        .is_some_and(|value| value.size > 0);
    let instruction_name = if override_present {
        PathBuf::from("AGENTS.override.md")
    } else {
        PathBuf::from("AGENTS.md")
    };
    let instruction_text =
        read_shared_utf8(&codex, &instruction_name, "effective instruction file")?
            .unwrap_or_default();
    let instruction_new = merge_routing_block(&instruction_text, &assets.routing_block)?;
    let limit = instruction_limit(&config_text)?;
    if instruction_new.len() >= limit {
        return Err(CommandError::Blocked(format!(
            "global instructions use {} of {limit} bytes after Juno and leave no safe project budget",
            instruction_new.len()
        )));
    }
    add_text_operation(
        &codex,
        OperationRoot::Codex,
        &instruction_name,
        instruction_new,
        0o600,
        true,
        &mut build,
    )?;

    let config_new = update_codex_config(&config_text, main_model, &main.effort)?;
    add_text_operation(
        &codex,
        OperationRoot::Codex,
        &config_name,
        config_new,
        0o600,
        true,
        &mut build,
    )?;

    for (name, content) in assets.agents {
        add_text_operation(
            &codex,
            OperationRoot::Codex,
            &PathBuf::from("agents").join(name),
            content,
            0o600,
            false,
            &mut build,
        )?;
    }

    add_source_operation(
        &install,
        Path::new(install_name),
        &source_binary,
        &source_content,
        &mut build,
    )?;

    if !conflicts.is_empty() {
        return Err(CommandError::Blocked(format!(
            "unknown collisions require direction: {}",
            conflicts.join(", ")
        )));
    }

    let plan = Plan {
        schema_version: 1,
        command: command.into(),
        juno_version: crate::VERSION.into(),
        binary_sha256: hex_sha256(&source_content),
        bundle_sha256: release_bundle_sha256(),
        catalog_sha256: hex_sha256(CATALOG_SOURCE.as_bytes()),
        recovery_binary_sha256: hex_sha256(&source_content),
        backup_root_template: roots.state_home.join("transactions/{PLAN_ID}/backups"),
        codex_home: roots.codex_home.clone(),
        state_home: roots.state_home.clone(),
        install_bin: roots.install_bin.clone(),
        source_bin: roots.source_bin.clone(),
        operations,
        conflicts,
        recovery: None,
    };
    save_plan(state, &plan)
}

struct PlanBuild<'a> {
    manifest: &'a Option<Manifest>,
    operations: &'a mut Vec<Operation>,
    conflicts: &'a mut Vec<String>,
}

fn add_text_operation(
    root: &SecureRoot,
    root_kind: OperationRoot,
    relative: &Path,
    desired: String,
    mode: u32,
    shared: bool,
    build: &mut PlanBuild<'_>,
) -> Result<(), CommandError> {
    let expected = root.inspect(relative)?;
    let mode = expected.as_ref().map_or(mode, |state| state.mode);
    let desired_hash = hex_sha256(desired.as_bytes());
    if expected
        .as_ref()
        .is_some_and(|state| state.sha256 == desired_hash)
    {
        return Ok(());
    }
    if expected.is_some()
        && !owned_by_manifest(build.manifest, root_kind, relative, expected.as_ref())
        && !shared
    {
        build.conflicts.push(relative.display().to_string());
        return Ok(());
    }
    let original_utf8 = root
        .read_bounded(relative, MAX_SHARED_FILE)?
        .map(String::from_utf8)
        .transpose()
        .map_err(|_| CommandError::Blocked(format!("{} is not UTF-8", relative.display())))?;
    build.operations.push(Operation {
        action: OperationAction::Write,
        root: root_kind,
        relative: relative.to_path_buf(),
        expected,
        desired_sha256: desired_hash,
        mode,
        shared,
        content_utf8: Some(desired),
        source_path: None,
        original_utf8,
    });
    Ok(())
}

fn add_source_operation(
    root: &SecureRoot,
    relative: &Path,
    source: &Path,
    source_content: &[u8],
    build: &mut PlanBuild<'_>,
) -> Result<(), CommandError> {
    let expected = root.inspect(relative)?;
    let desired_hash = hex_sha256(source_content);
    if expected
        .as_ref()
        .is_some_and(|state| state.sha256 == desired_hash)
    {
        return Ok(());
    }
    if expected.is_some()
        && !owned_by_manifest(
            build.manifest,
            OperationRoot::Install,
            relative,
            expected.as_ref(),
        )
    {
        build.conflicts.push(relative.display().to_string());
        return Ok(());
    }
    build.operations.push(Operation {
        action: OperationAction::Write,
        root: OperationRoot::Install,
        relative: relative.to_path_buf(),
        expected,
        desired_sha256: desired_hash,
        mode: 0o755,
        shared: false,
        content_utf8: None,
        source_path: Some(source.to_path_buf()),
        original_utf8: None,
    });
    Ok(())
}

fn create_uninstall_plan(roots: &Roots, state: &SecureRoot) -> Result<String, CommandError> {
    let manifest = read_manifest(state)?
        .ok_or_else(|| CommandError::Blocked("Juno is not installed".into()))?;
    let codex = SecureRoot::create(&roots.codex_home)?;
    let install = SecureRoot::create(
        roots
            .install_bin
            .parent()
            .ok_or_else(|| CommandError::Usage("installation path has no parent".into()))?,
    )?;
    let mut operations = Vec::new();
    let mut conflicts = Vec::new();

    for (key, managed) in &manifest.files {
        let root = match managed.root {
            OperationRoot::Codex => &codex,
            OperationRoot::Install => &install,
        };
        let Some(current_state) = root.inspect(&managed.relative)? else {
            conflicts.push(format!("{key} is missing"));
            continue;
        };
        if managed.shared {
            let current = read_shared_utf8(root, &managed.relative, key)?
                .ok_or_else(|| CommandError::Blocked(format!("{key} is missing")))?;
            let desired = if managed.relative == Path::new("config.toml") {
                restore_codex_config(
                    &current,
                    managed.installed_utf8.as_deref().unwrap_or(""),
                    managed.original_utf8.as_deref(),
                )
            } else {
                remove_routing_block(&current)
            };
            let desired = match desired {
                Ok(value) => value,
                Err(error) => {
                    conflicts.push(format!("{key}: {error}"));
                    continue;
                }
            };
            if desired.trim().is_empty() && managed.original.is_none() {
                operations.push(remove_operation(managed, current_state));
            } else if hex_sha256(desired.as_bytes()) != current_state.sha256 {
                operations.push(Operation {
                    action: OperationAction::Write,
                    root: managed.root,
                    relative: managed.relative.clone(),
                    expected: Some(current_state),
                    desired_sha256: hex_sha256(desired.as_bytes()),
                    mode: managed.original.as_ref().map_or(0o600, |state| state.mode),
                    shared: true,
                    content_utf8: Some(desired),
                    source_path: None,
                    original_utf8: None,
                });
            }
        } else if current_state.sha256 != managed.installed_sha256 {
            conflicts.push(format!("{key} was changed"));
        } else if let (Some(original), Some(content)) = (&managed.original, &managed.original_utf8)
        {
            operations.push(Operation {
                action: OperationAction::Write,
                root: managed.root,
                relative: managed.relative.clone(),
                expected: Some(current_state),
                desired_sha256: hex_sha256(content.as_bytes()),
                mode: original.mode,
                shared: false,
                content_utf8: Some(content.clone()),
                source_path: None,
                original_utf8: None,
            });
        } else if managed.original.is_none() {
            operations.push(remove_operation(managed, current_state));
        } else {
            conflicts.push(format!("{key} has no restorable baseline"));
        }
    }

    let source_content = read_nofollow(&roots.source_bin)?;
    let plan = Plan {
        schema_version: 1,
        command: "uninstall".into(),
        juno_version: crate::VERSION.into(),
        binary_sha256: hex_sha256(&source_content),
        bundle_sha256: release_bundle_sha256(),
        catalog_sha256: hex_sha256(CATALOG_SOURCE.as_bytes()),
        recovery_binary_sha256: hex_sha256(&source_content),
        backup_root_template: roots.state_home.join("transactions/{PLAN_ID}/backups"),
        codex_home: roots.codex_home.clone(),
        state_home: roots.state_home.clone(),
        install_bin: roots.install_bin.clone(),
        source_bin: roots.source_bin.clone(),
        operations,
        conflicts,
        recovery: None,
    };
    save_plan(state, &plan)
}

fn remove_operation(managed: &ManagedFile, current: FileState) -> Operation {
    Operation {
        action: OperationAction::Remove,
        root: managed.root,
        relative: managed.relative.clone(),
        expected: Some(current),
        desired_sha256: hex_sha256(&[]),
        mode: 0,
        shared: managed.shared,
        content_utf8: None,
        source_path: None,
        original_utf8: None,
    }
}

fn operation_post_matches(operation: &Operation, current: Option<&FileState>) -> bool {
    match operation.action {
        OperationAction::Write => current.is_some_and(|state| {
            state.sha256 == operation.desired_sha256
                && state.mode == operation.mode
                && state.links == 1
                && state.kind == "regular"
                && operation
                    .expected
                    .as_ref()
                    .is_none_or(|preimage| state.uid == preimage.uid && state.gid == preimage.gid)
        }),
        OperationAction::Remove => current.is_none(),
    }
}

fn manifest_matches_hash(current: Option<&FileState>, expected_sha256: &str) -> bool {
    if expected_sha256 == hex_sha256(&[]) {
        current.is_none()
    } else {
        current.is_some_and(|state| state.sha256 == expected_sha256)
    }
}

fn manifest_state_is_known(journal: &Journal, current: Option<&FileState>) -> bool {
    current == journal.manifest_before.as_ref()
        || journal
            .manifest_after_sha256
            .as_deref()
            .is_some_and(|hash| manifest_matches_hash(current, hash))
}

fn validate_journal(
    journal: &Journal,
    roots: &Roots,
    state: &SecureRoot,
) -> Result<(), CommandError> {
    if journal.schema_version != 1
        || journal.plan_id.len() != 64
        || !journal
            .plan_id
            .bytes()
            .all(|value| value.is_ascii_hexdigit())
        || journal.recovery_binary_sha256.len() != 64
        || !journal
            .recovery_binary_sha256
            .bytes()
            .all(|value| value.is_ascii_hexdigit())
    {
        return Err(CommandError::Invalid("journal identity is invalid".into()));
    }
    let recovery_relative = PathBuf::from("transactions")
        .join(&journal.plan_id)
        .join("recovery-juno");
    if journal.recovery_binary != roots.state_home.join(&recovery_relative) {
        return Err(CommandError::Invalid(
            "journal recovery binary path is invalid".into(),
        ));
    }
    let recovery = state
        .inspect(&recovery_relative)?
        .ok_or_else(|| CommandError::Invalid("stored recovery binary is missing".into()))?;
    if recovery.sha256 != journal.recovery_binary_sha256
        || recovery.mode != 0o700
        || recovery.links != 1
        || recovery.kind != "regular"
    {
        return Err(CommandError::Invalid(
            "stored recovery binary is invalid".into(),
        ));
    }
    match (&journal.manifest_before, &journal.manifest_backup) {
        (None, None) => {}
        (Some(before), Some(backup)) => {
            let expected = PathBuf::from("transactions")
                .join(&journal.plan_id)
                .join("manifest-before.json");
            if backup != &expected {
                return Err(CommandError::Invalid(
                    "journal manifest backup path is invalid".into(),
                ));
            }
            let stored = state
                .inspect(backup)?
                .ok_or_else(|| CommandError::Invalid("manifest backup is missing".into()))?;
            if stored.sha256 != before.sha256 || stored.size != before.size {
                return Err(CommandError::Invalid("manifest backup changed".into()));
            }
        }
        _ => {
            return Err(CommandError::Invalid(
                "journal manifest backup state is invalid".into(),
            ));
        }
    }
    let state_is_valid = match journal.state.as_str() {
        "applying" => journal.manifest_after_sha256.is_none(),
        "committing-manifest" | "manifest-committed" => {
            journal.manifest_after_sha256.as_ref().is_some_and(|hash| {
                hash.len() == 64 && hash.bytes().all(|value| value.is_ascii_hexdigit())
            })
        }
        _ => false,
    };
    if !state_is_valid {
        return Err(CommandError::Invalid("journal state is invalid".into()));
    }
    Ok(())
}

fn create_recovery_plan(
    strategy: RecoveryStrategy,
    roots: &Roots,
    state: &SecureRoot,
) -> Result<String, CommandError> {
    let journal = read_journal(state)?
        .ok_or_else(|| CommandError::Blocked("there is no incomplete transaction".into()))?;
    validate_journal(&journal, roots, state)?;
    let source = read_nofollow(&roots.source_bin)?;
    if hex_sha256(&source) != journal.recovery_binary_sha256 {
        return Err(CommandError::Blocked(format!(
            "recovery needs the compatible binary at {}",
            journal.recovery_binary.display()
        )));
    }
    let original = load_plan(state, &journal.plan_id)?;
    if journal.applied > original.operations.len()
        || journal
            .in_flight
            .is_some_and(|index| index != journal.applied || index >= original.operations.len())
    {
        return Err(CommandError::Invalid(
            "journal operation position is invalid".into(),
        ));
    }
    let codex = SecureRoot::create(&roots.codex_home)?;
    let install = SecureRoot::create(
        roots
            .install_bin
            .parent()
            .ok_or_else(|| CommandError::Usage("installation path has no parent".into()))?,
    )?;
    let mut conflicts = Vec::new();
    let mut effective_applied = journal.applied;
    let mut in_flight_conflict = false;
    if let Some(index) = journal.in_flight {
        let operation = &original.operations[index];
        let target = match operation.root {
            OperationRoot::Codex => &codex,
            OperationRoot::Install => &install,
        };
        let current = target.inspect(&operation.relative)?;
        let post_matches = operation_post_matches(operation, current.as_ref());
        if post_matches {
            effective_applied += 1;
        } else if current != operation.expected {
            effective_applied += 1;
            in_flight_conflict = true;
            conflicts.push(format!(
                "{} changed during the interrupted operation",
                operation.relative.display()
            ));
        }
    }
    for (index, operation) in original.operations.iter().enumerate() {
        let target = match operation.root {
            OperationRoot::Codex => &codex,
            OperationRoot::Install => &install,
        };
        let current = target.inspect(&operation.relative)?;
        if index < effective_applied {
            let post_matches = operation_post_matches(operation, current.as_ref());
            let pre_matches = current == operation.expected;
            if !(post_matches
                || pre_matches
                || journal.in_flight == Some(index) && in_flight_conflict)
            {
                conflicts.push(format!(
                    "{} changed after it was applied",
                    operation.relative.display()
                ));
            }
        } else if matches!(strategy, RecoveryStrategy::Complete) && current != operation.expected {
            conflicts.push(format!(
                "{} changed before completion",
                operation.relative.display()
            ));
        }
    }
    let manifest_current = state.inspect(Path::new("manifest.json"))?;
    if !manifest_state_is_known(&journal, manifest_current.as_ref()) {
        conflicts.push("manifest changed during the interrupted transaction".into());
    }
    let operations = match strategy {
        RecoveryStrategy::Complete => original.operations.clone(),
        RecoveryStrategy::Rollback => original.operations[..effective_applied].to_vec(),
    };
    let plan = Plan {
        schema_version: 1,
        command: "recover".into(),
        juno_version: original.juno_version,
        binary_sha256: original.binary_sha256,
        bundle_sha256: original.bundle_sha256,
        catalog_sha256: original.catalog_sha256,
        recovery_binary_sha256: journal.recovery_binary_sha256.clone(),
        backup_root_template: original.backup_root_template,
        codex_home: roots.codex_home.clone(),
        state_home: roots.state_home.clone(),
        install_bin: roots.install_bin.clone(),
        source_bin: journal.recovery_binary.clone(),
        operations,
        conflicts,
        recovery: Some(RecoveryAuthorization {
            original_plan_id: journal.plan_id,
            strategy,
            journal_applied: journal.applied,
            journal_in_flight: journal.in_flight,
            effective_applied,
        }),
    };
    save_plan(state, &plan)
}

fn apply_recovery_plan(
    plan_id: &str,
    options: &LifecycleOptions,
    roots: &Roots,
    state: &SecureRoot,
) -> Result<String, CommandError> {
    let plan = load_plan(state, plan_id)?;
    if plan.command != "recover" {
        return Err(CommandError::Blocked("plan is not a recovery plan".into()));
    }
    let authorization = plan
        .recovery
        .as_ref()
        .ok_or_else(|| CommandError::Invalid("recovery authorization is missing".into()))?;
    let journal = read_journal(state)?
        .ok_or_else(|| CommandError::Blocked("the incomplete transaction is gone".into()))?;
    validate_journal(&journal, roots, state)?;
    if journal.plan_id != authorization.original_plan_id
        || journal.applied != authorization.journal_applied
        || journal.in_flight != authorization.journal_in_flight
    {
        return Err(CommandError::Blocked(
            "the incomplete transaction changed after recovery approval".into(),
        ));
    }
    if !plan.conflicts.is_empty() && !options.allow_conflict_overwrite {
        return Err(CommandError::Blocked(
            "recovery conflicts require --allow-conflict-overwrite".into(),
        ));
    }
    if plan.operations.iter().any(|operation| operation.shared) && !options.allow_shared_files {
        return Err(CommandError::Blocked(
            "shared files require --allow-shared-files".into(),
        ));
    }
    let source = read_nofollow(&roots.source_bin)?;
    if hex_sha256(&source) != journal.recovery_binary_sha256 {
        return Err(CommandError::Blocked(format!(
            "recovery needs the compatible binary at {}",
            journal.recovery_binary.display()
        )));
    }
    let original = load_plan(state, &authorization.original_plan_id)?;
    {
        let _lock = LifecycleLock::acquire(state)?;
        let current_journal = read_journal(state)?
            .ok_or_else(|| CommandError::Blocked("the incomplete transaction is gone".into()))?;
        if current_journal != journal {
            return Err(CommandError::Blocked(
                "the incomplete transaction changed before recovery".into(),
            ));
        }
        rollback_applied(
            &original,
            &journal,
            authorization.effective_applied,
            options.allow_conflict_overwrite,
            roots,
            state,
        )?;
        remove_state_file(state, Path::new("journal.json"))?;
    }
    match authorization.strategy {
        RecoveryStrategy::Rollback => Ok(format!("rolled back plan {}", journal.plan_id)),
        RecoveryStrategy::Complete => {
            apply_plan(&journal.plan_id, &original.command, options, roots, state)
        }
    }
}

fn rollback_applied(
    original: &Plan,
    journal: &Journal,
    effective_applied: usize,
    allow_conflicts: bool,
    roots: &Roots,
    state: &SecureRoot,
) -> Result<(), CommandError> {
    let codex = SecureRoot::create(&roots.codex_home)?;
    let install = SecureRoot::create(
        roots
            .install_bin
            .parent()
            .ok_or_else(|| CommandError::Usage("installation path has no parent".into()))?,
    )?;
    for index in (0..effective_applied).rev() {
        let operation = &original.operations[index];
        let target = match operation.root {
            OperationRoot::Codex => &codex,
            OperationRoot::Install => &install,
        };
        let current = target.inspect(&operation.relative)?;
        if current == operation.expected {
            continue;
        }
        let expected_post = operation_post_matches(operation, current.as_ref());
        if !expected_post && !allow_conflicts {
            return Err(CommandError::Blocked(format!(
                "{} changed after the interrupted operation",
                operation.relative.display()
            )));
        }
        if let Some(original_state) = &operation.expected {
            let backup_relative = PathBuf::from("transactions")
                .join(&journal.plan_id)
                .join("backups")
                .join(index.to_string());
            let backup = state
                .read(&backup_relative)?
                .ok_or_else(|| CommandError::Invalid("transaction backup is missing".into()))?;
            if hex_sha256(&backup) != original_state.sha256 {
                return Err(CommandError::Invalid("transaction backup changed".into()));
            }
            target.write_atomic(
                &operation.relative,
                &backup,
                original_state.mode,
                current.as_ref(),
            )?;
        } else if let Some(current) = current {
            target.remove_atomic(&operation.relative, &current)?;
        }
    }
    restore_manifest(journal, allow_conflicts, state)?;
    Ok(())
}

fn restore_manifest(
    journal: &Journal,
    allow_conflicts: bool,
    state: &SecureRoot,
) -> Result<(), CommandError> {
    let relative = Path::new("manifest.json");
    let current = state.inspect(relative)?;
    if current == journal.manifest_before {
        return Ok(());
    }
    let matches_after = journal
        .manifest_after_sha256
        .as_deref()
        .is_some_and(|hash| manifest_matches_hash(current.as_ref(), hash));
    if !matches_after && !allow_conflicts {
        return Err(CommandError::Blocked(
            "manifest changed after the interrupted transaction".into(),
        ));
    }
    if let Some(before) = &journal.manifest_before {
        let backup_relative = journal
            .manifest_backup
            .as_ref()
            .ok_or_else(|| CommandError::Invalid("manifest backup is missing".into()))?;
        let backup = state
            .read_bounded(backup_relative, before.size)?
            .ok_or_else(|| CommandError::Invalid("manifest backup is missing".into()))?;
        if hex_sha256(&backup) != before.sha256 {
            return Err(CommandError::Invalid("manifest backup changed".into()));
        }
        state.write_atomic(relative, &backup, before.mode, current.as_ref())?;
    } else if let Some(current) = current {
        state.remove_atomic(relative, &current)?;
    }
    Ok(())
}

fn apply_plan(
    plan_id: &str,
    expected_command: &str,
    options: &LifecycleOptions,
    roots: &Roots,
    state: &SecureRoot,
) -> Result<String, CommandError> {
    let plan = load_plan(state, plan_id)?;
    if plan.command != expected_command {
        return Err(CommandError::Blocked("plan command does not match".into()));
    }
    if plan.codex_home != roots.codex_home
        || plan.state_home != roots.state_home
        || plan.install_bin != roots.install_bin
    {
        return Err(CommandError::Blocked(
            "plan roots do not match this invocation".into(),
        ));
    }
    if plan.operations.iter().any(|operation| operation.shared) && !options.allow_shared_files {
        return Err(CommandError::Blocked(
            "shared files require --allow-shared-files".into(),
        ));
    }
    if plan.recovery.is_some() && !plan.conflicts.is_empty() && !options.allow_conflict_overwrite {
        return Err(CommandError::Blocked(
            "conflicts require --allow-conflict-overwrite".into(),
        ));
    }

    let _lock = LifecycleLock::acquire(state)?;
    if state.inspect(Path::new("journal.json"))?.is_some() {
        return Err(CommandError::Blocked(
            "an incomplete transaction requires recovery".into(),
        ));
    }
    let current_binary = read_nofollow(&roots.source_bin)?;
    if hex_sha256(&current_binary) != plan.binary_sha256
        || plan.recovery_binary_sha256 != plan.binary_sha256
    {
        return Err(CommandError::Blocked(
            "Juno binary changed after approval".into(),
        ));
    }
    if release_bundle_sha256() != plan.bundle_sha256 {
        return Err(CommandError::Blocked(
            "release assets changed after approval".into(),
        ));
    }
    if hex_sha256(CATALOG_SOURCE.as_bytes()) != plan.catalog_sha256 {
        return Err(CommandError::Blocked(
            "catalog changed after approval".into(),
        ));
    }

    let codex = SecureRoot::create(&roots.codex_home)?;
    let install_parent = roots.install_bin.parent().unwrap();
    let install = SecureRoot::create(install_parent)?;
    prevalidate_operations(&plan, &codex, &install, &current_binary)?;
    let manifest_relative = Path::new("manifest.json");
    let manifest_before = state.inspect(manifest_relative)?;
    let manifest_before_content = manifest_before
        .as_ref()
        .map(|before| {
            state
                .read_bounded(manifest_relative, before.size)?
                .ok_or_else(|| CommandError::Blocked("manifest disappeared".into()))
        })
        .transpose()?;
    let previous_manifest: Option<Manifest> = manifest_before_content
        .as_deref()
        .map(|content| {
            serde_json::from_slice(content)
                .map_err(|error| CommandError::Invalid(format!("manifest does not parse: {error}")))
        })
        .transpose()?;
    let manifest_backup = if let Some(content) = &manifest_before_content {
        let relative = PathBuf::from("transactions")
            .join(plan_id)
            .join("manifest-before.json");
        match state.inspect(&relative)? {
            Some(existing) if existing.sha256 == hex_sha256(content) => {}
            Some(_) => return Err(CommandError::Blocked("manifest backup collision".into())),
            None => {
                state.write_atomic(&relative, content, 0o600, None)?;
            }
        }
        Some(relative)
    } else {
        None
    };
    let recovery_relative = PathBuf::from("transactions")
        .join(plan_id)
        .join("recovery-juno");
    let recovery_expected = state.inspect(&recovery_relative)?;
    if let Some(recovery_expected) = recovery_expected {
        if recovery_expected.sha256 != plan.recovery_binary_sha256 {
            return Err(CommandError::Blocked("recovery binary collision".into()));
        }
    } else {
        state.write_atomic(&recovery_relative, &current_binary, 0o700, None)?;
    }
    let mut journal = Journal {
        schema_version: 1,
        plan_id: plan_id.into(),
        recovery_binary_sha256: plan.recovery_binary_sha256.clone(),
        recovery_binary: roots.state_home.join(&recovery_relative),
        applied: 0,
        in_flight: None,
        state: "applying".into(),
        manifest_before,
        manifest_backup,
        manifest_after_sha256: None,
    };
    write_json(state, Path::new("journal.json"), &journal)?;

    let mut managed = previous_manifest
        .as_ref()
        .map(|manifest| manifest.files.clone())
        .unwrap_or_default();
    for (index, operation) in plan.operations.iter().enumerate() {
        let target = match operation.root {
            OperationRoot::Codex => &codex,
            OperationRoot::Install => &install,
        };
        if let Some(expected) = &operation.expected {
            let current = target
                .inspect(&operation.relative)?
                .ok_or_else(|| CommandError::Blocked("planned target disappeared".into()))?;
            if &current != expected {
                return Err(CommandError::Blocked(format!(
                    "planned target changed for {}",
                    operation.relative.display()
                )));
            }
            let backup = target
                .read_bounded(&operation.relative, expected.size)?
                .ok_or_else(|| CommandError::Blocked("planned target disappeared".into()))?;
            if hex_sha256(&backup) != expected.sha256 {
                return Err(CommandError::Blocked(format!(
                    "planned target changed for {}",
                    operation.relative.display()
                )));
            }
            let backup_relative = PathBuf::from("transactions")
                .join(plan_id)
                .join("backups")
                .join(index.to_string());
            match state.inspect(&backup_relative)? {
                Some(existing) if existing.sha256 == hex_sha256(&backup) => {}
                Some(_) => {
                    return Err(CommandError::Blocked("transaction backup collision".into()));
                }
                None => {
                    state.write_atomic(&backup_relative, &backup, 0o600, None)?;
                }
            }
        }

        journal.in_flight = Some(index);
        write_json(state, Path::new("journal.json"), &journal)?;

        let key = managed_key(operation.root, &operation.relative);
        match operation.action {
            OperationAction::Write => {
                let content = if let Some(content) = &operation.content_utf8 {
                    content.as_bytes().to_vec()
                } else {
                    operation
                        .source_path
                        .as_ref()
                        .ok_or_else(|| CommandError::Invalid("operation has no source".into()))?;
                    if !matches!(operation.root, OperationRoot::Install) {
                        return Err(CommandError::Invalid(
                            "source-backed operation has an invalid root".into(),
                        ));
                    }
                    current_binary.clone()
                };
                if hex_sha256(&content) != operation.desired_sha256 {
                    return Err(CommandError::Blocked(format!(
                        "planned content changed for {}",
                        operation.relative.display()
                    )));
                }
                let installed = target.write_atomic(
                    &operation.relative,
                    &content,
                    operation.mode,
                    operation.expected.as_ref(),
                )?;
                if options.fault_during == Some(index + 1) {
                    return Err(CommandError::Io(io::Error::other(
                        "injected in-flight transaction fault",
                    )));
                }
                if plan.command == "uninstall" {
                    managed.remove(&key);
                    journal.applied = index + 1;
                    journal.in_flight = None;
                    write_json(state, Path::new("journal.json"), &journal)?;
                    if options.fault_after == Some(journal.applied) {
                        return Err(CommandError::Io(io::Error::other(
                            "injected transaction fault",
                        )));
                    }
                    continue;
                }
                let previous = managed.get(&key);
                let original = previous
                    .map(|file| file.original.clone())
                    .unwrap_or_else(|| operation.expected.clone());
                let original_utf8 = previous
                    .and_then(|file| file.original_utf8.clone())
                    .or_else(|| operation.original_utf8.clone());
                managed.insert(
                    key,
                    ManagedFile {
                        root: operation.root,
                        relative: operation.relative.clone(),
                        installed_sha256: installed.sha256,
                        original,
                        original_utf8,
                        installed_utf8: operation.content_utf8.clone(),
                        shared: operation.shared,
                    },
                );
            }
            OperationAction::Remove => {
                let expected = operation.expected.as_ref().ok_or_else(|| {
                    CommandError::Invalid("remove operation has no preimage".into())
                })?;
                target.remove_atomic(&operation.relative, expected)?;
                if options.fault_during == Some(index + 1) {
                    return Err(CommandError::Io(io::Error::other(
                        "injected in-flight transaction fault",
                    )));
                }
                managed.remove(&key);
            }
        }
        journal.applied = index + 1;
        journal.in_flight = None;
        write_json(state, Path::new("journal.json"), &journal)?;
        if options.fault_after == Some(journal.applied) {
            return Err(CommandError::Io(io::Error::other(
                "injected transaction fault",
            )));
        }
    }

    let manifest_after = if managed.is_empty() {
        None
    } else {
        let manifest = Manifest {
            schema_version: 1,
            juno_version: plan.juno_version,
            binary_sha256: plan.binary_sha256,
            bundle_sha256: plan.bundle_sha256,
            catalog_sha256: plan.catalog_sha256,
            files: managed,
        };
        Some(
            serde_json::to_vec_pretty(&manifest)
                .map_err(|error| CommandError::Invalid(error.to_string()))?,
        )
    };
    journal.manifest_after_sha256 = Some(
        manifest_after
            .as_deref()
            .map(hex_sha256)
            .unwrap_or_else(|| hex_sha256(&[])),
    );
    journal.state = "committing-manifest".into();
    write_json(state, Path::new("journal.json"), &journal)?;
    let current_manifest = state.inspect(manifest_relative)?;
    if current_manifest != journal.manifest_before {
        return Err(CommandError::Blocked(
            "manifest changed during the transaction".into(),
        ));
    }
    if let Some(content) = &manifest_after {
        state.write_atomic(manifest_relative, content, 0o600, current_manifest.as_ref())?;
    } else if let Some(current) = current_manifest {
        state.remove_atomic(manifest_relative, &current)?;
    }
    if options.fault_after_manifest {
        return Err(CommandError::Io(io::Error::other(
            "injected post-manifest transaction fault",
        )));
    }
    journal.state = "manifest-committed".into();
    write_json(state, Path::new("journal.json"), &journal)?;
    remove_state_file(state, Path::new("journal.json"))?;
    let mut output = format!("applied plan {plan_id}");
    if matches!(plan.command.as_str(), "install" | "update") {
        let parent = roots.install_bin.parent().unwrap();
        if !path_contains(parent) {
            output.push_str(&format!(
                "\n{} is not on PATH. Add it to PATH or run {} directly.",
                parent.display(),
                roots.install_bin.display()
            ));
        }
    }
    Ok(output)
}

fn prevalidate_operations(
    plan: &Plan,
    codex: &SecureRoot,
    install: &SecureRoot,
    source_binary: &[u8],
) -> Result<(), CommandError> {
    for operation in &plan.operations {
        let target = match operation.root {
            OperationRoot::Codex => codex,
            OperationRoot::Install => install,
        };
        if target.inspect(&operation.relative)? != operation.expected {
            return Err(CommandError::Blocked(format!(
                "planned target changed for {}",
                operation.relative.display()
            )));
        }
        if matches!(operation.action, OperationAction::Write) {
            let desired_sha256 = if let Some(content) = &operation.content_utf8 {
                hex_sha256(content.as_bytes())
            } else {
                operation
                    .source_path
                    .as_ref()
                    .ok_or_else(|| CommandError::Invalid("operation has no source".into()))?;
                if !matches!(operation.root, OperationRoot::Install) {
                    return Err(CommandError::Invalid(
                        "source-backed operation has an invalid root".into(),
                    ));
                }
                hex_sha256(source_binary)
            };
            if desired_sha256 != operation.desired_sha256 {
                return Err(CommandError::Blocked(format!(
                    "planned content changed for {}",
                    operation.relative.display()
                )));
            }
        }
    }
    Ok(())
}

fn doctor(roots: &Roots, state: &SecureRoot) -> Result<DoctorReport, CommandError> {
    let codex = SecureRoot::create(&roots.codex_home)?;
    let config =
        read_shared_utf8(&codex, Path::new("config.toml"), "Codex config")?.unwrap_or_default();
    let override_present = codex
        .inspect(Path::new("AGENTS.override.md"))?
        .is_some_and(|value| value.size > 0);
    let effective_relative = if override_present {
        PathBuf::from("AGENTS.override.md")
    } else {
        PathBuf::from("AGENTS.md")
    };
    let instruction_bytes = codex
        .inspect(&effective_relative)?
        .map(|value| {
            usize::try_from(value.size)
                .map_err(|_| CommandError::Blocked("instruction file is too large".into()))
        })
        .transpose()?
        .unwrap_or(0);
    let instruction_limit = instruction_limit(&config)?;
    let (current_chain_bytes, current_chain_truncated) =
        current_instruction_chain(instruction_bytes, instruction_limit, &config)?;
    let mut ok = 0;
    let mut drifted = Vec::new();
    let manifest = read_manifest(state)?;
    if let Some(manifest) = &manifest {
        let install_parent = roots.install_bin.parent().unwrap();
        let install = SecureRoot::create(install_parent)?;
        for (key, file) in &manifest.files {
            let root = match file.root {
                OperationRoot::Codex => &codex,
                OperationRoot::Install => &install,
            };
            match root.inspect(&file.relative)? {
                Some(current) if current.sha256 == file.installed_sha256 => ok += 1,
                _ => drifted.push(key.clone()),
            }
        }
    }
    let journal_incomplete = state.inspect(Path::new("journal.json"))?.is_some();
    let status = if journal_incomplete || !drifted.is_empty() || current_chain_truncated {
        "attention"
    } else if manifest.is_some() {
        "installed"
    } else {
        "not-installed"
    };
    let compatibility = crate::check_compatibility();
    Ok(DoctorReport {
        status: status.into(),
        codex_home: roots.codex_home.clone(),
        effective_instruction_file: roots.codex_home.join(effective_relative),
        instruction_bytes,
        instruction_limit,
        instruction_remaining: instruction_limit.saturating_sub(current_chain_bytes),
        current_chain_bytes,
        current_chain_truncated,
        journal_incomplete,
        installed: manifest.is_some(),
        managed_files_ok: ok,
        managed_files_drifted: drifted,
        strict_verification: crate::verifier::strict_status(roots),
        compatibility,
    })
}

fn format_doctor(report: &DoctorReport) -> String {
    format!(
        "status: {}\neffective instructions: {}\ninstruction bytes: {}/{}\ncurrent chain bytes: {}\ninstruction bytes remaining: {}\ncurrent chain truncated: {}\ninstalled: {}\nmanaged files ok: {}\nmanaged files drifted: {}\ncompatibility: {}\nstrict verification: {}",
        report.status,
        report.effective_instruction_file.display(),
        report.instruction_bytes,
        report.instruction_limit,
        report.current_chain_bytes,
        report.instruction_remaining,
        report.current_chain_truncated,
        report.installed,
        report.managed_files_ok,
        report.managed_files_drifted.len(),
        report.compatibility.status,
        report.strict_verification,
    )
}

fn merge_routing_block(current: &str, block: &str) -> Result<String, CommandError> {
    let start = current
        .match_indices(crate::ROUTING_START)
        .collect::<Vec<_>>();
    let end = current
        .match_indices(crate::ROUTING_END)
        .collect::<Vec<_>>();
    match (start.as_slice(), end.as_slice()) {
        ([], []) => {
            let separator = if current.is_empty() || current.ends_with("\n\n") {
                ""
            } else if current.ends_with('\n') {
                "\n"
            } else {
                "\n\n"
            };
            Ok(format!("{current}{separator}{block}"))
        }
        ([(start, _)], [(end, _)]) if start < end => {
            let after = end + crate::ROUTING_END.len();
            let mut merged = String::new();
            merged.push_str(&current[..*start]);
            merged.push_str(block.trim_end());
            merged.push_str(&current[after..]);
            if !merged.ends_with('\n') {
                merged.push('\n');
            }
            Ok(merged)
        }
        _ => Err(CommandError::Blocked(
            "instruction file has malformed Juno markers".into(),
        )),
    }
}

fn remove_routing_block(current: &str) -> Result<String, CommandError> {
    let starts = current
        .match_indices(crate::ROUTING_START)
        .collect::<Vec<_>>();
    let ends = current
        .match_indices(crate::ROUTING_END)
        .collect::<Vec<_>>();
    let ([(start, _)], [(end, _)]) = (starts.as_slice(), ends.as_slice()) else {
        return Err(CommandError::Blocked(
            "instruction file has missing or duplicate Juno markers".into(),
        ));
    };
    if start >= end {
        return Err(CommandError::Blocked(
            "instruction file has reversed Juno markers".into(),
        ));
    }
    let mut after = end + crate::ROUTING_END.len();
    if current[after..].starts_with('\n') {
        after += 1;
    }
    let mut before = *start;
    if before >= 2 && &current[before - 2..before] == "\n\n" {
        before -= 1;
    }
    let mut result = format!("{}{}", &current[..before], &current[after..]);
    while result.ends_with("\n\n\n") {
        result.pop();
    }
    Ok(result)
}

fn update_codex_config(current: &str, model: &str, effort: &str) -> Result<String, CommandError> {
    if !current.trim().is_empty() {
        toml::from_str::<toml::Value>(current).map_err(|error| {
            CommandError::Blocked(format!("Codex config does not parse: {error}"))
        })?;
    }
    let mut updated = set_key(current, None, "model", &toml_string(model))?;
    updated = set_key(
        &updated,
        None,
        "model_reasoning_effort",
        &toml_string(effort),
    )?;
    let parsed: toml::Value = toml::from_str(&updated).map_err(|error| {
        CommandError::Invalid(format!("generated Codex config does not parse: {error}"))
    })?;
    if parsed
        .get("agents")
        .and_then(|value| value.get("enabled"))
        .and_then(toml::Value::as_bool)
        == Some(false)
    {
        updated = set_key(&updated, Some("agents"), "enabled", "true")?;
    }
    toml::from_str::<toml::Value>(&updated).map_err(|error| {
        CommandError::Invalid(format!("generated Codex config does not parse: {error}"))
    })?;
    Ok(updated)
}

fn restore_codex_config(
    current: &str,
    installed: &str,
    original: Option<&str>,
) -> Result<String, CommandError> {
    toml::from_str::<toml::Value>(current)
        .map_err(|error| CommandError::Blocked(format!("Codex config does not parse: {error}")))?;
    let mut output = current.to_string();
    for (table, key) in [
        (None, "model"),
        (None, "model_reasoning_effort"),
        (Some("agents"), "enabled"),
    ] {
        let installed_value = raw_key_value(installed, table, key)?;
        let Some(installed_value) = installed_value else {
            continue;
        };
        let current_value = raw_key_value(&output, table, key)?;
        if current_value.as_deref() != Some(installed_value.as_str()) {
            return Err(CommandError::Blocked(format!(
                "owned config key {}{} was changed",
                table.map_or(String::new(), |value| format!("{value}.")),
                key
            )));
        }
        let original_value = original
            .map(|source| raw_key_value(source, table, key))
            .transpose()?
            .flatten();
        output = set_optional_key(&output, table, key, original_value.as_deref())?;
    }
    if !output.trim().is_empty() {
        toml::from_str::<toml::Value>(&output).map_err(|error| {
            CommandError::Invalid(format!("restored Codex config does not parse: {error}"))
        })?;
    }
    Ok(output)
}

fn set_key(
    source: &str,
    table: Option<&str>,
    key: &str,
    value: &str,
) -> Result<String, CommandError> {
    let lines = source.lines().collect::<Vec<_>>();
    let mut section = None::<String>;
    let mut matches = Vec::new();
    let mut table_end = lines.len();
    let mut table_start = None;
    for (index, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            if table_start.is_some() && table_end == lines.len() {
                table_end = index;
            }
            section = Some(trimmed.trim_matches(&['[', ']'][..]).to_string());
            if section.as_deref() == table {
                table_start = Some(index);
            }
            continue;
        }
        if section.as_deref() == table && key_on_line(trimmed, key) {
            matches.push(index);
        }
    }
    if matches.len() > 1 {
        return Err(CommandError::Blocked(format!("duplicate {key} keys")));
    }
    let replacement = format!("{key} = {value}");
    let mut output = lines
        .iter()
        .map(|line| (*line).to_string())
        .collect::<Vec<_>>();
    if let Some(index) = matches.first().copied() {
        let comment = trailing_comment(lines[index]);
        output[index] = if comment.is_empty() {
            replacement
        } else {
            format!("{replacement} {comment}")
        };
    } else if let Some(table) = table {
        if let Some(start) = table_start {
            output.insert(table_end.max(start + 1), replacement);
        } else {
            if !output.is_empty() && !output.last().unwrap().is_empty() {
                output.push(String::new());
            }
            output.push(format!("[{table}]"));
            output.push(replacement);
        }
    } else {
        let first_table = output
            .iter()
            .position(|line| line.trim_start().starts_with('['))
            .unwrap_or(output.len());
        output.insert(first_table, replacement);
    }
    let mut result = output.join("\n");
    result.push('\n');
    Ok(result)
}

fn set_optional_key(
    source: &str,
    table: Option<&str>,
    key: &str,
    value: Option<&str>,
) -> Result<String, CommandError> {
    if let Some(value) = value {
        return set_key(source, table, key, value);
    }
    let mut section = None::<String>;
    let mut matches = Vec::new();
    for (index, line) in source.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            section = Some(trimmed.trim_matches(&['[', ']'][..]).to_string());
        } else if section.as_deref() == table && key_on_line(trimmed, key) {
            matches.push(index);
        }
    }
    if matches.len() > 1 {
        return Err(CommandError::Blocked(format!("duplicate {key} keys")));
    }
    let Some(remove) = matches.first().copied() else {
        return Ok(source.to_string());
    };
    let mut lines = source.lines().map(str::to_string).collect::<Vec<_>>();
    lines.remove(remove);
    let mut result = lines.join("\n");
    if !result.is_empty() {
        result.push('\n');
    }
    Ok(result)
}

fn raw_key_value(
    source: &str,
    table: Option<&str>,
    key: &str,
) -> Result<Option<String>, CommandError> {
    let mut section = None::<String>;
    let mut values = Vec::new();
    for line in source.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            section = Some(trimmed.trim_matches(&['[', ']'][..]).to_string());
        } else if section.as_deref() == table && key_on_line(trimmed, key) {
            let value = trimmed
                .split_once('=')
                .map(|(_, value)| value)
                .unwrap_or("");
            let comment = trailing_comment(value);
            let raw = if comment.is_empty() {
                value
            } else {
                &value[..value.len() - comment.len()]
            };
            values.push(raw.trim().to_string());
        }
    }
    if values.len() > 1 {
        return Err(CommandError::Blocked(format!("duplicate {key} keys")));
    }
    Ok(values.pop())
}

fn key_on_line(line: &str, key: &str) -> bool {
    line.strip_prefix(key)
        .is_some_and(|rest| rest.trim_start().starts_with('='))
}

fn trailing_comment(line: &str) -> &str {
    let mut quote = None;
    let mut escaped = false;
    for (index, character) in line.char_indices() {
        if escaped {
            escaped = false;
        } else if character == '\\' && quote == Some('"') {
            escaped = true;
        } else if matches!(character, '"' | '\'') {
            if quote == Some(character) {
                quote = None;
            } else if quote.is_none() {
                quote = Some(character);
            }
        } else if character == '#' && quote.is_none() {
            return &line[index..];
        }
    }
    ""
}

fn toml_string(value: &str) -> String {
    format!("{:?}", value)
}

fn shell_quote(path: &Path) -> String {
    let value = path.display().to_string();
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn save_plan(state: &SecureRoot, plan: &Plan) -> Result<String, CommandError> {
    let canonical =
        serde_json::to_vec(plan).map_err(|error| CommandError::Invalid(error.to_string()))?;
    let plan_id = hex_sha256(&canonical);
    let pretty = serde_json::to_vec_pretty(plan)
        .map_err(|error| CommandError::Invalid(error.to_string()))?;
    let relative = PathBuf::from("plans").join(format!("{plan_id}.json"));
    match state.inspect(&relative)? {
        Some(existing) if existing.sha256 == hex_sha256(&pretty) => {}
        Some(_) => return Err(CommandError::Invalid("plan ID collision".into())),
        None => {
            state.write_atomic(&relative, &pretty, 0o600, None)?;
        }
    }
    let command = match plan.recovery.as_ref().map(|value| value.strategy) {
        Some(RecoveryStrategy::Complete) => "recover --strategy complete",
        Some(RecoveryStrategy::Rollback) => "recover --strategy rollback",
        None => &plan.command,
    };
    let mut output = format!(
        "plan: {plan_id}\nbinary: {}\nbundle: {}\ncatalog: {}\noperations: {}\nconflicts: {}",
        plan.binary_sha256,
        plan.bundle_sha256,
        plan.catalog_sha256,
        plan.operations.len(),
        plan.conflicts.len(),
    );
    for (index, operation) in plan.operations.iter().enumerate() {
        let root = match operation.root {
            OperationRoot::Codex => &plan.codex_home,
            OperationRoot::Install => plan.install_bin.parent().unwrap(),
        };
        let preimage = operation
            .expected
            .as_ref()
            .map(|state| state.sha256.as_str())
            .unwrap_or("absent");
        output.push_str(&format!(
            "\n{}: {:?} {}\n  preimage: {}\n  desired: {}\n  mode: {:o}\n  shared: {}\n  backup: {}",
            index + 1,
            operation.action,
            root.join(&operation.relative).display(),
            preimage,
            operation.desired_sha256,
            operation.mode,
            operation.shared,
            plan.state_home
                .join("transactions")
                .join(&plan_id)
                .join("backups")
                .join(index.to_string())
                .display(),
        ));
    }
    for conflict in &plan.conflicts {
        output.push_str(&format!("\nconflict: {conflict}"));
    }
    output.push_str(&format!(
        "\napply: {} {} --apply {plan_id}{}{}",
        shell_quote(&plan.source_bin),
        command,
        if plan.operations.iter().any(|operation| operation.shared) {
            " --allow-shared-files"
        } else {
            ""
        },
        if plan.recovery.is_some() && !plan.conflicts.is_empty() {
            " --allow-conflict-overwrite"
        } else {
            ""
        }
    ));
    Ok(output)
}

fn load_plan(state: &SecureRoot, plan_id: &str) -> Result<Plan, CommandError> {
    if plan_id.len() != 64 || !plan_id.bytes().all(|value| value.is_ascii_hexdigit()) {
        return Err(CommandError::Usage(
            "plan ID must be a SHA-256 value".into(),
        ));
    }
    let relative = PathBuf::from("plans").join(format!("{plan_id}.json"));
    let content = state
        .read_bounded(&relative, MAX_PLAN_FILE)?
        .ok_or_else(|| CommandError::Blocked("plan does not exist".into()))?;
    let plan: Plan = serde_json::from_slice(&content)
        .map_err(|error| CommandError::Invalid(format!("plan does not parse: {error}")))?;
    let canonical =
        serde_json::to_vec(&plan).map_err(|error| CommandError::Invalid(error.to_string()))?;
    if hex_sha256(&canonical) != plan_id {
        return Err(CommandError::Blocked(
            "plan content does not match its ID".into(),
        ));
    }
    Ok(plan)
}

fn write_json<T: Serialize>(
    state: &SecureRoot,
    relative: &Path,
    value: &T,
) -> Result<(), CommandError> {
    let content = serde_json::to_vec_pretty(value)
        .map_err(|error| CommandError::Invalid(error.to_string()))?;
    let expected = state.inspect(relative)?;
    state.write_atomic(relative, &content, 0o600, expected.as_ref())?;
    Ok(())
}

fn read_manifest(state: &SecureRoot) -> Result<Option<Manifest>, CommandError> {
    let relative = Path::new("manifest.json");
    let Some(file_state) = state.inspect(relative)? else {
        return Ok(None);
    };
    if file_state.size > MAX_SHARED_FILE {
        return Err(CommandError::Blocked("manifest is too large".into()));
    }
    let content = state
        .read_bounded(relative, file_state.size)?
        .ok_or_else(|| CommandError::Blocked("manifest disappeared".into()))?;
    serde_json::from_slice(&content)
        .map(Some)
        .map_err(|error| CommandError::Invalid(format!("manifest does not parse: {error}")))
}

fn read_journal(state: &SecureRoot) -> Result<Option<Journal>, CommandError> {
    state
        .read_bounded(Path::new("journal.json"), MAX_JOURNAL_FILE)?
        .map(|content| {
            serde_json::from_slice(&content)
                .map_err(|error| CommandError::Invalid(format!("journal does not parse: {error}")))
        })
        .transpose()
}

fn remove_state_file(state: &SecureRoot, relative: &Path) -> Result<(), CommandError> {
    let expected = state
        .inspect(relative)?
        .ok_or_else(|| CommandError::Blocked("state file disappeared".into()))?;
    state.remove_atomic(relative, &expected)?;
    Ok(())
}

fn read_nofollow(path: &Path) -> Result<Vec<u8>, CommandError> {
    let mut options = OpenOptions::new();
    options.read(true).custom_flags(libc::O_NOFOLLOW_ANY);
    let mut file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.nlink() > 1 {
        return Err(CommandError::Blocked(format!(
            "unsafe source file: {}",
            path.display()
        )));
    }
    let mut content = Vec::new();
    file.read_to_end(&mut content)?;
    Ok(content)
}

fn read_shared_utf8(
    root: &SecureRoot,
    relative: &Path,
    label: &str,
) -> Result<Option<String>, CommandError> {
    let Some(state) = root.inspect(relative)? else {
        return Ok(None);
    };
    if state.size > MAX_SHARED_FILE {
        return Err(CommandError::Blocked(format!(
            "{label} exceeds the shared file limit"
        )));
    }
    let content = root
        .read_bounded(relative, MAX_SHARED_FILE)?
        .ok_or_else(|| CommandError::Blocked(format!("{label} disappeared")))?;
    String::from_utf8(content)
        .map(Some)
        .map_err(|_| CommandError::Blocked(format!("{label} is not UTF-8")))
}

pub(crate) fn release_bundle_sha256() -> String {
    let parts = [
        crate::VERSION.as_bytes(),
        CATALOG_SOURCE.as_bytes(),
        include_bytes!("../config/routing-defaults.toml").as_slice(),
        include_bytes!("../config/compatibility.toml").as_slice(),
        include_bytes!("../schemas/evidence-packet.schema.json").as_slice(),
        include_bytes!("../schemas/verifier-result.schema.json").as_slice(),
        include_bytes!("../templates/instructions/routing-policy.md").as_slice(),
        include_bytes!("../templates/agents/scout.md").as_slice(),
        include_bytes!("../templates/agents/surveyor.md").as_slice(),
        include_bytes!("../templates/agents/mech_executor.md").as_slice(),
        include_bytes!("../templates/agents/executor.md").as_slice(),
        include_bytes!("../templates/agents/light_verifier.md").as_slice(),
        include_bytes!("../templates/agents/verifier.md").as_slice(),
        include_bytes!("../templates/agents/heavy_verifier.md").as_slice(),
        include_bytes!("../templates/agents/security_executor.md").as_slice(),
    ];
    let mut record = Vec::new();
    for part in parts {
        record.extend_from_slice(&(part.len() as u64).to_be_bytes());
        record.extend_from_slice(part);
    }
    hex_sha256(&record)
}

fn instruction_limit(config: &str) -> Result<usize, CommandError> {
    if config.trim().is_empty() {
        return Ok(DEFAULT_DOC_LIMIT);
    }
    let parsed: toml::Value = toml::from_str(config)
        .map_err(|error| CommandError::Blocked(format!("Codex config does not parse: {error}")))?;
    let Some(value) = parsed.get("project_doc_max_bytes") else {
        return Ok(DEFAULT_DOC_LIMIT);
    };
    let value = value.as_integer().ok_or_else(|| {
        CommandError::Blocked("project_doc_max_bytes must be a positive integer".into())
    })?;
    usize::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| {
            CommandError::Blocked("project_doc_max_bytes must be a positive integer".into())
        })
}

fn current_instruction_chain(
    global_bytes: usize,
    limit: usize,
    config: &str,
) -> Result<(usize, bool), CommandError> {
    let current = env::current_dir()?;
    instruction_chain_at(&current, global_bytes, limit, config)
}

fn instruction_chain_at(
    current: &Path,
    global_bytes: usize,
    limit: usize,
    config: &str,
) -> Result<(usize, bool), CommandError> {
    let current = current.canonicalize()?;
    let mut total = global_bytes.min(limit);
    let mut truncated = global_bytes > limit;
    let root = project_root(&current, config)?;
    let fallback_names = project_doc_fallback_names(config)?;
    let relative = current.strip_prefix(&root).map_err(|_| {
        CommandError::Blocked("the current directory is outside its Git root".into())
    })?;
    let mut directories = vec![root.clone()];
    let mut next = root;
    for component in relative.components() {
        next.push(component);
        directories.push(next.clone());
    }

    for directory in directories {
        let Some(bytes) = instruction_file_bytes(&directory, &fallback_names)? else {
            continue;
        };
        let separator = usize::from(total > 0) * 2;
        let required = separator.saturating_add(bytes);
        let remaining = limit.saturating_sub(total);
        if required > remaining {
            total = limit;
            truncated = true;
            break;
        }
        total += required;
    }
    Ok((total, truncated))
}

fn project_root(current: &Path, config: &str) -> Result<PathBuf, CommandError> {
    let markers = project_root_markers(config)?;
    for directory in current.ancestors() {
        for marker in &markers {
            if fs_entry_exists(&directory.join(marker))? {
                return Ok(directory.to_path_buf());
            }
        }
    }
    Ok(current.to_path_buf())
}

fn project_root_markers(config: &str) -> Result<Vec<String>, CommandError> {
    config_name_array(config, "project_root_markers", &[".git"])
}

fn project_doc_fallback_names(config: &str) -> Result<Vec<String>, CommandError> {
    config_name_array(config, "project_doc_fallback_filenames", &[])
}

fn config_name_array(
    config: &str,
    key: &str,
    default: &[&str],
) -> Result<Vec<String>, CommandError> {
    if config.trim().is_empty() {
        return Ok(default.iter().map(|value| (*value).to_string()).collect());
    }
    let parsed: toml::Value = toml::from_str(config)
        .map_err(|error| CommandError::Blocked(format!("Codex config does not parse: {error}")))?;
    let Some(value) = parsed.get(key) else {
        return Ok(default.iter().map(|value| (*value).to_string()).collect());
    };
    let values = value
        .as_array()
        .ok_or_else(|| CommandError::Blocked(format!("{key} must be an array of names")))?;
    values
        .iter()
        .map(|value| {
            let name = value
                .as_str()
                .ok_or_else(|| CommandError::Blocked(format!("{key} must contain only names")))?;
            let mut components = Path::new(name).components();
            if !matches!(components.next(), Some(std::path::Component::Normal(_)))
                || components.next().is_some()
            {
                return Err(CommandError::Blocked(format!(
                    "{key} must contain simple file names"
                )));
            }
            Ok(name.to_string())
        })
        .collect()
}

fn fs_entry_exists(path: &Path) -> Result<bool, CommandError> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn instruction_file_bytes(
    directory: &Path,
    fallback_names: &[String],
) -> Result<Option<usize>, CommandError> {
    let names = ["AGENTS.override.md", "AGENTS.md"]
        .into_iter()
        .map(str::to_string)
        .chain(fallback_names.iter().cloned());
    for name in names {
        let path = directory.join(name);
        let metadata = match std::fs::metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        if !metadata.is_file() {
            continue;
        }
        let bytes = usize::try_from(metadata.len())
            .map_err(|_| CommandError::Blocked("instruction file is too large".into()))?;
        if bytes > 0 {
            return Ok(Some(bytes));
        }
    }
    Ok(None)
}

fn managed_key(root: OperationRoot, relative: &Path) -> String {
    format!("{:?}:{}", root, relative.display())
}

fn path_contains(directory: &Path) -> bool {
    env::split_paths(&env::var_os("PATH").unwrap_or_default()).any(|path| path == directory)
}

fn owned_by_manifest(
    manifest: &Option<Manifest>,
    root: OperationRoot,
    relative: &Path,
    current: Option<&FileState>,
) -> bool {
    manifest
        .as_ref()
        .and_then(|manifest| manifest.files.get(&managed_key(root, relative)))
        .zip(current)
        .is_some_and(|(file, current)| file.installed_sha256 == current.sha256)
}

struct LifecycleLock {
    _file: SecureLock,
}

impl LifecycleLock {
    fn acquire(state: &SecureRoot) -> Result<Self, CommandError> {
        let file = state.lock(Path::new("lifecycle.lock")).map_err(|error| {
            if error.raw_os_error() == Some(libc::EWOULDBLOCK) {
                CommandError::Blocked("another lifecycle command is running".into())
            } else {
                CommandError::Io(error)
            }
        })?;
        Ok(Self { _file: file })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::process::Command;

    #[test]
    fn routing_markers_are_replaced_without_touching_other_text() {
        let first =
            merge_routing_block("user\n", "<!-- juno:begin -->\nold\n<!-- juno:end -->\n").unwrap();
        let second =
            merge_routing_block(&first, "<!-- juno:begin -->\nnew\n<!-- juno:end -->\n").unwrap();
        assert!(second.starts_with("user\n\n"));
        assert!(second.contains("\nnew\n"));
        assert!(!second.contains("\nold\n"));
    }

    #[test]
    fn config_edit_preserves_comments_and_other_keys() {
        let input = "approval_policy = \"never\"\nmodel = \"old\" # keep\n\n[agents]\nenabled = false # keep too\n";
        let output = update_codex_config(input, "new", "high").unwrap();
        assert!(output.contains("approval_policy = \"never\""));
        assert!(output.contains("model = \"new\" # keep"));
        assert!(output.contains("enabled = true # keep too"));
        assert!(toml::from_str::<toml::Value>(&output).is_ok());
    }

    #[test]
    fn instruction_chain_uses_one_file_per_project_directory() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let status = Command::new("git")
            .args(["init", "-q"])
            .current_dir(&root)
            .status()
            .unwrap();
        assert!(status.success());
        fs::write(root.join("AGENTS.md"), b"root").unwrap();
        fs::write(root.join("FALLBACK.md"), b"ignored").unwrap();
        let child = root.join("child");
        fs::create_dir(&child).unwrap();
        fs::write(child.join("AGENTS.md"), b"ignored too").unwrap();
        fs::write(child.join("AGENTS.override.md"), b"override").unwrap();
        let config = "project_doc_fallback_filenames = [\"FALLBACK.md\"]\n";

        let result = instruction_chain_at(&child, 10, 100, config).unwrap();

        assert_eq!(result, (10 + 2 + 4 + 2 + 8, false));
    }

    #[test]
    fn instruction_chain_reports_exact_exhaustion() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let status = Command::new("git")
            .args(["init", "-q"])
            .current_dir(&root)
            .status()
            .unwrap();
        assert!(status.success());
        fs::write(root.join("AGENTS.md"), b"project").unwrap();

        assert_eq!(instruction_chain_at(&root, 7, 16, "").unwrap(), (16, false));
        assert_eq!(instruction_chain_at(&root, 8, 16, "").unwrap(), (16, true));
    }

    #[test]
    fn instruction_chain_checks_current_directory_without_a_root() {
        let temp = tempfile::tempdir().unwrap();
        let directory = temp.path().canonicalize().unwrap();
        fs::write(directory.join("AGENTS.md"), b"local").unwrap();

        assert_eq!(
            instruction_chain_at(&directory, 4, 32, "").unwrap(),
            (4 + 2 + 5, false)
        );
    }

    #[test]
    fn instruction_chain_uses_configured_root_markers() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        fs::write(root.join("WORKSPACE"), b"").unwrap();
        fs::write(root.join("AGENTS.md"), b"root").unwrap();
        let child = root.join("child");
        fs::create_dir(&child).unwrap();
        fs::write(child.join("AGENTS.md"), b"child").unwrap();
        let config = "project_root_markers = [\"WORKSPACE\"]\n";

        assert_eq!(
            instruction_chain_at(&child, 3, 32, config).unwrap(),
            (3 + 2 + 4 + 2 + 5, false)
        );
    }
}
