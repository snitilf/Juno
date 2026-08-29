use crate::secure_fs::{SecureRoot, hex_sha256};
use crate::{Catalog, Roots, Snapshot, create_snapshot};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;

const CATALOG_SOURCE: &str = include_str!("../config/model-catalog.toml");
const COMPATIBILITY_SOURCE: &str = include_str!("../config/compatibility.toml");
const ROUTING_DEFAULTS_SOURCE: &str = include_str!("../config/routing-defaults.toml");
const RESULT_SCHEMA: &str = include_str!("../schemas/verifier-result.schema.json");
const OUTPUT_LIMIT: u64 = 4 * 1024 * 1024;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidencePacket {
    pub requirement: String,
    pub paths: Vec<String>,
    pub claimed_checks: Vec<String>,
    pub constraints: Vec<String>,
}

#[derive(Debug, Serialize)]
struct FrozenEvidencePacket<'a> {
    snapshot_sha256: &'a str,
    requirement: &'a str,
    paths: &'a [String],
    claimed_checks: &'a [String],
    constraints: &'a [String],
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct VerifierResult {
    verdict: Verdict,
    material_findings: Vec<MaterialFinding>,
    unverified_assumptions: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
enum Verdict {
    #[serde(rename = "CONFIRMED")]
    Confirmed,
    #[serde(rename = "REFUTED")]
    Refuted,
    #[serde(rename = "BLOCKED")]
    Blocked,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct MaterialFinding {
    severity: Severity,
    claim: String,
    evidence: String,
    consequence: String,
    required_correction: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CanaryRecord {
    schema_version: u32,
    verified_on: String,
    juno_sha256: String,
    codex_sha256: String,
    passed: BTreeSet<String>,
}

#[derive(Debug)]
pub struct VerifyRequest {
    pub repo: PathBuf,
    pub packet: PathBuf,
    pub json: bool,
}

#[derive(Debug)]
struct LaunchSpec {
    program: PathBuf,
    arguments: Vec<String>,
    environment: Vec<(String, String)>,
    cwd: PathBuf,
}

#[derive(Debug, Deserialize)]
struct Compatibility {
    standalone_cli: CompatibleCli,
}

#[derive(Debug, Deserialize)]
struct CompatibleCli {
    path: PathBuf,
    launcher_sha256: String,
}

#[derive(Debug, Deserialize)]
struct RoutingDefaults {
    strict_verification: StrictVerificationDefaults,
}

#[derive(Debug, Deserialize)]
struct StrictVerificationDefaults {
    status: String,
    enabled: bool,
    required_canaries: Vec<String>,
}

pub fn verifier_login(roots: &Roots) -> Result<String, String> {
    crate::lifecycle::ensure_verifier_allowed(roots).map_err(|error| error.to_string())?;
    nested_sandbox_probe()?;
    let state = SecureRoot::create(&roots.state_home).map_err(|error| error.to_string())?;
    state
        .ensure_directory(Path::new("verifier/home/tmp"), 0o700)
        .map_err(|error| error.to_string())?;
    let verifier_home = roots.state_home.join("verifier/home");
    prepare_verifier_home(&verifier_home, None).map_err(|error| error.to_string())?;
    let codex = codex_path().map_err(|error| error.to_string())?;
    let status = isolated_command(&codex, &verifier_home)
        .arg("login")
        .status()
        .map_err(|error| error.to_string())?;
    if !status.success() {
        return Err(format!("Codex login failed with {status}"));
    }
    Ok(format!(
        "verifier login stored under {}\nstrict verification stays unavailable until the required canaries pass",
        verifier_home.display()
    ))
}

pub fn verify(request: &VerifyRequest, roots: &Roots) -> Result<String, String> {
    crate::lifecycle::ensure_verifier_allowed(roots).map_err(|error| error.to_string())?;
    if std::env::var_os("JUNO_STRICT_ACTIVE").is_some() {
        return Err("BLOCKED: strict verification cannot recurse".into());
    }
    nested_sandbox_probe()?;
    if crate::check_compatibility().status != "certified" {
        return Err("BLOCKED: this Codex CLI and desktop pair is not certified".into());
    }
    if !strict_verification_enabled()? {
        return Err("BLOCKED: strict verification has not passed its evaluation".into());
    }
    let codex = codex_path().map_err(|error| error.to_string())?;
    let codex_content = read_nofollow(&codex).map_err(|error| error.to_string())?;
    let codex_hash = hex_sha256(&codex_content);
    let juno_hash = hex_sha256(
        &read_nofollow(&roots.source_bin)
            .map_err(|error| format!("BLOCKED: cannot hash Juno: {error}"))?,
    );
    let verifier_root = roots.state_home.join("verifier");
    let state = SecureRoot::create(&roots.state_home).map_err(|error| error.to_string())?;
    let canary_content = state
        .read_bounded(Path::new("verifier/canaries.json"), 1024 * 1024)
        .map_err(|_| "BLOCKED: strict canary record is unreadable".to_string())?
        .ok_or_else(|| "BLOCKED: strict canary record is missing".to_string())?;
    let canaries = read_canaries(&canary_content)?;
    let required_canaries = required_canaries()?;
    if canaries.schema_version != 1
        || canaries.verified_on.is_empty()
        || canaries.juno_sha256 != juno_hash
        || canaries.codex_sha256 != codex_hash
        || canaries.passed != required_canaries.iter().cloned().collect::<BTreeSet<_>>()
    {
        return Err("BLOCKED: strict canaries have not passed for this Codex binary".into());
    }
    let packet = read_packet(&request.packet)?;
    let home = verifier_root.join("home");
    if private_regular_metadata(&home.join("auth.json")).is_err() {
        return Err("BLOCKED: run `juno verifier login` first".into());
    }
    state
        .ensure_directory(Path::new("verifier/home/tmp"), 0o700)
        .map_err(|error| error.to_string())?;
    state
        .ensure_directory(Path::new("verifier/runs"), 0o700)
        .map_err(|error| error.to_string())?;
    let runs = verifier_root.join("runs");
    fs::set_permissions(&runs, fs::Permissions::from_mode(0o700))
        .map_err(|error| error.to_string())?;
    let snapshot = create_snapshot(&request.repo, &runs).map_err(|error| error.to_string())?;
    for path in &packet.paths {
        fs::symlink_metadata(snapshot.root.join(path))
            .map_err(|_| format!("BLOCKED: evidence path is not in the snapshot: {path}"))?;
    }
    make_snapshot_read_only(&snapshot.root).map_err(|error| error.to_string())?;
    let run_root = snapshot
        .root
        .parent()
        .ok_or("BLOCKED: snapshot run has no parent")?
        .to_path_buf();
    let neutral = run_root.join("neutral");
    fs::create_dir(&neutral).map_err(|error| error.to_string())?;
    ensure_neutral(&neutral)?;
    let result_schema = run_root.join("result-schema.json");
    let result_path = run_root.join("result.json");
    fs::write(&result_schema, RESULT_SCHEMA).map_err(|error| error.to_string())?;
    let packet_path = run_root.join("evidence.json");
    fs::write(
        &packet_path,
        serde_json::to_vec_pretty(&FrozenEvidencePacket {
            snapshot_sha256: &snapshot.manifest_sha256,
            requirement: &packet.requirement,
            paths: &packet.paths,
            claimed_checks: &packet.claimed_checks,
            constraints: &packet.constraints,
        })
        .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    let prompt = verifier_prompt(&snapshot, &packet);
    prepare_verifier_home(&home, Some(&snapshot.root)).map_err(|error| error.to_string())?;
    let profile = run_root.join("outer.sb");
    fs::write(
        &profile,
        outer_profile(&codex, &home, &run_root, &snapshot.root),
    )
    .map_err(|error| error.to_string())?;
    let spec = launch_spec(
        &codex,
        &home,
        &neutral,
        &profile,
        &result_schema,
        &result_path,
        &prompt,
    )?;
    run_bounded(&spec)?;
    crate::snapshot::verify_snapshot(&snapshot).map_err(|error| error.to_string())?;
    let result = String::from_utf8(
        read_bounded_nofollow(&result_path, OUTPUT_LIMIT)
            .map_err(|error| format!("BLOCKED: verifier result is unsafe: {error}"))?,
    )
    .map_err(|_| "BLOCKED: verifier result is not UTF-8".to_string())?;
    let parsed: VerifierResult =
        serde_json::from_str(&result).map_err(|error| error.to_string())?;
    validate_result(&parsed)?;
    if request.json {
        serde_json::to_string_pretty(&serde_json::json!({
            "snapshot_sha256": snapshot.manifest_sha256,
            "result": parsed,
        }))
        .map_err(|error| error.to_string())
    } else {
        Ok(result)
    }
}

pub(crate) fn strict_status(roots: &Roots) -> String {
    if crate::check_compatibility().status != "certified" {
        return "unavailable: clients not certified".into();
    }
    if strict_verification_enabled() != Ok(true) {
        return "unavailable: strict evaluation not passed".into();
    }
    let Ok(codex) = codex_path() else {
        return "unavailable: incompatible Codex binary".into();
    };
    let Ok(content) = read_nofollow(&codex) else {
        return "unavailable: unreadable Codex binary".into();
    };
    let Ok(juno_content) = read_nofollow(&roots.source_bin) else {
        return "unavailable: unreadable Juno binary".into();
    };
    let Ok(state) = SecureRoot::create(&roots.state_home) else {
        return "unavailable: unsafe verifier state".into();
    };
    let Ok(Some(canary_content)) =
        state.read_bounded(Path::new("verifier/canaries.json"), 1024 * 1024)
    else {
        return "unavailable: canaries not passed".into();
    };
    let Ok(canaries) = read_canaries(&canary_content) else {
        return "unavailable: invalid canary record".into();
    };
    let Ok(required_canaries) = required_canaries() else {
        return "unavailable: invalid canary contract".into();
    };
    if canaries.schema_version == 1
        && !canaries.verified_on.is_empty()
        && canaries.juno_sha256 == hex_sha256(&juno_content)
        && canaries.codex_sha256 == hex_sha256(&content)
        && canaries.passed == required_canaries.into_iter().collect::<BTreeSet<_>>()
    {
        "available".into()
    } else {
        "unavailable: stale canaries".into()
    }
}

fn read_packet(path: &Path) -> Result<EvidencePacket, String> {
    let metadata = fs::metadata(path).map_err(|error| error.to_string())?;
    if metadata.len() > 1024 * 1024 {
        return Err("evidence packet exceeds 1 MiB".into());
    }
    let packet: EvidencePacket =
        serde_json::from_slice(&fs::read(path).map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())?;
    if packet.requirement.is_empty()
        || packet.requirement.len() > 20_000
        || packet.paths.len() > 200
        || packet.claimed_checks.len() > 200
        || packet.constraints.len() > 200
        || packet
            .paths
            .iter()
            .chain(&packet.claimed_checks)
            .chain(&packet.constraints)
            .any(|value| value.is_empty() || value.len() > 4096)
        || packet.paths.iter().any(|value| {
            let path = Path::new(value);
            path.is_absolute()
                || path
                    .components()
                    .any(|component| !matches!(component, std::path::Component::Normal(_)))
        })
    {
        return Err("evidence packet violates its bounds".into());
    }
    Ok(packet)
}

fn validate_result(result: &VerifierResult) -> Result<(), String> {
    if result.material_findings.len() > 200
        || result.unverified_assumptions.len() > 200
        || result
            .material_findings
            .iter()
            .flat_map(|finding| {
                [
                    &finding.claim,
                    &finding.evidence,
                    &finding.consequence,
                    &finding.required_correction,
                ]
            })
            .chain(&result.unverified_assumptions)
            .any(|value| value.is_empty() || value.len() > 4096)
    {
        return Err("BLOCKED: verifier result violates its bounds".into());
    }
    if matches!(result.verdict, Verdict::Confirmed) && !result.material_findings.is_empty() {
        return Err("BLOCKED: a confirmed result cannot contain material findings".into());
    }
    if matches!(result.verdict, Verdict::Refuted) && result.material_findings.is_empty() {
        return Err("BLOCKED: a refuted result needs a material finding".into());
    }
    Ok(())
}

fn prepare_verifier_home(home: &Path, snapshot: Option<&Path>) -> io::Result<()> {
    if !fs::metadata(home)?.is_dir() {
        return Err(io::Error::other("verifier home is not a directory"));
    }
    fs::set_permissions(home, fs::Permissions::from_mode(0o700))?;
    for forbidden in [
        "AGENTS.md",
        "AGENTS.override.md",
        "agents",
        "skills",
        "plugins",
        "hooks.json",
        "rules",
        "rules.json",
        "mcp.json",
    ] {
        match fs::symlink_metadata(home.join(forbidden)) {
            Ok(_) => {
                return Err(io::Error::other(format!(
                    "verifier home contains forbidden state: {forbidden}"
                )));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    let temporary = home.join("tmp");
    if !fs::metadata(&temporary)?.is_dir() {
        return Err(io::Error::other(
            "verifier temporary path is not a directory",
        ));
    }
    fs::set_permissions(&temporary, fs::Permissions::from_mode(0o700))?;
    let catalog = Catalog::parse(CATALOG_SOURCE).map_err(io::Error::other)?;
    let binding = catalog
        .bindings
        .get("heavy_verifier")
        .ok_or_else(|| io::Error::other("heavy verifier binding is missing"))?;
    let model = catalog
        .models
        .get(&binding.model)
        .ok_or_else(|| io::Error::other("heavy verifier model is missing"))?;
    let mut config = format!(
        "cli_auth_credentials_store = \"file\"\ncheck_for_update_on_startup = false\nweb_search = \"disabled\"\napproval_policy = \"never\"\ndefault_permissions = \"juno-strict\"\nmodel = {}\nmodel_reasoning_effort = {}\n\n[history]\npersistence = \"none\"\n\n[agents]\nenabled = false\n\n[features]\napps = false\nremote_plugin = false\nshell_snapshot = false\n\n[shell_environment_policy]\ninherit = \"none\"\nignore_default_excludes = false\nexperimental_use_profile = false\n\n[shell_environment_policy.set]\nPATH = \"/opt/homebrew/bin:/usr/bin:/bin\"\nLANG = \"en_US.UTF-8\"\nTMPDIR = {}\nJUNO_STRICT_ACTIVE = \"1\"\n\n[permissions.juno-strict.filesystem]\n\":root\" = \"deny\"\n\":minimal\" = \"read\"\n\n[permissions.juno-strict.network]\nenabled = false\n",
        toml_string(&model.id),
        toml_string(&binding.effort),
        toml_string(&temporary.display().to_string()),
    );
    if let Some(snapshot) = snapshot {
        config.push_str(&format!(
            "\n[permissions.juno-strict.workspace_roots]\n{} = true\n\n[permissions.juno-strict.filesystem.\":workspace_roots\"]\n\".\" = \"read\"\n",
            toml_string(&snapshot.display().to_string())
        ));
    }
    let parsed = toml::from_str::<toml::Value>(&config).map_err(io::Error::other)?;
    if parsed.get("model").and_then(toml::Value::as_str) != Some(model.id.as_str()) {
        return Err(io::Error::other(
            "verifier model is not a top-level setting",
        ));
    }
    if parsed
        .get("shell_environment_policy")
        .and_then(|value| value.get("inherit"))
        .and_then(toml::Value::as_str)
        != Some("none")
    {
        return Err(io::Error::other(
            "verifier command environment is not isolated",
        ));
    }
    write_private(&home.join("config.toml"), config.as_bytes())
}

fn codex_path() -> io::Result<PathBuf> {
    if let Some(path) = std::env::var_os("JUNO_CODEX_BIN") {
        return Ok(PathBuf::from(path));
    }
    let compatibility: Compatibility =
        toml::from_str(COMPATIBILITY_SOURCE).map_err(io::Error::other)?;
    let content = read_nofollow(&compatibility.standalone_cli.path)?;
    if hex_sha256(&content) != compatibility.standalone_cli.launcher_sha256 {
        return Err(io::Error::other(
            "configured Codex executable does not match the compatible hash",
        ));
    }
    Ok(compatibility.standalone_cli.path)
}

fn nested_sandbox_probe() -> Result<(), String> {
    let status = Command::new("/usr/bin/sandbox-exec")
        .args(["-p", "(version 1)(allow default)", "/usr/bin/true"])
        .status()
        .map_err(|error| format!("BLOCKED: sandbox probe failed: {error}"))?;
    if !status.success() {
        return Err("BLOCKED: strict verification must start outside an existing sandbox".into());
    }
    Ok(())
}

fn read_canaries(content: &[u8]) -> Result<CanaryRecord, String> {
    serde_json::from_slice(content)
        .map_err(|error| format!("BLOCKED: strict canary record is invalid: {error}"))
}

fn required_canaries() -> Result<Vec<String>, String> {
    let defaults: RoutingDefaults =
        toml::from_str(ROUTING_DEFAULTS_SOURCE).map_err(|error| error.to_string())?;
    if defaults.strict_verification.required_canaries.is_empty() {
        return Err("strict canary contract is empty".into());
    }
    let unique = defaults
        .strict_verification
        .required_canaries
        .iter()
        .collect::<BTreeSet<_>>();
    if unique.len() != defaults.strict_verification.required_canaries.len() {
        return Err("strict canary contract contains duplicates".into());
    }
    Ok(defaults.strict_verification.required_canaries)
}

fn strict_verification_enabled() -> Result<bool, String> {
    let defaults: RoutingDefaults =
        toml::from_str(ROUTING_DEFAULTS_SOURCE).map_err(|error| error.to_string())?;
    Ok(defaults.strict_verification.enabled && defaults.strict_verification.status == "passed")
}

fn ensure_neutral(path: &Path) -> Result<(), String> {
    for forbidden in [".git", "AGENTS.md", "AGENTS.override.md", ".codex"] {
        if path.join(forbidden).exists() {
            return Err(format!("BLOCKED: neutral directory contains {forbidden}"));
        }
    }
    Ok(())
}

fn verifier_prompt(snapshot: &Snapshot, packet: &EvidencePacket) -> String {
    format!(
        "Act only as a verifier. Do not repair files. Review the frozen repository at {}. The snapshot manifest is {}. Requirement: {}\nRelevant paths: {}\nClaimed checks: {}\nConstraints: {}\nReturn only the required JSON result.",
        snapshot.root.display(),
        snapshot.manifest_sha256,
        packet.requirement,
        packet.paths.join(", "),
        packet.claimed_checks.join(", "),
        packet.constraints.join(", "),
    )
}

fn launch_spec(
    codex: &Path,
    home: &Path,
    neutral: &Path,
    profile: &Path,
    schema: &Path,
    result: &Path,
    prompt: &str,
) -> Result<LaunchSpec, String> {
    if !neutral.is_absolute() || !schema.is_absolute() || !result.is_absolute() {
        return Err("BLOCKED: strict launch paths must be absolute".into());
    }
    Ok(LaunchSpec {
        program: PathBuf::from("/usr/bin/sandbox-exec"),
        arguments: vec![
            "-f".into(),
            profile.display().to_string(),
            codex.display().to_string(),
            "exec".into(),
            "--skip-git-repo-check".into(),
            "--strict-config".into(),
            "--ignore-rules".into(),
            "--ephemeral".into(),
            "--json".into(),
            "--output-schema".into(),
            schema.display().to_string(),
            "--output-last-message".into(),
            result.display().to_string(),
            "-C".into(),
            neutral.display().to_string(),
            prompt.into(),
        ],
        environment: isolated_environment(home),
        cwd: neutral.to_path_buf(),
    })
}

fn isolated_environment(home: &Path) -> Vec<(String, String)> {
    vec![
        ("CODEX_HOME".into(), home.display().to_string()),
        ("HOME".into(), home.display().to_string()),
        ("PATH".into(), "/opt/homebrew/bin:/usr/bin:/bin".into()),
        ("LANG".into(), "en_US.UTF-8".into()),
        ("TMPDIR".into(), home.join("tmp").display().to_string()),
        ("JUNO_STRICT_ACTIVE".into(), "1".into()),
    ]
}

fn isolated_command(program: &Path, home: &Path) -> Command {
    let mut command = Command::new(program);
    command.env_clear();
    for (key, value) in isolated_environment(home) {
        command.env(key, value);
    }
    command
}

fn run_bounded(spec: &LaunchSpec) -> Result<(), String> {
    let mut command = Command::new(&spec.program);
    command
        .args(&spec.arguments)
        .current_dir(&spec.cwd)
        .env_clear()
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (key, value) in &spec.environment {
        command.env(key, value);
    }
    let mut child = command.spawn().map_err(|error| error.to_string())?;
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    let stdout_thread = thread::spawn(move || bounded_read(stdout, OUTPUT_LIMIT));
    let stderr_thread = thread::spawn(move || bounded_read(stderr, OUTPUT_LIMIT));
    let status = child.wait().map_err(|error| error.to_string())?;
    let _stdout = stdout_thread
        .join()
        .map_err(|_| "verifier stdout reader failed".to_string())?
        .map_err(|error| error.to_string())?;
    let stderr = stderr_thread
        .join()
        .map_err(|_| "verifier stderr reader failed".to_string())?
        .map_err(|error| error.to_string())?;
    if !status.success() {
        return Err(format!(
            "BLOCKED: verifier process failed: {}",
            String::from_utf8_lossy(&stderr).trim()
        ));
    }
    Ok(())
}

fn bounded_read(mut reader: impl Read, limit: u64) -> io::Result<Vec<u8>> {
    let mut output = Vec::new();
    reader.by_ref().take(limit + 1).read_to_end(&mut output)?;
    if output.len() as u64 > limit {
        return Err(io::Error::other("verifier stream exceeded its limit"));
    }
    Ok(output)
}

fn outer_profile(codex: &Path, home: &Path, run: &Path, snapshot: &Path) -> String {
    format!(
        "(version 1)\n(deny default)\n(allow process*)\n(allow sysctl-read)\n(allow file-read* (subpath \"/System\") (subpath \"/usr\") (subpath \"/bin\") (subpath \"/sbin\") (subpath \"/Library/Apple\") (subpath \"/opt/homebrew\") (subpath \"/private/etc\") (subpath \"/dev\") (subpath {codex}) (subpath {home}) (subpath {run}) (subpath {snapshot}))\n(allow file-write* (subpath {home}) (subpath {run}))\n(deny file-write* (subpath {snapshot}))\n(allow network-outbound)\n",
        codex = sandbox_string(codex),
        home = sandbox_string(home),
        run = sandbox_string(run),
        snapshot = sandbox_string(snapshot),
    )
}

fn make_snapshot_read_only(root: &Path) -> io::Result<()> {
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let metadata = fs::symlink_metadata(entry.path())?;
        if metadata.is_dir() {
            make_snapshot_read_only(&entry.path())?;
            fs::set_permissions(entry.path(), fs::Permissions::from_mode(0o500))?;
        } else if metadata.is_file() {
            let executable = metadata.permissions().mode() & 0o111 != 0;
            fs::set_permissions(
                entry.path(),
                fs::Permissions::from_mode(if executable { 0o500 } else { 0o400 }),
            )?;
        }
    }
    fs::set_permissions(root, fs::Permissions::from_mode(0o500))
}

fn read_nofollow(path: &Path) -> io::Result<Vec<u8>> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW_ANY)
        .open(path)?;
    let mut content = Vec::new();
    file.read_to_end(&mut content)?;
    Ok(content)
}

fn read_bounded_nofollow(path: &Path, limit: u64) -> io::Result<Vec<u8>> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW_ANY)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.nlink() != 1 {
        return Err(io::Error::other("file has unsafe metadata"));
    }
    if metadata.len() > limit {
        return Err(io::Error::other("file exceeds its read limit"));
    }
    let mut content = Vec::new();
    Read::by_ref(&mut file)
        .take(limit + 1)
        .read_to_end(&mut content)?;
    if content.len() as u64 > limit {
        return Err(io::Error::other("file grew past its read limit"));
    }
    Ok(content)
}

fn private_regular_metadata(path: &Path) -> io::Result<fs::Metadata> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW_ANY)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o077 != 0 || metadata.nlink() != 1 {
        return Err(io::Error::other("private file has unsafe metadata"));
    }
    Ok(metadata)
}

fn write_private(path: &Path, content: &[u8]) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = match OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW_ANY)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?,
        Err(error) => return Err(error),
    };
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.nlink() != 1 {
        return Err(io::Error::other("private target has unsafe metadata"));
    }
    file.set_len(0)?;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    file.write_all(content)?;
    file.sync_all()
}

fn toml_string(value: &str) -> String {
    format!("{:?}", value)
}

fn sandbox_string(path: &Path) -> String {
    toml_string(&path.display().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn launch_uses_a_neutral_directory_and_clears_sensitive_environment() {
        let base = Path::new("/private/tmp/juno-verifier-test");
        let neutral = base.join("neutral");
        let spec = launch_spec(
            Path::new("/opt/homebrew/bin/codex"),
            &base.join("home"),
            &neutral,
            &base.join("outer.sb"),
            &base.join("schema.json"),
            &base.join("result.json"),
            "review /private/tmp/snapshot",
        )
        .unwrap();
        assert_eq!(spec.cwd, neutral);
        let cd = spec
            .arguments
            .iter()
            .position(|value| value == "-C")
            .unwrap();
        assert_eq!(spec.arguments[cd + 1], spec.cwd.display().to_string());
        assert!(
            spec.arguments
                .iter()
                .any(|value| value == "--skip-git-repo-check")
        );
        assert!(
            spec.arguments
                .iter()
                .all(|value| value != "--ignore-user-config")
        );
        let keys = spec
            .environment
            .iter()
            .map(|(key, _)| key.as_str())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            keys,
            BTreeSet::from([
                "CODEX_HOME",
                "HOME",
                "JUNO_STRICT_ACTIVE",
                "LANG",
                "PATH",
                "TMPDIR",
            ])
        );
        assert!(!keys.contains("OPENAI_API_KEY"));
        assert!(!keys.contains("CODEX_API_KEY"));
        assert!(!keys.contains("HTTP_PROXY"));
        assert!(!keys.contains("SSH_AUTH_SOCK"));
    }

    #[test]
    fn packet_rejects_reasoning_and_unknown_fields() {
        let temp = tempfile::tempdir().unwrap();
        let packet = temp.path().join("packet.json");
        fs::write(
            &packet,
            r#"{"requirement":"x","paths":[],"claimed_checks":[],"constraints":[],"reasoning":"secret"}"#,
        )
        .unwrap();
        assert!(read_packet(&packet).is_err());
    }

    #[test]
    fn packet_rejects_paths_outside_the_snapshot() {
        let temp = tempfile::tempdir().unwrap();
        let packet = temp.path().join("packet.json");
        fs::write(
            &packet,
            r#"{"requirement":"x","paths":["../secret"],"claimed_checks":[],"constraints":[]}"#,
        )
        .unwrap();
        assert!(read_packet(&packet).is_err());
    }

    #[test]
    fn result_requires_verdict_consistency() {
        let confirmed_with_finding = VerifierResult {
            verdict: Verdict::Confirmed,
            material_findings: vec![MaterialFinding {
                severity: Severity::High,
                claim: "claim".into(),
                evidence: "evidence".into(),
                consequence: "consequence".into(),
                required_correction: "correction".into(),
            }],
            unverified_assumptions: Vec::new(),
        };
        assert!(validate_result(&confirmed_with_finding).is_err());
        let refuted_without_finding = VerifierResult {
            verdict: Verdict::Refuted,
            material_findings: Vec::new(),
            unverified_assumptions: Vec::new(),
        };
        assert!(validate_result(&refuted_without_finding).is_err());
    }

    #[test]
    fn result_reader_rejects_links_and_large_files() {
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path().canonicalize().unwrap();
        let regular = base.join("regular");
        fs::write(&regular, b"result").unwrap();
        std::os::unix::fs::symlink(&regular, base.join("link")).unwrap();
        assert!(read_bounded_nofollow(&base.join("link"), 64).is_err());
        assert!(read_bounded_nofollow(&regular, 3).is_err());
        assert_eq!(read_bounded_nofollow(&regular, 6).unwrap(), b"result");
    }

    #[test]
    fn strict_contract_is_blocked_and_has_unique_canaries() {
        assert_eq!(required_canaries().unwrap().len(), 15);
        assert_eq!(strict_verification_enabled(), Ok(false));
    }
}
