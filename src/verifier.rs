use crate::secure_fs::{SecureRoot, hex_sha256};
use crate::{Catalog, Roots, create_snapshot};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const CATALOG_SOURCE: &str = include_str!("../config/model-catalog.toml");
const COMPATIBILITY_SOURCE: &str = include_str!("../config/compatibility.toml");
const ROUTING_DEFAULTS_SOURCE: &str = include_str!("../config/routing-defaults.toml");
const RESULT_SCHEMA: &str = include_str!("../schemas/verifier-result.schema.json");
const OUTPUT_LIMIT: u64 = 4 * 1024 * 1024;
const PROCESS_TIMEOUT: Duration = Duration::from_secs(20 * 60);

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidencePacket {
    pub requirement: String,
    pub paths: Vec<String>,
    pub claimed_checks: Vec<String>,
    pub constraints: Vec<String>,
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

#[derive(Debug)]
pub struct VerifyRequest {
    pub repo: PathBuf,
    pub packet: PathBuf,
    pub json: bool,
}

#[doc(hidden)]
#[derive(Debug)]
pub struct StrictProbeRequest {
    pub codex_bin: PathBuf,
    pub verifier_home: PathBuf,
    pub runs_root: PathBuf,
    pub repo: PathBuf,
    pub output_schema: Vec<u8>,
    pub prompt: String,
    pub required_paths: Vec<String>,
}

#[doc(hidden)]
#[derive(Debug)]
pub struct StrictProbeResult {
    pub snapshot_sha256: String,
    pub output: Vec<u8>,
    pub proxy_hosts: Vec<String>,
}

#[derive(Debug)]
struct LaunchSpec {
    program: PathBuf,
    arguments: Vec<String>,
    environment: Vec<(String, String)>,
    cwd: PathBuf,
}

struct StrictLaunchFiles<'a> {
    profile: &'a Path,
    schema: &'a Path,
    result: &'a Path,
}

struct ServiceProxy {
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    requests: Arc<Mutex<Vec<String>>>,
    error: Arc<Mutex<Option<String>>>,
    thread: Option<thread::JoinHandle<()>>,
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
    required_canaries: Vec<String>,
}

pub fn verifier_login(roots: &Roots) -> Result<String, String> {
    require_unsandboxed_parent()?;
    crate::lifecycle::ensure_verifier_allowed(roots).map_err(|error| error.to_string())?;
    let (evidence, _) = crate::lifecycle::installed_release_evidence(roots)
        .map_err(|error| format!("BLOCKED: {error}"))?;
    if crate::compatibility::check_compatibility_with_evidence(Some(&evidence)).status
        != "certified"
    {
        return Err("BLOCKED: this Juno release is not certified for these clients".into());
    }
    let state = SecureRoot::create(&roots.state_home).map_err(|error| error.to_string())?;
    state
        .ensure_directory(Path::new("verifier/home/tmp"), 0o700)
        .map_err(|error| error.to_string())?;
    let verifier_home = roots.state_home.join("verifier/home");
    prepare_verifier_home(&verifier_home, None).map_err(|error| error.to_string())?;
    let login_relative = PathBuf::from(format!("verifier/login-{}", std::process::id()));
    state
        .ensure_directory(&login_relative.join("tmp"), 0o700)
        .map_err(|error| error.to_string())?;
    let login_home = roots.state_home.join(&login_relative);
    prepare_verifier_home(&login_home, None).map_err(|error| error.to_string())?;
    let codex = codex_path().map_err(|error| error.to_string())?;
    let status = isolated_command(&codex, &login_home)
        .arg("login")
        .status()
        .map_err(|error| error.to_string())?;
    if !status.success() {
        return Err(format!(
            "Codex login failed with {status}; private staging state remains at {}",
            login_home.display()
        ));
    }
    move_private_auth(&login_home, &verifier_home).map_err(|error| error.to_string())?;
    fs::remove_dir_all(&login_home).map_err(|error| {
        format!(
            "verifier login succeeded, but credential-free staging cleanup failed at {}: {error}",
            login_home.display()
        )
    })?;
    Ok(format!(
        "verifier login stored under {}\nrun `juno doctor` to confirm strict verification is available",
        verifier_home.display()
    ))
}

pub fn verify(request: &VerifyRequest, roots: &Roots) -> Result<String, String> {
    if std::env::var_os("JUNO_STRICT_ACTIVE").is_some() {
        return Err("BLOCKED: strict verification cannot recurse".into());
    }
    require_unsandboxed_parent()?;
    crate::lifecycle::ensure_verifier_allowed(roots).map_err(|error| error.to_string())?;
    let (evidence, _) = crate::lifecycle::installed_release_evidence(roots)
        .map_err(|error| format!("BLOCKED: {error}"))?;
    if crate::compatibility::check_compatibility_with_evidence(Some(&evidence)).status
        != "certified"
    {
        return Err("BLOCKED: this Codex CLI and desktop pair is not certified".into());
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
    let candidate = &evidence.candidate;
    let canaries = &evidence.canaries;
    let required_canaries = required_canaries()?;
    if candidate.binary_sha256 != juno_hash
        || canaries.juno_sha256 != juno_hash
        || canaries.codex_sha256 != codex_hash
        || canaries.passed_names() != required_canaries.iter().cloned().collect::<BTreeSet<_>>()
        || canaries.validate(candidate).is_err()
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
    let probe = execute_strict_core(&StrictProbeRequest {
        codex_bin: codex,
        verifier_home: home,
        runs_root: runs,
        repo: request.repo.clone(),
        output_schema: RESULT_SCHEMA.as_bytes().to_vec(),
        prompt: verifier_prompt_without_snapshot(&packet),
        required_paths: packet.paths.clone(),
    })?;
    let result = String::from_utf8(probe.output)
        .map_err(|_| "BLOCKED: verifier result is not UTF-8".to_string())?;
    let parsed: VerifierResult =
        serde_json::from_str(&result).map_err(|error| error.to_string())?;
    validate_result(&parsed)?;
    if request.json {
        serde_json::to_string_pretty(&serde_json::json!({
            "snapshot_sha256": probe.snapshot_sha256,
            "result": parsed,
        }))
        .map_err(|error| error.to_string())
    } else {
        Ok(result)
    }
}

#[doc(hidden)]
pub fn execute_strict_probe(request: &StrictProbeRequest) -> Result<StrictProbeResult, String> {
    require_unsandboxed_parent()?;
    execute_strict_core(request)
}

fn execute_strict_core(request: &StrictProbeRequest) -> Result<StrictProbeResult, String> {
    for path in [
        &request.codex_bin,
        &request.verifier_home,
        &request.runs_root,
        &request.repo,
    ] {
        if !path.is_absolute() {
            return Err("BLOCKED: strict probe paths must be absolute".into());
        }
    }
    read_bounded_nofollow(&request.codex_bin, 512 * 1024 * 1024)
        .map_err(|error| format!("BLOCKED: Codex binary is unsafe: {error}"))?;
    private_regular_metadata(&request.verifier_home.join("auth.json"))
        .map_err(|_| "BLOCKED: dedicated verifier login is missing or unsafe".to_string())?;
    if request.output_schema.is_empty() || request.output_schema.len() > 1024 * 1024 {
        return Err("BLOCKED: strict output schema is invalid".into());
    }
    serde_json::from_slice::<serde_json::Value>(&request.output_schema)
        .map_err(|error| format!("BLOCKED: strict output schema does not parse: {error}"))?;
    ensure_private_directory(&request.verifier_home)?;
    ensure_private_directory(&request.runs_root)?;
    let snapshot =
        create_snapshot(&request.repo, &request.runs_root).map_err(|error| error.to_string())?;
    for path in &request.required_paths {
        let relative = Path::new(path);
        if relative.is_absolute()
            || relative
                .components()
                .any(|component| !matches!(component, std::path::Component::Normal(_)))
            || fs::symlink_metadata(snapshot.root.join(relative)).is_err()
        {
            return Err(format!(
                "BLOCKED: evidence path is not in the snapshot: {path}"
            ));
        }
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
    write_private(&result_schema, &request.output_schema).map_err(|error| error.to_string())?;
    prepare_verifier_home(&request.verifier_home, Some(&snapshot.root))
        .map_err(|error| error.to_string())?;
    let mut proxy = ServiceProxy::start()?;
    let profile = run_root.join("outer.sb");
    write_private(
        &profile,
        outer_profile(
            &request.codex_bin,
            &request.verifier_home,
            &run_root,
            &snapshot.root,
            proxy.address,
        )
        .as_bytes(),
    )
    .map_err(|error| error.to_string())?;
    let prompt = request
        .prompt
        .replace("{SNAPSHOT}", &snapshot.root.display().to_string())
        .replace("{SNAPSHOT_SHA256}", &snapshot.manifest_sha256)
        .replace("{SERVICE_PROXY}", &format!("http://{}", proxy.address));
    let spec = launch_spec(
        &request.codex_bin,
        &request.verifier_home,
        &neutral,
        StrictLaunchFiles {
            profile: &profile,
            schema: &result_schema,
            result: &result_path,
        },
        &prompt,
        proxy.address,
    )?;
    run_bounded(&spec)?;
    let proxy_hosts = proxy.finish()?;
    if proxy_hosts.is_empty() || proxy_hosts.iter().any(|host| !allowed_service_host(host)) {
        return Err("BLOCKED: Codex service proxy containment was not proven".into());
    }
    crate::snapshot::verify_snapshot(&snapshot).map_err(|error| error.to_string())?;
    let output = read_bounded_nofollow(&result_path, OUTPUT_LIMIT)
        .map_err(|error| format!("BLOCKED: verifier result is unsafe: {error}"))?;
    Ok(StrictProbeResult {
        snapshot_sha256: snapshot.manifest_sha256,
        output,
        proxy_hosts,
    })
}

pub(crate) fn strict_status(roots: &Roots) -> String {
    let Ok((evidence, _)) = crate::lifecycle::installed_release_evidence(roots) else {
        return "unavailable: release evidence missing".into();
    };
    if crate::compatibility::check_compatibility_with_evidence(Some(&evidence)).status
        != "certified"
    {
        return "unavailable: clients not certified".into();
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
    let candidate = &evidence.candidate;
    let canaries = &evidence.canaries;
    let Ok(required_canaries) = required_canaries() else {
        return "unavailable: invalid canary contract".into();
    };
    if candidate.binary_sha256 == hex_sha256(&juno_content)
        && canaries.juno_sha256 == hex_sha256(&juno_content)
        && canaries.codex_sha256 == hex_sha256(&content)
        && canaries.passed_names() == required_canaries.into_iter().collect::<BTreeSet<_>>()
        && canaries.validate(candidate).is_ok()
    {
        if private_regular_metadata(&roots.state_home.join("verifier/home/auth.json")).is_ok() {
            "available".into()
        } else {
            "login-required".into()
        }
    } else {
        "unavailable: stale canaries".into()
    }
}

fn read_packet(path: &Path) -> Result<EvidencePacket, String> {
    let content = read_bounded_nofollow(path, 1024 * 1024).map_err(|error| error.to_string())?;
    let packet: EvidencePacket =
        serde_json::from_slice(&content).map_err(|error| error.to_string())?;
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

fn require_unsandboxed_parent() -> Result<(), String> {
    let status = Command::new("/usr/bin/sandbox-exec")
        .args(["-p", "(version 1)(allow default)", "/usr/bin/true"])
        .status()
        .map_err(|error| format!("BLOCKED: sandbox probe failed: {error}"))?;
    if !status.success() {
        return Err("BLOCKED: strict verification must start outside an existing sandbox".into());
    }
    Ok(())
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

fn ensure_neutral(path: &Path) -> Result<(), String> {
    for forbidden in [".git", "AGENTS.md", "AGENTS.override.md", ".codex"] {
        if path.join(forbidden).exists() {
            return Err(format!("BLOCKED: neutral directory contains {forbidden}"));
        }
    }
    Ok(())
}

fn verifier_prompt_without_snapshot(packet: &EvidencePacket) -> String {
    format!(
        "Act only as a verifier. Do not repair files. Review the frozen repository at {{SNAPSHOT}}. The snapshot manifest is {{SNAPSHOT_SHA256}}. Requirement: {}\nRelevant paths: {}\nClaimed checks: {}\nConstraints: {}\nReturn only the required JSON result.",
        packet.requirement,
        packet.paths.join(", "),
        packet.claimed_checks.join(", "),
        packet.constraints.join(", "),
    )
}

fn ensure_private_directory(path: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(format!(
            "BLOCKED: strict directory is unsafe: {}",
            path.display()
        ));
    }
    Ok(())
}

fn launch_spec(
    codex: &Path,
    home: &Path,
    neutral: &Path,
    files: StrictLaunchFiles<'_>,
    prompt: &str,
    proxy: SocketAddr,
) -> Result<LaunchSpec, String> {
    if !neutral.is_absolute() || !files.schema.is_absolute() || !files.result.is_absolute() {
        return Err("BLOCKED: strict launch paths must be absolute".into());
    }
    Ok(LaunchSpec {
        program: PathBuf::from("/usr/bin/sandbox-exec"),
        arguments: vec![
            "-f".into(),
            files.profile.display().to_string(),
            codex.display().to_string(),
            "exec".into(),
            "--skip-git-repo-check".into(),
            "--strict-config".into(),
            "--ignore-rules".into(),
            "--ephemeral".into(),
            "--json".into(),
            "--output-schema".into(),
            files.schema.display().to_string(),
            "--output-last-message".into(),
            files.result.display().to_string(),
            "-C".into(),
            neutral.display().to_string(),
            prompt.into(),
        ],
        environment: isolated_environment(home, Some(proxy)),
        cwd: neutral.to_path_buf(),
    })
}

fn isolated_environment(home: &Path, proxy: Option<SocketAddr>) -> Vec<(String, String)> {
    let mut environment = vec![
        ("CODEX_HOME".into(), home.display().to_string()),
        ("HOME".into(), home.display().to_string()),
        ("PATH".into(), "/opt/homebrew/bin:/usr/bin:/bin".into()),
        ("LANG".into(), "en_US.UTF-8".into()),
        ("TMPDIR".into(), home.join("tmp").display().to_string()),
        ("JUNO_STRICT_ACTIVE".into(), "1".into()),
    ];
    if let Some(proxy) = proxy {
        let url = format!("http://{proxy}");
        environment.extend([
            ("HTTP_PROXY".into(), url.clone()),
            ("HTTPS_PROXY".into(), url.clone()),
            ("ALL_PROXY".into(), url),
        ]);
    }
    environment
}

fn isolated_command(program: &Path, home: &Path) -> Command {
    let mut command = Command::new(program);
    command.env_clear();
    for (key, value) in isolated_environment(home, None) {
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
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().map_err(|error| error.to_string())? {
            break status;
        }
        if started.elapsed() >= PROCESS_TIMEOUT {
            child.kill().map_err(|error| error.to_string())?;
            let _ = child.wait();
            return Err("BLOCKED: verifier process exceeded its time limit".into());
        }
        thread::sleep(Duration::from_millis(100));
    };
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

impl ServiceProxy {
    fn start() -> Result<Self, String> {
        let listener = TcpListener::bind("127.0.0.1:0")
            .map_err(|error| format!("BLOCKED: cannot bind the service proxy: {error}"))?;
        listener
            .set_nonblocking(true)
            .map_err(|error| format!("BLOCKED: cannot configure the service proxy: {error}"))?;
        let address = listener
            .local_addr()
            .map_err(|error| format!("BLOCKED: cannot inspect the service proxy: {error}"))?;
        let stop = Arc::new(AtomicBool::new(false));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let error = Arc::new(Mutex::new(None));
        let thread_stop = Arc::clone(&stop);
        let thread_requests = Arc::clone(&requests);
        let thread_error = Arc::clone(&error);
        let thread = thread::spawn(move || {
            while !thread_stop.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let requests = Arc::clone(&thread_requests);
                        thread::spawn(move || {
                            let _ = handle_service_proxy_connection(stream, &requests);
                        });
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => {
                        if let Ok(mut value) = thread_error.lock() {
                            *value = Some(error.to_string());
                        }
                        break;
                    }
                }
            }
        });
        Ok(Self {
            address,
            stop,
            requests,
            error,
            thread: Some(thread),
        })
    }

    fn finish(&mut self) -> Result<Vec<String>, String> {
        self.stop();
        if let Some(thread) = self.thread.take() {
            thread
                .join()
                .map_err(|_| "BLOCKED: service proxy thread failed".to_string())?;
        }
        if let Some(error) = self
            .error
            .lock()
            .map_err(|_| "BLOCKED: service proxy state failed".to_string())?
            .clone()
        {
            return Err(format!("BLOCKED: service proxy failed: {error}"));
        }
        self.requests
            .lock()
            .map_err(|_| "BLOCKED: service proxy log failed".to_string())
            .map(|value| value.clone())
    }

    fn stop(&self) {
        self.stop.store(true, Ordering::Release);
        let _ = TcpStream::connect(self.address);
    }
}

impl Drop for ServiceProxy {
    fn drop(&mut self) {
        self.stop();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn handle_service_proxy_connection(
    mut client: TcpStream,
    requests: &Arc<Mutex<Vec<String>>>,
) -> io::Result<()> {
    client.set_read_timeout(Some(Duration::from_secs(30)))?;
    client.set_write_timeout(Some(Duration::from_secs(30)))?;
    let mut header = Vec::new();
    let mut buffer = [0u8; 2048];
    let header_end = loop {
        let count = client.read(&mut buffer)?;
        if count == 0 {
            return Ok(());
        }
        header.extend_from_slice(&buffer[..count]);
        if header.len() > 32 * 1024 {
            write_proxy_response(&mut client, "431 Request Header Fields Too Large")?;
            return Ok(());
        }
        if let Some(index) = header.windows(4).position(|value| value == b"\r\n\r\n") {
            break index + 4;
        }
    };
    let line_end = header
        .windows(2)
        .position(|value| value == b"\r\n")
        .ok_or_else(|| io::Error::other("proxy request line is missing"))?;
    let request_line = std::str::from_utf8(&header[..line_end])
        .map_err(|_| io::Error::other("proxy request line is not UTF-8"))?;
    let mut parts = request_line.split_ascii_whitespace();
    let method = parts.next().unwrap_or_default();
    let target = parts.next().unwrap_or_default();
    let version = parts.next().unwrap_or_default();
    if method != "CONNECT" || version != "HTTP/1.1" || parts.next().is_some() {
        write_proxy_response(&mut client, "405 Method Not Allowed")?;
        return Ok(());
    }
    let Some((host, port)) = parse_proxy_target(target) else {
        write_proxy_response(&mut client, "403 Forbidden")?;
        return Ok(());
    };
    if let Ok(mut values) = requests.lock() {
        values.push(host.clone());
    }
    if !allowed_service_host(&host) || port != 443 {
        write_proxy_response(&mut client, "403 Forbidden")?;
        return Ok(());
    }
    let addresses = (host.as_str(), port).to_socket_addrs()?;
    let mut upstream = None;
    for address in addresses {
        if let Ok(stream) = TcpStream::connect_timeout(&address, Duration::from_secs(20)) {
            upstream = Some(stream);
            break;
        }
    }
    let Some(mut upstream) = upstream else {
        write_proxy_response(&mut client, "502 Bad Gateway")?;
        return Ok(());
    };
    upstream.set_read_timeout(Some(PROCESS_TIMEOUT))?;
    upstream.set_write_timeout(Some(PROCESS_TIMEOUT))?;
    client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
    if header_end < header.len() {
        upstream.write_all(&header[header_end..])?;
    }
    let mut client_reader = client.try_clone()?;
    let mut upstream_writer = upstream.try_clone()?;
    let upload = thread::spawn(move || io::copy(&mut client_reader, &mut upstream_writer));
    let _ = io::copy(&mut upstream, &mut client);
    let _ = upload.join();
    Ok(())
}

fn write_proxy_response(stream: &mut TcpStream, status: &str) -> io::Result<()> {
    stream.write_all(format!("HTTP/1.1 {status}\r\nConnection: close\r\n\r\n").as_bytes())
}

fn parse_proxy_target(target: &str) -> Option<(String, u16)> {
    let (host, port) = target.rsplit_once(':')?;
    if host.is_empty() || host.contains(':') || host.contains('@') {
        return None;
    }
    Some((host.to_ascii_lowercase(), port.parse().ok()?))
}

fn allowed_service_host(host: &str) -> bool {
    let valid_name = host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
            && label
                .as_bytes()
                .last()
                .is_some_and(u8::is_ascii_alphanumeric)
            && label
                .bytes()
                .all(|value| value.is_ascii_alphanumeric() || value == b'-')
    });
    valid_name
        && ["openai.com", "chatgpt.com"]
            .iter()
            .any(|suffix| host == *suffix || host.ends_with(&format!(".{suffix}")))
}

fn outer_profile(
    codex: &Path,
    home: &Path,
    run: &Path,
    snapshot: &Path,
    proxy: SocketAddr,
) -> String {
    format!(
        "(version 1)\n(deny default)\n(allow process*)\n(allow sysctl-read)\n(allow file-read* (subpath \"/System\") (subpath \"/usr\") (subpath \"/bin\") (subpath \"/sbin\") (subpath \"/Library/Apple\") (subpath \"/opt/homebrew\") (subpath \"/private/etc\") (subpath \"/dev\") (subpath {codex}) (subpath {home}) (subpath {run}) (subpath {snapshot}))\n(allow file-write* (subpath {home}) (subpath {run}))\n(deny file-write* (subpath {snapshot}))\n(allow network-outbound (remote ip \"{proxy}\"))\n",
        codex = sandbox_string(codex),
        home = sandbox_string(home),
        run = sandbox_string(run),
        snapshot = sandbox_string(snapshot),
        proxy = proxy,
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
    read_bounded_nofollow(path, 512 * 1024 * 1024)
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

fn move_private_auth(source_home: &Path, destination_home: &Path) -> io::Result<()> {
    let source = source_home.join("auth.json");
    let destination = destination_home.join("auth.json");
    private_regular_metadata(&source)?;
    match fs::symlink_metadata(&destination) {
        Ok(_) => {
            private_regular_metadata(&destination)?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    fs::rename(&source, &destination)?;
    private_regular_metadata(&destination)?;
    Ok(())
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
        let proxy = "127.0.0.1:43123".parse().unwrap();
        let spec = launch_spec(
            Path::new("/opt/homebrew/bin/codex"),
            &base.join("home"),
            &neutral,
            StrictLaunchFiles {
                profile: &base.join("outer.sb"),
                schema: &base.join("schema.json"),
                result: &base.join("result.json"),
            },
            "review /private/tmp/snapshot",
            proxy,
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
                "HTTP_PROXY",
                "HTTPS_PROXY",
                "JUNO_STRICT_ACTIVE",
                "LANG",
                "PATH",
                "TMPDIR",
                "ALL_PROXY",
            ])
        );
        assert!(!keys.contains("OPENAI_API_KEY"));
        assert!(!keys.contains("CODEX_API_KEY"));
        assert!(!keys.contains("SSH_AUTH_SOCK"));
        let command_keys = isolated_environment(&base.join("home"), None)
            .into_iter()
            .map(|(key, _)| key)
            .collect::<BTreeSet<_>>();
        assert!(!command_keys.contains("HTTP_PROXY"));
        assert!(!command_keys.contains("HTTPS_PROXY"));
        assert!(!command_keys.contains("ALL_PROXY"));
    }

    #[test]
    fn outer_sandbox_and_proxy_allow_only_service_tunnels() {
        let base = Path::new("/private/tmp/juno-verifier-test");
        let proxy = "127.0.0.1:43123".parse().unwrap();
        let profile = outer_profile(
            Path::new("/opt/homebrew/bin/codex"),
            &base.join("home"),
            &base.join("run"),
            &base.join("snapshot"),
            proxy,
        );
        assert!(profile.contains("(allow network-outbound (remote ip \"127.0.0.1:43123\"))"));
        assert!(!profile.contains("(allow network-outbound)"));
        assert_eq!(
            parse_proxy_target("api.openai.com:443"),
            Some(("api.openai.com".into(), 443))
        );
        assert!(allowed_service_host("api.openai.com"));
        assert!(allowed_service_host("chatgpt.com"));
        assert!(!allowed_service_host("openai.com.example.org"));
        assert!(!allowed_service_host("127.0.0.1"));
        assert!(parse_proxy_target("api.openai.com@127.0.0.1:443").is_none());
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
    fn strict_contract_has_unique_canaries() {
        assert_eq!(required_canaries().unwrap().len(), 15);
    }

    #[test]
    fn login_credential_moves_without_leaving_a_copy() {
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path().canonicalize().unwrap();
        let source = base.join("source");
        let destination = base.join("destination");
        fs::create_dir(&source).unwrap();
        fs::create_dir(&destination).unwrap();
        let auth = source.join("auth.json");
        fs::write(&auth, b"credential").unwrap();
        fs::set_permissions(&auth, fs::Permissions::from_mode(0o600)).unwrap();
        move_private_auth(&source, &destination).unwrap();
        assert!(!source.join("auth.json").exists());
        assert_eq!(
            fs::read(destination.join("auth.json")).unwrap(),
            b"credential"
        );
    }
}
