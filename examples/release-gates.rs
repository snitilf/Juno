use juno::gates::{
    CanaryRecord, CandidateRecord, CertificationCorpus, CertificationRun, freeze_candidate,
    score_run,
};
use std::env;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

const INPUT_LIMIT: u64 = 32 * 1024 * 1024;

fn main() {
    if let Err(error) = run() {
        eprintln!("release-gates: {error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), String> {
    let mut arguments = env::args_os().skip(1);
    let command = arguments
        .next()
        .and_then(|value| value.into_string().ok())
        .ok_or_else(usage)?;
    let rest = arguments.collect::<Vec<_>>();
    match command.as_str() {
        "freeze" => freeze(&rest),
        "seal-canaries" => seal_canaries(&rest),
        "score" => score(&rest),
        _ => Err(usage()),
    }
}

fn freeze(arguments: &[std::ffi::OsString]) -> Result<(), String> {
    let values = parse_pairs(arguments)?;
    require_only(
        &values,
        &["--repo", "--binary", "--verified-on", "--output"],
    )?;
    let repo = required_path(&values, "--repo")?;
    let binary = required_path(&values, "--binary")?;
    let verified_on = required_string(&values, "--verified-on")?;
    let output = required_path(&values, "--output")?;
    let candidate = freeze_candidate(&repo, &binary, &verified_on)?;
    write_new_json(&output, &candidate)?;
    println!("candidate: {}", candidate.fingerprint()?);
    Ok(())
}

fn seal_canaries(arguments: &[std::ffi::OsString]) -> Result<(), String> {
    require_certification_account()?;
    require_unsandboxed()?;
    let values = parse_pairs(arguments)?;
    let candidate_path = required_path(&values, "--candidate")?;
    let evidence_path = required_path(&values, "--evidence")?;
    let juno_path = required_path(&values, "--juno")?;
    let codex_path = required_path(&values, "--codex")?;
    let state_home = required_path(&values, "--state-home")?;
    let evidence_root = required_path(&values, "--evidence-root")?;
    require_only(
        &values,
        &[
            "--candidate",
            "--evidence",
            "--evidence-root",
            "--juno",
            "--codex",
            "--state-home",
        ],
    )?;
    let candidate: CandidateRecord = read_json(&candidate_path)?;
    let record: CanaryRecord = read_json(&evidence_path)?;
    record.validate(&candidate)?;
    if file_hash(&juno_path)? != record.juno_sha256
        || file_hash(&codex_path)? != record.codex_sha256
    {
        return Err("canary evidence does not match the supplied binaries".into());
    }
    for (name, evidence) in &record.checks {
        let path = evidence_root.join(format!("{name}.json"));
        if file_hash(&path)? != evidence.evidence_sha256 {
            return Err(format!("canary artifact hash mismatch: {name}"));
        }
    }
    let auth = state_home.join("verifier/home/auth.json");
    require_private_regular(&auth)?;
    let fingerprint = candidate.fingerprint()?;
    write_new_json(
        &state_home.join(format!("release/candidates/{fingerprint}.json")),
        &candidate,
    )?;
    write_new_json(
        &state_home.join(format!("verifier/evidence/{fingerprint}/canaries.json")),
        &record,
    )?;
    write_replaced_json(&state_home.join("release/candidate.json"), &candidate)?;
    let destination = state_home.join("verifier/canaries.json");
    write_replaced_json(&destination, &record)?;
    println!("sealed canaries: {}", record.passed_names().len());
    Ok(())
}

fn score(arguments: &[std::ffi::OsString]) -> Result<(), String> {
    require_certification_account()?;
    let values = parse_pairs(arguments)?;
    require_only(
        &values,
        &[
            "--candidate",
            "--corpus",
            "--run",
            "--evidence-root",
            "--environment",
            "--output",
        ],
    )?;
    let candidate: CandidateRecord = read_json(&required_path(&values, "--candidate")?)?;
    let corpus: CertificationCorpus = read_json(&required_path(&values, "--corpus")?)?;
    let run: CertificationRun = read_json(&required_path(&values, "--run")?)?;
    let evidence_root = required_path(&values, "--evidence-root")?;
    let environment = required_path(&values, "--environment")?;
    let output = required_path(&values, "--output")?;
    if file_hash(&environment)? != run.environment_sha256 {
        return Err("certification environment hash mismatch".into());
    }
    for outcome in &run.outcomes {
        let path = evidence_root.join(format!("{}.json", outcome.id));
        if file_hash(&path)? != outcome.evidence_sha256 {
            return Err(format!(
                "certification artifact hash mismatch: {}",
                outcome.id
            ));
        }
    }
    let evidence = score_run(&candidate, &corpus, &run)?;
    if !evidence.report.passed {
        return Err(format!(
            "certification failed: {}",
            evidence.report.failures.join("; ")
        ));
    }
    write_new_json(&output, &evidence)?;
    println!("certification passed");
    Ok(())
}

fn require_only(
    values: &std::collections::BTreeMap<String, PathBuf>,
    allowed: &[&str],
) -> Result<(), String> {
    if values
        .keys()
        .any(|key| !allowed.iter().any(|allowed| key == allowed))
    {
        return Err(usage());
    }
    Ok(())
}

fn parse_pairs(
    arguments: &[std::ffi::OsString],
) -> Result<std::collections::BTreeMap<String, PathBuf>, String> {
    if !arguments.len().is_multiple_of(2) {
        return Err(usage());
    }
    let mut values = std::collections::BTreeMap::new();
    for pair in arguments.chunks_exact(2) {
        let key = pair[0]
            .to_str()
            .ok_or("argument names must be UTF-8")?
            .to_string();
        if !key.starts_with("--") || values.insert(key, pair[1].clone().into()).is_some() {
            return Err(usage());
        }
    }
    Ok(values)
}

fn required_path(
    values: &std::collections::BTreeMap<String, PathBuf>,
    key: &str,
) -> Result<PathBuf, String> {
    values
        .get(key)
        .cloned()
        .ok_or_else(|| format!("missing {key}"))
}

fn required_string(
    values: &std::collections::BTreeMap<String, PathBuf>,
    key: &str,
) -> Result<String, String> {
    values
        .get(key)
        .and_then(|value| value.to_str())
        .map(str::to_string)
        .ok_or_else(|| format!("missing or invalid {key}"))
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, String> {
    let content = read_regular(path, INPUT_LIMIT)?;
    serde_json::from_slice(&content).map_err(|error| error.to_string())
}

fn file_hash(path: &Path) -> Result<String, String> {
    Ok(sha256(&read_regular(path, 512 * 1024 * 1024)?))
}

fn read_regular(path: &Path, limit: u64) -> Result<Vec<u8>, String> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW_ANY)
        .open(path)
        .map_err(|error| error.to_string())?;
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_file() || metadata.nlink() != 1 || metadata.len() > limit {
        return Err("input file has unsafe metadata".into());
    }
    let mut content = Vec::new();
    Read::by_ref(&mut file)
        .take(limit + 1)
        .read_to_end(&mut content)
        .map_err(|error| error.to_string())?;
    if content.len() as u64 > limit {
        return Err("input file exceeds its limit".into());
    }
    Ok(content)
}

fn write_new_json(path: &Path, value: &impl serde::Serialize) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
            .map_err(|error| error.to_string())?;
    }
    let content = serde_json::to_vec_pretty(value).map_err(|error| error.to_string())?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| error.to_string())?;
    file.write_all(&content)
        .map_err(|error| error.to_string())?;
    file.sync_all().map_err(|error| error.to_string())
}

fn write_replaced_json(path: &Path, value: &impl serde::Serialize) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
            .map_err(|error| error.to_string())?;
    }
    let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
    write_new_json(&temporary, value)?;
    fs::rename(&temporary, path).map_err(|error| error.to_string())
}

fn require_private_regular(path: &Path) -> Result<(), String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW_ANY)
        .open(path)
        .map_err(|_| "dedicated verifier login is missing".to_string())?;
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_file() || metadata.nlink() != 1 || metadata.permissions().mode() & 0o077 != 0 {
        return Err("dedicated verifier login has unsafe metadata".into());
    }
    Ok(())
}

fn require_certification_account() -> Result<(), String> {
    if env::var("JUNO_CERTIFICATION_ACCOUNT").as_deref() != Ok("1") {
        return Err("set JUNO_CERTIFICATION_ACCOUNT=1 inside the disposable account".into());
    }
    Ok(())
}

fn require_unsandboxed() -> Result<(), String> {
    let status = Command::new("/usr/bin/sandbox-exec")
        .args(["-p", "(version 1)(allow default)", "/usr/bin/true"])
        .status()
        .map_err(|error| error.to_string())?;
    if !status.success() {
        return Err("canary sealing must start outside an existing sandbox".into());
    }
    Ok(())
}

fn sha256(content: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(content))
}

fn usage() -> String {
    "usage: release-gates freeze|seal-canaries|score [named arguments]".into()
}
