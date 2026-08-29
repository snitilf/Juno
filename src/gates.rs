use crate::eval::{CertificationCounts, CertificationReport, score_certification};
use crate::secure_fs::hex_sha256;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::OpenOptions;
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::process::Command;

const CATALOG_SOURCE: &[u8] = include_bytes!("../config/model-catalog.toml");
const COMPATIBILITY_SOURCE: &[u8] = include_bytes!("../config/compatibility.toml");
const ROUTING_SOURCE: &[u8] = include_bytes!("../templates/instructions/routing-policy.md");
const ROUTING_DEFAULTS_SOURCE: &str = include_str!("../config/routing-defaults.toml");
const DEVELOPMENT_SOURCE: &str = include_str!("../evals/development-cases.toml");

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DevelopmentCase {
    pub id: String,
    pub task: String,
    pub expected_owner: String,
    pub expected_verifier: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DevelopmentSuite {
    pub schema_version: u32,
    pub status: String,
    pub cases: Vec<DevelopmentCase>,
}

impl DevelopmentSuite {
    pub fn load() -> Result<Self, String> {
        let suite: Self = toml::from_str(DEVELOPMENT_SOURCE).map_err(|error| error.to_string())?;
        suite.validate()?;
        Ok(suite)
    }

    pub fn validate(&self) -> Result<(), String> {
        let owners = [
            "main",
            "scout",
            "surveyor",
            "mech_executor",
            "executor",
            "security_executor",
        ];
        let verifiers = ["light_verifier", "verifier", "heavy_verifier"];
        let mut ids = BTreeSet::new();
        if self.schema_version != 1 || self.status != "open" || self.cases.is_empty() {
            return Err("development suite identity is invalid".into());
        }
        for case in &self.cases {
            if !safe_id(&case.id)
                || !ids.insert(case.id.clone())
                || case.task.is_empty()
                || case.task.len() > 4096
                || !owners.contains(&case.expected_owner.as_str())
                || !verifiers.contains(&case.expected_verifier.as_str())
            {
                return Err("development case is invalid".into());
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateRecord {
    pub schema_version: u32,
    pub verified_on: String,
    pub source_commit: String,
    pub source_clean: bool,
    pub juno_version: String,
    pub binary_sha256: String,
    pub bundle_sha256: String,
    pub catalog_sha256: String,
    pub routing_sha256: String,
    pub compatibility_sha256: String,
}

impl CandidateRecord {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != 1
            || !valid_date(&self.verified_on)
            || !self.source_clean
            || !valid_hex(&self.source_commit, 40)
            || self.juno_version != crate::VERSION
        {
            return Err("candidate identity is invalid".into());
        }
        for value in [
            &self.binary_sha256,
            &self.bundle_sha256,
            &self.catalog_sha256,
            &self.routing_sha256,
            &self.compatibility_sha256,
        ] {
            if !valid_hex(value, 64) {
                return Err("candidate hash is invalid".into());
            }
        }
        if self.catalog_sha256 != hex_sha256(CATALOG_SOURCE)
            || self.routing_sha256 != hex_sha256(ROUTING_SOURCE)
            || self.compatibility_sha256 != hex_sha256(COMPATIBILITY_SOURCE)
            || self.bundle_sha256 != crate::lifecycle::release_bundle_sha256()
        {
            return Err("candidate assets do not match this build".into());
        }
        Ok(())
    }

    pub fn fingerprint(&self) -> Result<String, String> {
        self.validate()?;
        let canonical = serde_json::to_vec(self).map_err(|error| error.to_string())?;
        Ok(hex_sha256(&canonical))
    }
}

pub fn freeze_candidate(
    repo: &Path,
    binary: &Path,
    verified_on: &str,
) -> Result<CandidateRecord, String> {
    let repo = repo.canonicalize().map_err(|error| error.to_string())?;
    let status = git_output(
        &repo,
        &["status", "--porcelain=v2", "--untracked-files=all"],
    )?;
    if !status.is_empty() {
        return Err("candidate repository is not clean".into());
    }
    let source_commit = String::from_utf8(git_output(&repo, &["rev-parse", "--verify", "HEAD"])?)
        .map_err(|error| error.to_string())?
        .trim()
        .to_string();
    let binary = read_regular_nofollow(binary, 512 * 1024 * 1024)
        .map_err(|error| format!("candidate binary is unsafe: {error}"))?;
    let record = CandidateRecord {
        schema_version: 1,
        verified_on: verified_on.into(),
        source_commit,
        source_clean: true,
        juno_version: crate::VERSION.into(),
        binary_sha256: hex_sha256(&binary),
        bundle_sha256: crate::lifecycle::release_bundle_sha256(),
        catalog_sha256: hex_sha256(CATALOG_SOURCE),
        routing_sha256: hex_sha256(ROUTING_SOURCE),
        compatibility_sha256: hex_sha256(COMPATIBILITY_SOURCE),
    };
    record.validate()?;
    Ok(record)
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CanaryEvidence {
    pub passed: bool,
    pub evidence_sha256: String,
    pub summary: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CanaryRecord {
    pub schema_version: u32,
    pub verified_on: String,
    pub candidate_sha256: String,
    pub juno_sha256: String,
    pub codex_sha256: String,
    pub execution_context: String,
    pub checks: BTreeMap<String, CanaryEvidence>,
}

impl CanaryRecord {
    pub fn validate(&self, candidate: &CandidateRecord) -> Result<(), String> {
        candidate.validate()?;
        if self.schema_version != 1
            || !valid_date(&self.verified_on)
            || self.candidate_sha256 != candidate.fingerprint()?
            || self.juno_sha256 != candidate.binary_sha256
            || !valid_hex(&self.codex_sha256, 64)
            || self.execution_context != "unsandboxed-dedicated-account"
        {
            return Err("canary identity is invalid".into());
        }
        if self.checks.keys().cloned().collect::<BTreeSet<_>>() != required_canaries()? {
            return Err("canary set is incomplete".into());
        }
        for evidence in self.checks.values() {
            if !evidence.passed
                || !valid_hex(&evidence.evidence_sha256, 64)
                || evidence.summary.is_empty()
                || evidence.summary.len() > 4096
            {
                return Err("canary evidence is invalid".into());
            }
        }
        Ok(())
    }

    pub fn passed_names(&self) -> BTreeSet<String> {
        self.checks
            .iter()
            .filter(|(_, evidence)| evidence.passed)
            .map(|(name, _)| name.clone())
            .collect()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ClientKind {
    Cli,
    Desktop,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CaseKind {
    Routing,
    SeededDefect,
    Clean,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DefectSeverity {
    Critical,
    High,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CertificationCase {
    pub id: String,
    pub kind: CaseKind,
    pub requirement: String,
    pub fixture_sha256: String,
    pub expected_owner: Option<String>,
    pub expected_verifier: Option<String>,
    pub seeded_severity: Option<DefectSeverity>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CertificationCorpus {
    pub schema_version: u32,
    pub client: ClientKind,
    pub candidate_sha256: String,
    pub created_after_freeze: bool,
    pub generation_id: String,
    pub preregistered_infrastructure_failures: Vec<String>,
    pub cases: Vec<CertificationCase>,
}

impl CertificationCorpus {
    pub fn validate(&self, candidate: &CandidateRecord) -> Result<(), String> {
        candidate.validate()?;
        if self.schema_version != 1
            || self.candidate_sha256 != candidate.fingerprint()?
            || !self.created_after_freeze
            || self.generation_id.is_empty()
            || self.generation_id.len() > 200
        {
            return Err("certification corpus identity is invalid".into());
        }
        let mut ids = BTreeSet::new();
        let mut counts = [0u32; 3];
        for case in &self.cases {
            if !safe_id(&case.id)
                || case.id.len() > 200
                || !ids.insert(case.id.clone())
                || case.requirement.is_empty()
                || case.requirement.len() > 20_000
                || !valid_hex(&case.fixture_sha256, 64)
            {
                return Err("certification case is invalid".into());
            }
            match case.kind {
                CaseKind::Routing => {
                    counts[0] += 1;
                    if case.expected_owner.as_deref().is_none_or(str::is_empty)
                        || case.expected_verifier.as_deref().is_none_or(str::is_empty)
                        || case.seeded_severity.is_some()
                    {
                        return Err("routing case expectations are invalid".into());
                    }
                }
                CaseKind::SeededDefect => {
                    counts[1] += 1;
                    if case.seeded_severity.is_none()
                        || case.expected_owner.is_some()
                        || case.expected_verifier.is_some()
                    {
                        return Err("seeded defect case expectations are invalid".into());
                    }
                }
                CaseKind::Clean => {
                    counts[2] += 1;
                    if case.seeded_severity.is_some()
                        || case.expected_owner.is_some()
                        || case.expected_verifier.is_some()
                    {
                        return Err("clean case expectations are invalid".into());
                    }
                }
            }
        }
        if counts != [120, 120, 120] || self.cases.len() != 360 {
            return Err("certification corpus must contain 120 cases of each kind".into());
        }
        let mut infrastructure = BTreeSet::new();
        for value in &self.preregistered_infrastructure_failures {
            if value.is_empty() || value.len() > 200 || !infrastructure.insert(value) {
                return Err("infrastructure failure list is invalid".into());
            }
        }
        Ok(())
    }

    pub fn fingerprint(&self, candidate: &CandidateRecord) -> Result<String, String> {
        self.validate(candidate)?;
        let canonical = serde_json::to_vec(self).map_err(|error| error.to_string())?;
        Ok(hex_sha256(&canonical))
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaseOutcome {
    pub id: String,
    pub instruction_passed: bool,
    pub routing_correct: Option<bool>,
    pub defect_detected: Option<bool>,
    pub false_positive: Option<bool>,
    pub unauthorized_changes: u32,
    pub infrastructure_failure: Option<String>,
    pub evidence_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CertificationRun {
    pub schema_version: u32,
    pub client: ClientKind,
    pub candidate_sha256: String,
    pub corpus_sha256: String,
    pub run_id: String,
    pub environment_sha256: String,
    pub outcomes: Vec<CaseOutcome>,
}

#[derive(Clone, Debug, Serialize)]
pub struct CertificationEvidence {
    pub client: ClientKind,
    pub candidate_sha256: String,
    pub corpus_sha256: String,
    pub counts: CertificationCounts,
    pub report: CertificationReport,
}

pub fn score_run(
    candidate: &CandidateRecord,
    corpus: &CertificationCorpus,
    run: &CertificationRun,
) -> Result<CertificationEvidence, String> {
    corpus.validate(candidate)?;
    let corpus_sha256 = corpus.fingerprint(candidate)?;
    if run.schema_version != 1
        || run.client != corpus.client
        || run.candidate_sha256 != candidate.fingerprint()?
        || run.corpus_sha256 != corpus_sha256
        || !safe_id(&run.run_id)
        || run.run_id.len() > 200
        || !valid_hex(&run.environment_sha256, 64)
    {
        return Err("certification run identity is invalid".into());
    }
    let cases = corpus
        .cases
        .iter()
        .map(|case| (case.id.as_str(), case))
        .collect::<BTreeMap<_, _>>();
    let mut outcomes = BTreeMap::new();
    for outcome in &run.outcomes {
        if !cases.contains_key(outcome.id.as_str())
            || outcomes.insert(outcome.id.as_str(), outcome).is_some()
            || !valid_hex(&outcome.evidence_sha256, 64)
        {
            return Err("certification outcome is invalid".into());
        }
        if let Some(reason) = &outcome.infrastructure_failure {
            if !corpus
                .preregistered_infrastructure_failures
                .iter()
                .any(|allowed| allowed == reason)
            {
                return Err("infrastructure failure was not preregistered".into());
            }
            return Err("certification run is blocked by an infrastructure failure".into());
        }
    }
    if outcomes.len() != cases.len() {
        return Err("certification run is incomplete".into());
    }
    let mut counts = CertificationCounts {
        required_instruction_passes: 0,
        required_instruction_total: 0,
        seeded_defects_detected: 0,
        seeded_defect_total: 0,
        critical_or_high_escapes: 0,
        unauthorized_changes: 0,
        routing_correct: 0,
        routing_total: 0,
        clean_false_positives: 0,
        clean_total: 0,
    };
    for case in &corpus.cases {
        let outcome = outcomes[case.id.as_str()];
        counts.unauthorized_changes = counts
            .unauthorized_changes
            .saturating_add(outcome.unauthorized_changes);
        match case.kind {
            CaseKind::Routing => {
                if outcome.defect_detected.is_some() || outcome.false_positive.is_some() {
                    return Err("routing outcome has unrelated fields".into());
                }
                counts.required_instruction_total += 1;
                counts.routing_total += 1;
                counts.required_instruction_passes += u32::from(outcome.instruction_passed);
                counts.routing_correct += u32::from(
                    outcome
                        .routing_correct
                        .ok_or("routing outcome is missing its result")?,
                );
            }
            CaseKind::SeededDefect => {
                if outcome.routing_correct.is_some() || outcome.false_positive.is_some() {
                    return Err("seeded defect outcome has unrelated fields".into());
                }
                let detected = outcome
                    .defect_detected
                    .ok_or("seeded defect outcome is missing its result")?;
                counts.seeded_defect_total += 1;
                counts.seeded_defects_detected += u32::from(detected);
                if !detected {
                    counts.critical_or_high_escapes += 1;
                }
            }
            CaseKind::Clean => {
                if outcome.routing_correct.is_some() || outcome.defect_detected.is_some() {
                    return Err("clean outcome has unrelated fields".into());
                }
                counts.clean_total += 1;
                counts.clean_false_positives += u32::from(
                    outcome
                        .false_positive
                        .ok_or("clean outcome is missing its result")?,
                );
            }
        }
    }
    let report = score_certification(&counts);
    Ok(CertificationEvidence {
        client: run.client,
        candidate_sha256: run.candidate_sha256.clone(),
        corpus_sha256,
        counts,
        report,
    })
}

pub fn required_canaries() -> Result<BTreeSet<String>, String> {
    let value: toml::Value =
        toml::from_str(ROUTING_DEFAULTS_SOURCE).map_err(|error| error.to_string())?;
    let names = value
        .get("strict_verification")
        .and_then(|table| table.get("required_canaries"))
        .and_then(toml::Value::as_array)
        .ok_or("strict canary list is missing")?;
    let mut result = BTreeSet::new();
    for name in names {
        let name = name.as_str().ok_or("strict canary name is invalid")?;
        if !result.insert(name.to_string()) {
            return Err("strict canary list contains duplicates".into());
        }
    }
    if result.len() != 15 {
        return Err("strict canary list must contain 15 checks".into());
    }
    Ok(result)
}

fn git_output(repo: &Path, arguments: &[&str]) -> Result<Vec<u8>, String> {
    let output = Command::new("git")
        .args([
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.hooksPath=/dev/null",
        ])
        .arg("-C")
        .arg(repo)
        .args(arguments)
        .output()
        .map_err(|error| error.to_string())?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
    }
    Ok(output.stdout)
}

fn read_regular_nofollow(path: &Path, limit: u64) -> io::Result<Vec<u8>> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW_ANY)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.nlink() != 1 || metadata.len() > limit {
        return Err(io::Error::other("file has unsafe metadata"));
    }
    let mut content = Vec::new();
    Read::by_ref(&mut file)
        .take(limit + 1)
        .read_to_end(&mut content)?;
    if content.len() as u64 > limit {
        return Err(io::Error::other("file exceeds its read limit"));
    }
    Ok(content)
}

fn valid_hex(value: &str, length: usize) -> bool {
    value.len() == length && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn valid_date(value: &str) -> bool {
    value.len() == 10
        && value.as_bytes()[4] == b'-'
        && value.as_bytes()[7] == b'-'
        && value
            .bytes()
            .enumerate()
            .all(|(index, byte)| index == 4 || index == 7 || byte.is_ascii_digit())
}

fn safe_id(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate() -> CandidateRecord {
        CandidateRecord {
            schema_version: 1,
            verified_on: "2026-08-29".into(),
            source_commit: "a".repeat(40),
            source_clean: true,
            juno_version: crate::VERSION.into(),
            binary_sha256: "b".repeat(64),
            bundle_sha256: crate::lifecycle::release_bundle_sha256(),
            catalog_sha256: hex_sha256(CATALOG_SOURCE),
            routing_sha256: hex_sha256(ROUTING_SOURCE),
            compatibility_sha256: hex_sha256(COMPATIBILITY_SOURCE),
        }
    }

    fn corpus() -> CertificationCorpus {
        let candidate = candidate();
        let mut cases = Vec::new();
        for index in 0..120 {
            cases.push(CertificationCase {
                id: format!("routing-{index:03}"),
                kind: CaseKind::Routing,
                requirement: "Choose the expected bounded role.".into(),
                fixture_sha256: "d".repeat(64),
                expected_owner: Some("scout".into()),
                expected_verifier: Some("light_verifier".into()),
                seeded_severity: None,
            });
            cases.push(CertificationCase {
                id: format!("defect-{index:03}"),
                kind: CaseKind::SeededDefect,
                requirement: "Find the seeded material defect.".into(),
                fixture_sha256: "e".repeat(64),
                expected_owner: None,
                expected_verifier: None,
                seeded_severity: Some(DefectSeverity::High),
            });
            cases.push(CertificationCase {
                id: format!("clean-{index:03}"),
                kind: CaseKind::Clean,
                requirement: "Do not invent a material finding.".into(),
                fixture_sha256: "f".repeat(64),
                expected_owner: None,
                expected_verifier: None,
                seeded_severity: None,
            });
        }
        CertificationCorpus {
            schema_version: 1,
            client: ClientKind::Cli,
            candidate_sha256: candidate.fingerprint().unwrap(),
            created_after_freeze: true,
            generation_id: "fresh-set-1".into(),
            preregistered_infrastructure_failures: vec!["service-unavailable".into()],
            cases,
        }
    }

    fn passing_run(corpus: &CertificationCorpus) -> CertificationRun {
        let candidate = candidate();
        let outcomes = corpus
            .cases
            .iter()
            .map(|case| CaseOutcome {
                id: case.id.clone(),
                instruction_passed: true,
                routing_correct: (case.kind == CaseKind::Routing).then_some(true),
                defect_detected: (case.kind == CaseKind::SeededDefect).then_some(true),
                false_positive: (case.kind == CaseKind::Clean).then_some(false),
                unauthorized_changes: 0,
                infrastructure_failure: None,
                evidence_sha256: "1".repeat(64),
            })
            .collect();
        CertificationRun {
            schema_version: 1,
            client: corpus.client,
            candidate_sha256: candidate.fingerprint().unwrap(),
            corpus_sha256: corpus.fingerprint(&candidate).unwrap(),
            run_id: "run-1".into(),
            environment_sha256: "2".repeat(64),
            outcomes,
        }
    }

    #[test]
    fn candidate_and_canary_contracts_are_bound_to_hashes() {
        let candidate = candidate();
        candidate.validate().unwrap();
        let checks = required_canaries()
            .unwrap()
            .into_iter()
            .map(|name| {
                (
                    name,
                    CanaryEvidence {
                        passed: true,
                        evidence_sha256: "3".repeat(64),
                        summary: "direct evidence".into(),
                    },
                )
            })
            .collect();
        let record = CanaryRecord {
            schema_version: 1,
            verified_on: "2026-08-29".into(),
            candidate_sha256: candidate.fingerprint().unwrap(),
            juno_sha256: candidate.binary_sha256.clone(),
            codex_sha256: "4".repeat(64),
            execution_context: "unsandboxed-dedicated-account".into(),
            checks,
        };
        record.validate(&candidate).unwrap();
    }

    #[test]
    fn open_development_cases_are_valid_and_cover_every_role() {
        let suite = DevelopmentSuite::load().unwrap();
        assert_eq!(suite.cases.len(), 24);
        let routes = suite
            .cases
            .iter()
            .flat_map(|case| [&case.expected_owner, &case.expected_verifier])
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        for role in [
            "main",
            "scout",
            "surveyor",
            "mech_executor",
            "executor",
            "security_executor",
            "light_verifier",
            "verifier",
            "heavy_verifier",
        ] {
            assert!(routes.contains(role), "missing role {role}");
        }
    }

    #[test]
    fn certification_requires_one_complete_frozen_run() {
        let candidate = candidate();
        let corpus = corpus();
        let run = passing_run(&corpus);
        let evidence = score_run(&candidate, &corpus, &run).unwrap();
        assert!(evidence.report.passed);
        let mut duplicate = run;
        duplicate.outcomes.push(duplicate.outcomes[0].clone());
        assert!(score_run(&candidate, &corpus, &duplicate).is_err());
    }

    #[test]
    fn unregistered_infrastructure_failures_are_rejected() {
        let candidate = candidate();
        let corpus = corpus();
        let mut run = passing_run(&corpus);
        run.outcomes[0].infrastructure_failure = Some("unexpected".into());
        assert!(score_run(&candidate, &corpus, &run).is_err());
    }
}
