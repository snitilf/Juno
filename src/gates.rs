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

#[doc(hidden)]
pub fn logical_bundle_sha256() -> String {
    crate::lifecycle::release_bundle_sha256()
}

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
pub struct DevelopmentOutcome {
    pub id: String,
    pub profile: String,
    pub owner: String,
    pub verifier: String,
    pub instruction_passed: bool,
    pub unauthorized_changes: u32,
    pub evidence_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DevelopmentRepeat {
    pub index: u32,
    pub order_sha256: String,
    pub outcomes: Vec<DevelopmentOutcome>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DevelopmentRun {
    pub schema_version: u32,
    pub factor: String,
    pub baseline_profile: String,
    pub candidate_profile: String,
    pub randomized: bool,
    pub repeats: Vec<DevelopmentRepeat>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DevelopmentEvidence {
    pub factor: String,
    pub baseline_profile: String,
    pub candidate_profile: String,
    pub baseline_correct: u32,
    pub candidate_correct: u32,
    pub total_per_profile: u32,
    pub winner: String,
    pub run_sha256: String,
    pub raw_artifacts_sha256: String,
}

pub fn score_development(run: &DevelopmentRun) -> Result<DevelopmentEvidence, String> {
    let suite = DevelopmentSuite::load()?;
    if run.schema_version != 1
        || !safe_id(&run.factor)
        || !safe_id(&run.baseline_profile)
        || !safe_id(&run.candidate_profile)
        || run.baseline_profile == run.candidate_profile
        || !run.randomized
        || run.repeats.len() != 3
    {
        return Err("development run identity is invalid".into());
    }
    let cases = suite
        .cases
        .iter()
        .map(|case| (case.id.as_str(), case))
        .collect::<BTreeMap<_, _>>();
    let profiles = [&run.baseline_profile, &run.candidate_profile];
    let mut baseline_correct = 0;
    let mut candidate_correct = 0;
    let mut evidence_hashes = Vec::new();
    let mut unique_evidence = BTreeSet::new();
    let mut repeat_indexes = BTreeSet::new();
    for repeat in &run.repeats {
        if !(1..=3).contains(&repeat.index)
            || !repeat_indexes.insert(repeat.index)
            || !valid_hex(&repeat.order_sha256, 64)
        {
            return Err("development repeat identity is invalid".into());
        }
        let mut seen = BTreeSet::new();
        for outcome in &repeat.outcomes {
            let Some(case) = cases.get(outcome.id.as_str()) else {
                return Err("development outcome references an unknown case".into());
            };
            if !profiles.contains(&&outcome.profile)
                || !seen.insert((outcome.profile.as_str(), outcome.id.as_str()))
                || !valid_hex(&outcome.evidence_sha256, 64)
                || !unique_evidence.insert(outcome.evidence_sha256.as_str())
                || outcome.unauthorized_changes != 0
            {
                return Err("development outcome is invalid".into());
            }
            let correct = outcome.instruction_passed
                && outcome.owner == case.expected_owner
                && outcome.verifier == case.expected_verifier;
            if outcome.profile == run.baseline_profile {
                baseline_correct += u32::from(correct);
            } else {
                candidate_correct += u32::from(correct);
            }
            evidence_hashes.push(outcome.evidence_sha256.as_str());
        }
        if seen.len() != cases.len() * 2 {
            return Err("development repeat is incomplete".into());
        }
    }
    let total_per_profile = u32::try_from(cases.len() * 3).map_err(|error| error.to_string())?;
    let winner = if candidate_correct > baseline_correct {
        run.candidate_profile.clone()
    } else if baseline_correct > candidate_correct {
        run.baseline_profile.clone()
    } else {
        "tie".into()
    };
    Ok(DevelopmentEvidence {
        factor: run.factor.clone(),
        baseline_profile: run.baseline_profile.clone(),
        candidate_profile: run.candidate_profile.clone(),
        baseline_correct,
        candidate_correct,
        total_per_profile,
        winner,
        run_sha256: hex_sha256(&serde_json::to_vec(run).map_err(|error| error.to_string())?),
        raw_artifacts_sha256: aggregate_hashes(&mut evidence_hashes)?,
    })
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateRecord {
    pub schema_version: u32,
    pub verified_on: String,
    pub frozen_at_unix: u64,
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
            || self.frozen_at_unix == 0
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
    validate_macos_arm64_binary(&binary)?;
    let record = CandidateRecord {
        schema_version: 1,
        verified_on: verified_on.into(),
        frozen_at_unix: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|error| error.to_string())?
            .as_secs(),
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

#[doc(hidden)]
pub fn validate_candidate_binary(candidate: &CandidateRecord, binary: &Path) -> Result<(), String> {
    candidate.validate()?;
    let content = read_regular_nofollow(binary, 512 * 1024 * 1024)
        .map_err(|error| format!("candidate binary is unsafe: {error}"))?;
    validate_macos_arm64_binary(&content)?;
    if hex_sha256(&content) != candidate.binary_sha256 {
        return Err("candidate binary hash does not match".into());
    }
    Ok(())
}

fn validate_macos_arm64_binary(content: &[u8]) -> Result<(), String> {
    const MACHO_64_LE: [u8; 4] = [0xcf, 0xfa, 0xed, 0xfe];
    const CPU_TYPE_ARM64: u32 = 0x0100_000c;
    if content.get(..4) != Some(MACHO_64_LE.as_slice())
        || content
            .get(4..8)
            .and_then(|bytes| bytes.try_into().ok())
            .map(u32::from_le_bytes)
            != Some(CPU_TYPE_ARM64)
    {
        return Err("candidate binary is not a native macOS arm64 executable".into());
    }
    Ok(())
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
pub struct CanaryArtifact {
    pub schema_version: u32,
    pub name: String,
    pub candidate_sha256: String,
    pub juno_sha256: String,
    pub codex_sha256: String,
    pub execution_context: String,
    pub passed: bool,
    pub probe_sha256: String,
    pub output_sha256: String,
    pub environment_sha256: String,
    pub summary: String,
}

impl CanaryArtifact {
    pub fn validate(&self, candidate: &CandidateRecord, name: &str) -> Result<(), String> {
        candidate.validate()?;
        if self.schema_version != 1
            || self.name != name
            || self.candidate_sha256 != candidate.fingerprint()?
            || self.juno_sha256 != candidate.binary_sha256
            || !valid_hex(&self.codex_sha256, 64)
            || self.execution_context != "unsandboxed-dedicated-account"
            || !self.passed
            || !valid_hex(&self.probe_sha256, 64)
            || !valid_hex(&self.output_sha256, 64)
            || !valid_hex(&self.environment_sha256, 64)
            || self.summary.is_empty()
            || self.summary.len() > 4096
        {
            return Err(format!("canary artifact is invalid: {name}"));
        }
        Ok(())
    }
}

pub fn collect_canaries(
    candidate: &CandidateRecord,
    codex_sha256: String,
    verified_on: String,
    artifacts: BTreeMap<String, (CanaryArtifact, String)>,
) -> Result<CanaryRecord, String> {
    if artifacts.keys().cloned().collect::<BTreeSet<_>>() != required_canaries()? {
        return Err("canary artifact set is incomplete".into());
    }
    let mut checks = BTreeMap::new();
    for (name, (artifact, raw_sha256)) in artifacts {
        artifact.validate(candidate, &name)?;
        if artifact.codex_sha256 != codex_sha256 || !valid_hex(&raw_sha256, 64) {
            return Err(format!("canary artifact binding is invalid: {name}"));
        }
        checks.insert(
            name,
            CanaryEvidence {
                passed: true,
                evidence_sha256: raw_sha256,
                summary: artifact.summary,
            },
        );
    }
    let record = CanaryRecord {
        schema_version: 1,
        verified_on,
        candidate_sha256: candidate.fingerprint()?,
        juno_sha256: candidate.binary_sha256.clone(),
        codex_sha256,
        execution_context: "unsandboxed-dedicated-account".into(),
        checks,
    };
    record.validate(candidate)?;
    Ok(record)
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
        let mut evidence_hashes = BTreeSet::new();
        for evidence in self.checks.values() {
            if !evidence.passed
                || !valid_hex(&evidence.evidence_sha256, 64)
                || !evidence_hashes.insert(evidence.evidence_sha256.as_str())
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
    pub seed_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CertificationFixtureFile {
    pub path: String,
    pub content: String,
    pub executable: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CertificationFixture {
    pub schema_version: u32,
    pub id: String,
    pub kind: CaseKind,
    pub requirement: String,
    pub files: Vec<CertificationFixtureFile>,
}

impl CertificationFixture {
    pub fn validate(&self, case: &CertificationCase) -> Result<(), String> {
        if self.schema_version != 1
            || self.id != case.id
            || self.kind != case.kind
            || self.requirement != case.requirement
            || (self.kind == CaseKind::Routing && !self.files.is_empty())
            || (self.kind != CaseKind::Routing && self.files.is_empty())
        {
            return Err("certification fixture identity is invalid".into());
        }
        let mut paths = BTreeSet::new();
        let mut total = 0usize;
        for file in &self.files {
            let path = Path::new(&file.path);
            let normalized = path.components().collect::<std::path::PathBuf>();
            let has_control_component = path.components().any(|component| {
                matches!(component, std::path::Component::Normal(name) if name == ".git" || name == ".codex")
            });
            let has_instruction_name = path
                .file_name()
                .is_some_and(|name| name == "AGENTS.md" || name == "AGENTS.override.md");
            if file.path.is_empty()
                || file.path.len() > 1024
                || path.is_absolute()
                || path
                    .components()
                    .any(|component| !matches!(component, std::path::Component::Normal(_)))
                || paths.iter().any(|existing: &std::path::PathBuf| {
                    normalized.starts_with(existing) || existing.starts_with(&normalized)
                })
                || file.content.len() > 1024 * 1024
                || has_control_component
                || has_instruction_name
            {
                return Err("certification fixture file is invalid".into());
            }
            paths.insert(normalized);
            total = total.saturating_add(file.content.len());
        }
        if total > 5 * 1024 * 1024 {
            return Err("certification fixture is too large".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CertificationCorpus {
    pub schema_version: u32,
    pub client: ClientKind,
    pub candidate_sha256: String,
    pub created_after_freeze: bool,
    pub generated_at_unix: u64,
    pub generation_id: String,
    pub seed_sha256: String,
    pub preregistered_infrastructure_failures: Vec<String>,
    pub cases: Vec<CertificationCase>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CertificationCorpusDraft {
    pub schema_version: u32,
    pub generation_id: String,
    pub seed_sha256: String,
    pub preregistered_infrastructure_failures: Vec<String>,
    pub cases: Vec<CertificationCase>,
}

pub fn generate_corpus(
    candidate: &CandidateRecord,
    client: ClientKind,
    draft: CertificationCorpusDraft,
) -> Result<CertificationCorpus, String> {
    if draft.schema_version != 1 || !valid_hex(&draft.seed_sha256, 64) {
        return Err("certification corpus draft is invalid".into());
    }
    let corpus = CertificationCorpus {
        schema_version: 1,
        client,
        candidate_sha256: candidate.fingerprint()?,
        created_after_freeze: true,
        generated_at_unix: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|error| error.to_string())?
            .as_secs(),
        generation_id: draft.generation_id,
        seed_sha256: draft.seed_sha256,
        preregistered_infrastructure_failures: draft.preregistered_infrastructure_failures,
        cases: draft.cases,
    };
    corpus.validate(candidate)?;
    Ok(corpus)
}

impl CertificationCorpus {
    pub fn validate(&self, candidate: &CandidateRecord) -> Result<(), String> {
        candidate.validate()?;
        if self.schema_version != 1
            || self.candidate_sha256 != candidate.fingerprint()?
            || !self.created_after_freeze
            || self.generated_at_unix < candidate.frozen_at_unix
            || self.generation_id.is_empty()
            || self.generation_id.len() > 200
            || !valid_hex(&self.seed_sha256, 64)
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
                    if ![
                        "main",
                        "scout",
                        "surveyor",
                        "mech_executor",
                        "executor",
                        "security_executor",
                    ]
                    .contains(&case.expected_owner.as_deref().unwrap_or_default())
                        || !["light_verifier", "verifier", "heavy_verifier"]
                            .contains(&case.expected_verifier.as_deref().unwrap_or_default())
                        || case.seeded_severity.is_some()
                        || case.seed_id.is_some()
                    {
                        return Err("routing case expectations are invalid".into());
                    }
                }
                CaseKind::SeededDefect => {
                    counts[1] += 1;
                    if case.seeded_severity.is_none()
                        || case.seed_id.as_deref().is_none_or(|value| !safe_id(value))
                        || case.expected_owner.is_some()
                        || case.expected_verifier.is_some()
                    {
                        return Err("seeded defect case expectations are invalid".into());
                    }
                }
                CaseKind::Clean => {
                    counts[2] += 1;
                    if case.seeded_severity.is_some()
                        || case.seed_id.is_some()
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

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CertificationEvidence {
    pub client: ClientKind,
    pub candidate_sha256: String,
    pub corpus_sha256: String,
    pub run_sha256: String,
    pub environment_sha256: String,
    pub raw_artifacts_sha256: String,
    pub client_target_sha256: String,
    pub counts: CertificationCounts,
    pub report: CertificationReport,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IndependentReview {
    pub candidate_sha256: String,
    pub verifier_role: String,
    pub verdict: String,
    pub packet_sha256: String,
    pub snapshot_sha256: String,
    pub result_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseEvidence {
    pub schema_version: u32,
    pub sealed_on: String,
    pub candidate: CandidateRecord,
    pub canaries: CanaryRecord,
    pub certifications: BTreeMap<String, CertificationEvidence>,
    pub independent_review: IndependentReview,
}

impl CertificationEvidence {
    pub fn validate(&self, candidate: &CandidateRecord) -> Result<(), String> {
        candidate.validate()?;
        if self.candidate_sha256 != candidate.fingerprint()?
            || !valid_hex(&self.corpus_sha256, 64)
            || !valid_hex(&self.run_sha256, 64)
            || !valid_hex(&self.environment_sha256, 64)
            || !valid_hex(&self.raw_artifacts_sha256, 64)
            || self.client_target_sha256 != client_target_sha256(self.client)?
        {
            return Err("certification evidence identity is invalid".into());
        }
        let expected = score_certification(&self.counts);
        if !self.report.passed
            || !expected.passed
            || !self.report.failures.is_empty()
            || (self.report.routing_wilson_lower - expected.routing_wilson_lower).abs() > 1e-12
            || (self.report.false_positive_wilson_upper - expected.false_positive_wilson_upper)
                .abs()
                > 1e-12
        {
            return Err("certification evidence does not pass the quality floor".into());
        }
        Ok(())
    }
}

impl ReleaseEvidence {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != 1 || !valid_date(&self.sealed_on) {
            return Err("release evidence identity is invalid".into());
        }
        self.candidate.validate()?;
        self.canaries.validate(&self.candidate)?;
        if self.canaries.juno_sha256 != self.candidate.binary_sha256
            || self.canaries.codex_sha256 != standalone_launcher_sha256()?
        {
            return Err("strict canaries do not match the frozen binaries".into());
        }
        if self.certifications.keys().cloned().collect::<BTreeSet<_>>()
            != BTreeSet::from(["cli".to_string(), "desktop".to_string()])
        {
            return Err("release evidence needs CLI and desktop certification".into());
        }
        let cli = self
            .certifications
            .get("cli")
            .ok_or("CLI certification is missing")?;
        let desktop = self
            .certifications
            .get("desktop")
            .ok_or("desktop certification is missing")?;
        if cli.client != ClientKind::Cli || desktop.client != ClientKind::Desktop {
            return Err("certification client labels are invalid".into());
        }
        cli.validate(&self.candidate)?;
        desktop.validate(&self.candidate)?;
        if cli.corpus_sha256 == desktop.corpus_sha256
            || cli.run_sha256 == desktop.run_sha256
            || cli.environment_sha256 == desktop.environment_sha256
            || cli.raw_artifacts_sha256 == desktop.raw_artifacts_sha256
        {
            return Err("client certifications are not independent".into());
        }
        let review = &self.independent_review;
        if review.candidate_sha256 != self.candidate.fingerprint()?
            || review.verifier_role != "heavy_verifier"
            || review.verdict != "CONFIRMED"
        {
            return Err("independent review is not confirmed".into());
        }
        for value in [
            &review.packet_sha256,
            &review.snapshot_sha256,
            &review.result_sha256,
        ] {
            if !valid_hex(value, 64) {
                return Err("independent review hash is invalid".into());
            }
        }
        Ok(())
    }

    pub fn fingerprint(&self) -> Result<String, String> {
        self.validate()?;
        let canonical = serde_json::to_vec(self).map_err(|error| error.to_string())?;
        Ok(hex_sha256(&canonical))
    }
}

pub fn seal_independent_review(
    candidate: &CandidateRecord,
    packet: &[u8],
    snapshot_manifest: &[u8],
    result: &[u8],
) -> Result<IndependentReview, String> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ResultRecord {
        verdict: String,
        material_findings: Vec<serde_json::Value>,
        unverified_assumptions: Vec<String>,
    }
    candidate.validate()?;
    let result_record: ResultRecord =
        serde_json::from_slice(result).map_err(|error| error.to_string())?;
    if result_record.verdict != "CONFIRMED" || !result_record.material_findings.is_empty() {
        return Err("independent review is not confirmed".into());
    }
    if result_record
        .unverified_assumptions
        .iter()
        .any(|value| value.is_empty() || value.len() > 4096)
    {
        return Err("independent review assumptions are invalid".into());
    }
    Ok(IndependentReview {
        candidate_sha256: candidate.fingerprint()?,
        verifier_role: "heavy_verifier".into(),
        verdict: "CONFIRMED".into(),
        packet_sha256: hex_sha256(packet),
        snapshot_sha256: hex_sha256(snapshot_manifest),
        result_sha256: hex_sha256(result),
    })
}

pub fn seal_release_evidence(
    sealed_on: String,
    candidate: CandidateRecord,
    canaries: CanaryRecord,
    cli: CertificationEvidence,
    desktop: CertificationEvidence,
    independent_review: IndependentReview,
) -> Result<ReleaseEvidence, String> {
    let evidence = ReleaseEvidence {
        schema_version: 1,
        sealed_on,
        candidate,
        canaries,
        certifications: BTreeMap::from([("cli".into(), cli), ("desktop".into(), desktop)]),
        independent_review,
    };
    evidence.validate()?;
    Ok(evidence)
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
    let mut evidence_hashes = BTreeSet::new();
    for outcome in &run.outcomes {
        if !cases.contains_key(outcome.id.as_str())
            || outcomes.insert(outcome.id.as_str(), outcome).is_some()
            || !valid_hex(&outcome.evidence_sha256, 64)
            || !evidence_hashes.insert(outcome.evidence_sha256.as_str())
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
    let run_sha256 = hex_sha256(&serde_json::to_vec(run).map_err(|error| error.to_string())?);
    Ok(CertificationEvidence {
        client: run.client,
        candidate_sha256: run.candidate_sha256.clone(),
        corpus_sha256,
        run_sha256,
        environment_sha256: run.environment_sha256.clone(),
        raw_artifacts_sha256: aggregate_outcomes_hash(&run.outcomes)?,
        client_target_sha256: client_target_sha256(run.client)?,
        counts,
        report,
    })
}

pub fn client_target_sha256(client: ClientKind) -> Result<String, String> {
    let value: toml::Value = toml::from_str(
        std::str::from_utf8(COMPATIBILITY_SOURCE).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    let table = match client {
        ClientKind::Cli => value.get("standalone_cli"),
        ClientKind::Desktop => value.get("desktop"),
    }
    .ok_or("compatibility target is missing")?;
    let encoded = toml::to_string(table).map_err(|error| error.to_string())?;
    Ok(hex_sha256(encoded.as_bytes()))
}

fn standalone_launcher_sha256() -> Result<String, String> {
    let value: toml::Value = toml::from_str(
        std::str::from_utf8(COMPATIBILITY_SOURCE).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    value
        .get("standalone_cli")
        .and_then(|table| table.get("launcher_sha256"))
        .and_then(toml::Value::as_str)
        .filter(|value| valid_hex(value, 64))
        .map(str::to_string)
        .ok_or_else(|| "standalone launcher hash is invalid".into())
}

fn aggregate_outcomes_hash(outcomes: &[CaseOutcome]) -> Result<String, String> {
    let mut hashes = outcomes
        .iter()
        .map(|outcome| outcome.evidence_sha256.as_str())
        .collect::<Vec<_>>();
    hashes.sort_unstable();
    if hashes.iter().any(|value| !valid_hex(value, 64)) {
        return Err("certification artifact hash is invalid".into());
    }
    aggregate_hashes(&mut hashes)
}

fn aggregate_hashes(hashes: &mut Vec<&str>) -> Result<String, String> {
    hashes.sort_unstable();
    if hashes.iter().any(|value| !valid_hex(value, 64)) {
        return Err("artifact hash is invalid".into());
    }
    let mut record = Vec::new();
    for hash in hashes {
        record.extend_from_slice(&(hash.len() as u64).to_be_bytes());
        record.extend_from_slice(hash.as_bytes());
    }
    Ok(hex_sha256(&record))
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
    let output = Command::new("/usr/bin/git")
        .args([
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.hooksPath=/dev/null",
        ])
        .arg("-C")
        .arg(repo)
        .args(arguments)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
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
            frozen_at_unix: 1,
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
                seed_id: None,
            });
            cases.push(CertificationCase {
                id: format!("defect-{index:03}"),
                kind: CaseKind::SeededDefect,
                requirement: "Find the seeded material defect.".into(),
                fixture_sha256: "e".repeat(64),
                expected_owner: None,
                expected_verifier: None,
                seeded_severity: Some(DefectSeverity::High),
                seed_id: Some(format!("seed-{index:03}")),
            });
            cases.push(CertificationCase {
                id: format!("clean-{index:03}"),
                kind: CaseKind::Clean,
                requirement: "Do not invent a material finding.".into(),
                fixture_sha256: "f".repeat(64),
                expected_owner: None,
                expected_verifier: None,
                seeded_severity: None,
                seed_id: None,
            });
        }
        CertificationCorpus {
            schema_version: 1,
            client: ClientKind::Cli,
            candidate_sha256: candidate.fingerprint().unwrap(),
            created_after_freeze: true,
            generated_at_unix: 2,
            generation_id: "fresh-set-1".into(),
            seed_sha256: "c".repeat(64),
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
                evidence_sha256: hex_sha256(case.id.as_bytes()),
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

    fn passing_development_run() -> DevelopmentRun {
        let suite = DevelopmentSuite::load().unwrap();
        let repeats = (1..=3)
            .map(|index| DevelopmentRepeat {
                index,
                order_sha256: format!("{:x}", index).repeat(64),
                outcomes: ["baseline", "candidate"]
                    .into_iter()
                    .flat_map(|profile| {
                        suite.cases.iter().map(move |case| DevelopmentOutcome {
                            id: case.id.clone(),
                            profile: profile.into(),
                            owner: case.expected_owner.clone(),
                            verifier: case.expected_verifier.clone(),
                            instruction_passed: true,
                            unauthorized_changes: 0,
                            evidence_sha256: hex_sha256(
                                format!("{profile}-{index}-{}", case.id).as_bytes(),
                            ),
                        })
                    })
                    .collect(),
            })
            .collect();
        DevelopmentRun {
            schema_version: 1,
            factor: "concurrency".into(),
            baseline_profile: "baseline".into(),
            candidate_profile: "candidate".into(),
            randomized: true,
            repeats,
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
                    name.clone(),
                    CanaryEvidence {
                        passed: true,
                        evidence_sha256: hex_sha256(name.as_bytes()),
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
    fn candidate_binary_requires_native_macos_arm64_header() {
        let mut valid = vec![0xcf, 0xfa, 0xed, 0xfe];
        valid.extend_from_slice(&0x0100_000cu32.to_le_bytes());
        assert!(validate_macos_arm64_binary(&valid).is_ok());
        valid[4] = 0x07;
        assert!(validate_macos_arm64_binary(&valid).is_err());
        assert!(validate_macos_arm64_binary(b"#!/bin/sh").is_err());
    }

    #[test]
    fn canary_collection_requires_bound_raw_artifacts() {
        let candidate = candidate();
        let candidate_sha256 = candidate.fingerprint().unwrap();
        let codex_sha256 = "4".repeat(64);
        let artifacts = required_canaries()
            .unwrap()
            .into_iter()
            .map(|name| {
                let raw_sha256 = hex_sha256(format!("raw-{name}").as_bytes());
                (
                    name.clone(),
                    (
                        CanaryArtifact {
                            schema_version: 1,
                            name: name.clone(),
                            candidate_sha256: candidate_sha256.clone(),
                            juno_sha256: candidate.binary_sha256.clone(),
                            codex_sha256: codex_sha256.clone(),
                            execution_context: "unsandboxed-dedicated-account".into(),
                            passed: true,
                            probe_sha256: hex_sha256(format!("probe-{name}").as_bytes()),
                            output_sha256: hex_sha256(format!("output-{name}").as_bytes()),
                            environment_sha256: hex_sha256(
                                format!("environment-{name}").as_bytes(),
                            ),
                            summary: "direct canary proof".into(),
                        },
                        raw_sha256,
                    ),
                )
            })
            .collect();
        let record =
            collect_canaries(&candidate, codex_sha256, "2026-08-29".into(), artifacts).unwrap();
        assert_eq!(record.checks.len(), 15);
    }

    #[test]
    fn open_development_cases_are_valid_and_cover_every_role() {
        let suite = DevelopmentSuite::load().unwrap();
        assert_eq!(suite.cases.len(), 30);
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
    fn development_run_requires_three_complete_paired_repeats() {
        let mut run = passing_development_run();
        let evidence = score_development(&run).unwrap();
        assert_eq!(evidence.total_per_profile, 90);
        assert_eq!(evidence.winner, "tie");
        run.repeats[0].outcomes.pop();
        assert!(score_development(&run).is_err());
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
    fn corpus_generation_binds_the_seed_and_frozen_candidate() {
        let candidate = candidate();
        let source = corpus();
        let draft = CertificationCorpusDraft {
            schema_version: 1,
            generation_id: "generated-after-freeze".into(),
            seed_sha256: "9".repeat(64),
            preregistered_infrastructure_failures: source.preregistered_infrastructure_failures,
            cases: source.cases,
        };
        let generated = generate_corpus(&candidate, ClientKind::Desktop, draft).unwrap();
        assert_eq!(generated.client, ClientKind::Desktop);
        assert_eq!(generated.seed_sha256, "9".repeat(64));
        assert_eq!(generated.candidate_sha256, candidate.fingerprint().unwrap());
    }

    #[test]
    fn certification_fixture_rejects_instruction_and_repository_control_files() {
        let case = CertificationCase {
            id: "clean-001".into(),
            kind: CaseKind::Clean,
            requirement: "Review the bounded code.".into(),
            fixture_sha256: "a".repeat(64),
            expected_owner: None,
            expected_verifier: None,
            seeded_severity: None,
            seed_id: None,
        };
        let mut fixture = CertificationFixture {
            schema_version: 1,
            id: case.id.clone(),
            kind: case.kind,
            requirement: case.requirement.clone(),
            files: vec![CertificationFixtureFile {
                path: "src/lib.rs".into(),
                content: "pub fn ready() -> bool { true }".into(),
                executable: false,
            }],
        };
        fixture.validate(&case).unwrap();
        for path in [
            "AGENTS.md",
            "nested/AGENTS.override.md",
            ".git",
            ".git/config",
            "nested/.codex/config.toml",
        ] {
            fixture.files[0].path = path.into();
            assert!(fixture.validate(&case).is_err());
        }
    }

    #[test]
    fn certification_fixture_rejects_colliding_paths() {
        let case = CertificationCase {
            id: "clean-001".into(),
            kind: CaseKind::Clean,
            requirement: "Review the bounded code.".into(),
            fixture_sha256: "a".repeat(64),
            expected_owner: None,
            expected_verifier: None,
            seeded_severity: None,
            seed_id: None,
        };
        let fixture = CertificationFixture {
            schema_version: 1,
            id: case.id.clone(),
            kind: case.kind,
            requirement: case.requirement.clone(),
            files: vec![
                CertificationFixtureFile {
                    path: "src".into(),
                    content: "file".into(),
                    executable: false,
                },
                CertificationFixtureFile {
                    path: "src/lib.rs".into(),
                    content: "nested".into(),
                    executable: false,
                },
            ],
        };
        assert!(fixture.validate(&case).is_err());
    }

    #[test]
    fn independent_review_must_be_confirmed_without_findings() {
        let candidate = candidate();
        let confirmed =
            br#"{"verdict":"CONFIRMED","material_findings":[],"unverified_assumptions":[]}"#;
        let review =
            seal_independent_review(&candidate, b"packet", b"snapshot", confirmed).unwrap();
        assert_eq!(review.verdict, "CONFIRMED");
        let refuted =
            br#"{"verdict":"REFUTED","material_findings":[{}],"unverified_assumptions":[]}"#;
        assert!(seal_independent_review(&candidate, b"packet", b"snapshot", refuted).is_err());
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
