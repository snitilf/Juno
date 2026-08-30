use juno::gates::{
    CanaryEvidence, CanaryRecord, CandidateRecord, CertificationEvidence, ClientKind,
    IndependentReview, ReleaseEvidence, client_target_sha256, logical_bundle_sha256,
};
use juno::{CertificationCounts, Roots, score_certification};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

fn sha256(content: &[u8]) -> String {
    format!("{:x}", Sha256::digest(content))
}

fn passing_counts() -> CertificationCounts {
    CertificationCounts {
        required_instruction_passes: 120,
        required_instruction_total: 120,
        seeded_defects_detected: 120,
        seeded_defect_total: 120,
        critical_or_high_escapes: 0,
        unauthorized_changes: 0,
        routing_correct: 119,
        routing_total: 120,
        clean_false_positives: 1,
        clean_total: 120,
    }
}

fn certification(client: ClientKind, candidate_sha256: &str) -> CertificationEvidence {
    let counts = passing_counts();
    let hashes = match client {
        ClientKind::Cli => ['5', '6', '7', '8'],
        ClientKind::Desktop => ['9', 'a', 'b', 'c'],
    };
    CertificationEvidence {
        client,
        candidate_sha256: candidate_sha256.into(),
        corpus_sha256: hashes[0].to_string().repeat(64),
        run_sha256: hashes[1].to_string().repeat(64),
        environment_sha256: hashes[2].to_string().repeat(64),
        raw_artifacts_sha256: hashes[3].to_string().repeat(64),
        client_target_sha256: client_target_sha256(client).unwrap(),
        report: score_certification(&counts),
        counts,
    }
}

pub fn write_release_evidence(roots: &Roots) {
    let binary = fs::read(&roots.source_bin).unwrap();
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let catalog = fs::read(root.join("config/model-catalog.toml")).unwrap();
    let routing = fs::read(root.join("templates/instructions/routing-policy.md")).unwrap();
    let compatibility = fs::read(root.join("config/compatibility.toml")).unwrap();
    let compatibility_value: toml::Value =
        toml::from_str(std::str::from_utf8(&compatibility).unwrap()).unwrap();
    let launcher_sha256 = compatibility_value["standalone_cli"]["launcher_sha256"]
        .as_str()
        .unwrap()
        .to_string();
    let candidate = CandidateRecord {
        schema_version: 1,
        verified_on: "2026-08-29".into(),
        frozen_at_unix: 1,
        source_commit: "a".repeat(40),
        source_clean: true,
        juno_version: juno::VERSION.into(),
        binary_sha256: sha256(&binary),
        bundle_sha256: logical_bundle_sha256(),
        catalog_sha256: sha256(&catalog),
        routing_sha256: sha256(&routing),
        compatibility_sha256: sha256(&compatibility),
    };
    let candidate_sha256 = candidate.fingerprint().unwrap();
    let required: toml::Value =
        toml::from_str(include_str!("../../config/routing-defaults.toml")).unwrap();
    let checks = required["strict_verification"]["required_canaries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| {
            let name = value.as_str().unwrap().to_string();
            (
                name.clone(),
                CanaryEvidence {
                    passed: true,
                    evidence_sha256: sha256(name.as_bytes()),
                    summary: "isolated fixture evidence".into(),
                },
            )
        })
        .collect();
    let canaries = CanaryRecord {
        schema_version: 1,
        verified_on: "2026-08-29".into(),
        candidate_sha256: candidate_sha256.clone(),
        juno_sha256: candidate.binary_sha256.clone(),
        codex_sha256: launcher_sha256,
        execution_context: "unsandboxed-dedicated-account".into(),
        checks,
    };
    let certifications = BTreeMap::from([
        (
            "cli".into(),
            certification(ClientKind::Cli, &candidate_sha256),
        ),
        (
            "desktop".into(),
            certification(ClientKind::Desktop, &candidate_sha256),
        ),
    ]);
    let evidence = ReleaseEvidence {
        schema_version: 1,
        sealed_on: "2026-08-29".into(),
        candidate,
        canaries,
        certifications,
        independent_review: IndependentReview {
            candidate_sha256,
            verifier_role: "heavy_verifier".into(),
            verdict: "CONFIRMED".into(),
            packet_sha256: "9".repeat(64),
            snapshot_sha256: "a".repeat(64),
            result_sha256: "b".repeat(64),
        },
    };
    evidence.validate().unwrap();
    fs::write(
        roots
            .source_bin
            .parent()
            .unwrap()
            .join("release-evidence.json"),
        serde_json::to_vec_pretty(&evidence).unwrap(),
    )
    .unwrap();
}

#[allow(dead_code)]
pub fn replace_source(roots: &Roots, content: &[u8]) {
    fs::write(&roots.source_bin, content).unwrap();
    fs::set_permissions(&roots.source_bin, fs::Permissions::from_mode(0o755)).unwrap();
    write_release_evidence(roots);
}
