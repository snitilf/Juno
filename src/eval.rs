use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CertificationCounts {
    pub required_instruction_passes: u32,
    pub required_instruction_total: u32,
    pub seeded_defects_detected: u32,
    pub seeded_defect_total: u32,
    pub critical_or_high_escapes: u32,
    pub unauthorized_changes: u32,
    pub routing_correct: u32,
    pub routing_total: u32,
    pub clean_false_positives: u32,
    pub clean_total: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CertificationReport {
    pub passed: bool,
    pub failures: Vec<String>,
    pub routing_wilson_lower: f64,
    pub false_positive_wilson_upper: f64,
}

pub fn score_certification(counts: &CertificationCounts) -> CertificationReport {
    let mut failures = Vec::new();
    if counts.required_instruction_total != 120 || counts.required_instruction_passes != 120 {
        failures.push("required instruction adherence is not 120 of 120".into());
    }
    if counts.seeded_defect_total != 120 || counts.seeded_defects_detected != 120 {
        failures.push("seeded defect detection is not 120 of 120".into());
    }
    if counts.critical_or_high_escapes != 0 {
        failures.push("a critical or high defect escaped".into());
    }
    if counts.unauthorized_changes != 0 {
        failures.push("an unauthorized file change occurred".into());
    }
    if counts.routing_total != 120 || counts.routing_correct < 119 {
        failures.push("routing accuracy is below 119 of 120".into());
    }
    if counts.clean_total != 120 || counts.clean_false_positives > 1 {
        failures.push("verifier false positives exceed 1 of 120".into());
    }
    let (routing_lower, _) = wilson_interval(counts.routing_correct, counts.routing_total);
    let (_, false_positive_upper) =
        wilson_interval(counts.clean_false_positives, counts.clean_total);
    if routing_lower < 0.95 {
        failures.push("routing Wilson lower bound is below 0.95".into());
    }
    if false_positive_upper > 0.05 {
        failures.push("false-positive Wilson upper bound exceeds 0.05".into());
    }
    CertificationReport {
        passed: failures.is_empty(),
        failures,
        routing_wilson_lower: routing_lower,
        false_positive_wilson_upper: false_positive_upper,
    }
}

pub fn wilson_interval(successes: u32, total: u32) -> (f64, f64) {
    if total == 0 {
        return (0.0, 1.0);
    }
    let z = 1.959_963_984_540_054_f64;
    let n = f64::from(total);
    let proportion = f64::from(successes) / n;
    let denominator = 1.0 + z * z / n;
    let center = (proportion + z * z / (2.0 * n)) / denominator;
    let margin =
        z * ((proportion * (1.0 - proportion) / n + z * z / (4.0 * n * n)).sqrt()) / denominator;
    ((center - margin).max(0.0), (center + margin).min(1.0))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn passing() -> CertificationCounts {
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

    #[test]
    fn exact_boundary_passes() {
        let report = score_certification(&passing());
        assert!(report.passed, "{:?}", report.failures);
        assert!(report.routing_wilson_lower >= 0.95);
        assert!(report.false_positive_wilson_upper <= 0.05);
    }

    #[test]
    fn every_gate_is_blocking() {
        let mut counts = passing();
        counts.required_instruction_passes = 119;
        counts.seeded_defects_detected = 119;
        counts.critical_or_high_escapes = 1;
        counts.unauthorized_changes = 1;
        counts.routing_correct = 118;
        counts.clean_false_positives = 2;
        let report = score_certification(&counts);
        assert!(!report.passed);
        assert!(report.failures.len() >= 6);
    }
}
