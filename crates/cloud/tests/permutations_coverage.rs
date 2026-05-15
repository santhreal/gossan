//! AWS S3 / GCS / Azure / DO bucket permutation coverage.
//!
//! Per GOSSAN_LEGENDARY A11: every common pattern produces a probe
//! candidate from `permutations::generate`.

use std::collections::HashSet;

#[test]
fn generate_emits_canonical_buckets_for_a_simple_org() {
    let cands: HashSet<String> = gossan_cloud::permutations::generate("acme")
        .into_iter()
        .collect();
    // Canonical bucket-name patterns we expect for any production org.
    let must_include = [
        "acme",
        "acme-prod",
        "acme-dev",
        "acme-staging",
        "acme-backup",
        "acme-assets",
        "acme-static",
    ];
    let missing: Vec<&&str> = must_include
        .iter()
        .filter(|p| !cands.contains(**p))
        .collect();
    assert!(
        missing.is_empty(),
        "missing canonical bucket patterns: {:?}\ngot {} candidates: {:?}",
        missing,
        cands.len(),
        cands.iter().take(20).collect::<Vec<_>>(),
    );
}

#[test]
fn generate_includes_at_least_30_patterns() {
    let cands = gossan_cloud::permutations::generate("acme");
    assert!(
        cands.len() >= 30,
        "expected ≥30 candidate names; got {}: {:?}",
        cands.len(),
        cands
    );
}

#[test]
fn generate_lowercases_org_input() {
    let cands: HashSet<String> = gossan_cloud::permutations::generate("ACME")
        .into_iter()
        .collect();
    assert!(cands.contains("acme"), "ACME must lowercase to acme");
}

#[test]
fn generate_respects_s3_length_limits() {
    // S3 bucket-name spec: 3-63 chars.
    let cands = gossan_cloud::permutations::generate("acme");
    for c in &cands {
        assert!(c.len() >= 3 && c.len() <= 63, "{c} violates 3-63 length limit");
    }
}

#[test]
fn generate_handles_dotted_org_without_panic() {
    // Some orgs are reverse-DNS style (com.acme).
    let cands = gossan_cloud::permutations::generate("com.acme");
    assert!(!cands.is_empty());
}
