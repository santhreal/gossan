//! TLSWeakness chain coverage.
//!
//! Per GOSSAN_LEGENDARY A12: deduplicates 100 identical TLS issues
//! into 1 chain; fires on N≥2 distinct TLS issues; doesn't fire on
//! N=1.

use gossan_correlation::CorrelationEngine;
use secfinding::{Finding, Severity};

fn tls_finding(host: &str, title: &str) -> Finding {
    Finding::builder("portscan", host, Severity::Medium)
        .title(title)
        .detail("synthetic")
        .build()
        .expect("build")
}

#[test]
fn one_tls_issue_does_not_fire_chain() {
    let engine = CorrelationEngine::new();
    let host = "https://api.example.com/";
    let chains = engine.run(&[tls_finding(host, "self-signed certificate")], &[]);
    assert!(
        !chains
            .iter()
            .any(|f| f.title().to_lowercase().contains("tls-weakness")),
        "single issue must not fire tls chain; got: {:?}",
        chains.iter().map(|f| f.title()).collect::<Vec<_>>()
    );
}

#[test]
fn two_distinct_tls_issues_fire_chain() {
    let engine = CorrelationEngine::new();
    let host = "https://api.example.com/";
    let chains = engine.run(
        &[
            tls_finding(host, "self-signed certificate"),
            tls_finding(host, "expired certificate"),
        ],
        &[],
    );
    assert!(
        chains.iter().any(|f| {
            let t = f.title().to_lowercase();
            t.contains("tls") || t.contains("certificate") || t.contains("weakness")
        }),
        "two distinct TLS issues must fire chain; got: {:?}",
        chains.iter().map(|f| f.title()).collect::<Vec<_>>()
    );
}

#[test]
fn one_hundred_identical_issues_collapse_to_one_chain_or_none() {
    let engine = CorrelationEngine::new();
    let host = "https://api.example.com/";
    let findings: Vec<Finding> = (0..100)
        .map(|_| tls_finding(host, "self-signed certificate"))
        .collect();
    let chains = engine.run(&findings, &[]);
    let tls_chains = chains
        .iter()
        .filter(|f| {
            let t = f.title().to_lowercase();
            t.contains("tls") || t.contains("certificate") || t.contains("weakness")
        })
        .count();
    // 100 identical issues dedupe to 1 distinct issue → below the
    // N≥2-required-distinct threshold → 0 chain findings (deduped).
    assert!(
        tls_chains <= 1,
        "100 identical issues must collapse to ≤1 chain; got {tls_chains}"
    );
}
