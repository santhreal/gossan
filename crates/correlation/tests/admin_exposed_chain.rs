//! AdminExposed correlation rule — positive + negative chains.
//!
//! Per GOSSAN_LEGENDARY A12: "AdminExposed coverage" — detects
//! "admin panel + no auth"; doesn't fire on admin-with-auth.

use gossan_correlation::CorrelationEngine;
use secfinding::{Finding, Severity};

fn admin_finding(host: &str) -> Finding {
    Finding::builder("hidden", host, Severity::High)
        .title("Admin panel exposed at /admin")
        .detail("HTTP 200")
        .build()
        .expect("build")
}

fn missing_auth_finding(host: &str) -> Finding {
    Finding::builder("techstack", host, Severity::Medium)
        .title("Missing WWW-Authenticate header")
        .detail("server returns 200 without auth challenge")
        .build()
        .expect("build")
}

#[test]
fn admin_exposed_chain_fires_when_admin_and_no_auth_share_host() {
    let engine = CorrelationEngine::new();
    let host = "https://admin.example.com/";
    let findings = vec![admin_finding(host), missing_auth_finding(host)];
    let chains = engine.run(&findings, &[]);
    let admin_chain = chains
        .iter()
        .find(|f| f.title().to_lowercase().contains("admin"));
    assert!(
        admin_chain.is_some(),
        "expected an admin-no-auth chain finding; got: {:?}",
        chains.iter().map(|f| f.title()).collect::<Vec<_>>()
    );
}

#[test]
fn admin_exposed_chain_does_not_fire_when_only_admin_finding() {
    let engine = CorrelationEngine::new();
    let host = "https://admin.example.com/";
    // Admin finding alone — no auth-missing pair.
    let chains = engine.run(&[admin_finding(host)], &[]);
    assert!(
        !chains
            .iter()
            .any(|f| f.title().to_lowercase().contains("admin-no-auth")
                || f.title().to_lowercase().contains("admin panel")),
        "admin-only must not fire chain; got: {:?}",
        chains.iter().map(|f| f.title()).collect::<Vec<_>>()
    );
}

#[test]
fn admin_exposed_chain_does_not_fire_for_different_hosts() {
    let engine = CorrelationEngine::new();
    let chains = engine.run(
        &[
            admin_finding("https://admin.a.example.com/"),
            missing_auth_finding("https://b.example.com/"),
        ],
        &[],
    );
    assert!(
        !chains
            .iter()
            .any(|f| f.title().to_lowercase().contains("admin")),
        "chain must not fire across different hosts; got: {:?}",
        chains.iter().map(|f| f.title()).collect::<Vec<_>>()
    );
}
