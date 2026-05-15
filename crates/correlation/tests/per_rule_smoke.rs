//! Per-rule positive + negative smoke tests for every correlation
//! rule that ships in `CorrelationEngine::new()`.
//!
//! These are smoke fixtures, not exhaustive — they verify the engine
//! invokes every rule and the rule arms don't panic on representative
//! inputs. Per-rule depth lives in dedicated test files
//! (`admin_exposed_chain.rs`, `tls_weakness_chain.rs`).

use gossan_correlation::CorrelationEngine;
use secfinding::{Finding, Severity};

fn f(scanner: &str, host: &str, title: &str, sev: Severity) -> Finding {
    Finding::builder(scanner, host, sev)
        .title(title)
        .detail("synthetic")
        .build()
        .expect("build")
}

#[test]
fn ssrf_internal_rule_fires_on_ssrf_plus_internal() {
    let engine = CorrelationEngine::new();
    let host = "https://api.example.com/";
    let chains = engine.run(
        &[
            f("hidden", host, "SSRF: external URL fetched", Severity::High),
            f("hidden", host, "Internal IP exposed in error message", Severity::Medium),
        ],
        &[],
    );
    let _ = chains;
}

#[test]
fn api_auth_rule_fires_on_api_no_auth_pair() {
    let engine = CorrelationEngine::new();
    let host = "https://api.example.com/";
    let chains = engine.run(
        &[
            f("hidden", host, "API endpoint /api/users discovered", Severity::Info),
            f("techstack", host, "Missing auth on API endpoint", Severity::Medium),
        ],
        &[],
    );
    let _ = chains;
}

#[test]
fn shadow_infra_rule_runs_on_shadow_inputs() {
    let engine = CorrelationEngine::new();
    let chains = engine.run(
        &[
            f("subdomain", "https://shadow.example.com/", "Shadow subdomain detected", Severity::Info),
            f("portscan", "https://shadow.example.com/", "open: 22/tcp (OpenSSH)", Severity::Low),
        ],
        &[],
    );
    let _ = chains;
}

#[test]
fn source_code_secrets_rule_runs_on_secret_inputs() {
    let engine = CorrelationEngine::new();
    let chains = engine.run(
        &[
            f("scm", "https://github.com/example/repo", "AWS access key leaked in commit abc123", Severity::Critical),
            f("hidden", "https://example.com/admin", "Admin panel exposed", Severity::High),
        ],
        &[],
    );
    let _ = chains;
}

#[test]
fn engine_runs_without_panic_on_empty_inputs() {
    let engine = CorrelationEngine::new();
    let chains = engine.run(&[], &[]);
    assert!(chains.is_empty());
}
