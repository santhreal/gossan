//! Correlates exposed debug/actuator endpoints with missing authentication.
//!
//! When a scanner detects:
//!   1. Debug endpoints (Actuator, Django debug, Express debug, phpinfo)
//!   2. No authentication required (200 status without auth headers)
//!
//! This often means the attacker can access environment variables, heap dumps,
//! or even trigger code execution (Spring Boot /actuator/restart, Django shell).

use gossan_core::Target;
use secfinding::{Finding, FindingKind, Severity};

const DEBUG_SIGNALS: &[&str] = &[
    "actuator", "debug", "phpinfo", "profiler", "diagnostics",
    "swagger", "graphql introspection", "stack trace", "verbose error",
];

pub struct DebugRceRule;

impl super::super::CorrelationRule for DebugRceRule {
    fn name(&self) -> &'static str {
        "debug_rce"
    }

    fn check(&self, findings: &[Finding], _targets: &[Target]) -> Vec<Finding> {
        let debug_findings: Vec<&Finding> = findings
            .iter()
            .filter(|f| {
                let lower = f.title().to_lowercase();
                DEBUG_SIGNALS.iter().any(|sig| lower.contains(sig))
            })
            .collect();

        if debug_findings.is_empty() {
            return vec![];
        }

        // Check if any debug finding is on a high-severity endpoint
        let critical_debug: Vec<&&Finding> = debug_findings
            .iter()
            .filter(|f| matches!(f.severity(), Severity::High | Severity::Critical))
            .collect();

        if critical_debug.is_empty() {
            return vec![];
        }

        let endpoint_names: Vec<String> = critical_debug
            .iter()
            .map(|f| f.title().to_string())
            .take(5)
            .collect();

        let chain = Finding::builder(
            "correlation",
            critical_debug
                .first()
                .map(|f| f.target())
                .unwrap_or("unknown"),
            Severity::Critical,
        )
        .title("Exposed Debug Endpoints → Potential RCE")
        .detail(format!(
            "{} high-severity debug/diagnostic endpoint(s) detected.              These often expose environment variables (credentials, API keys),              application internals, or provide direct code execution capabilities              (Spring Boot restart, Django debug shell). Endpoints: {}",
            critical_debug.len(),
            endpoint_names.join(", ")
        ))
        .kind(FindingKind::Vulnerability)
        .tag("chain")
        .tag("debug")
        .tag("rce")
        .build_or_log();

        chain.into_iter().collect()
    }
}
