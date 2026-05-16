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

use crate::utils::normalize_host;

const DEBUG_SIGNALS: &[&str] = &[
    "actuator",
    "debug",
    "phpinfo",
    "profiler",
    "diagnostics",
    "swagger",
    "graphql introspection",
    "stack trace",
    "verbose error",
];

pub struct DebugRceRule;

impl super::super::CorrelationRule for DebugRceRule {
    fn name(&self) -> &'static str {
        "debug_rce"
    }

    fn check(&self, findings: &[Finding], _targets: &[Target]) -> Vec<Finding> {
        // Group debug-titled findings by normalized host. Each host
        // gets its own chain — emitting a single chain that lists
        // endpoints from MULTIPLE hosts under one target field is
        // misleading (the report shows e.g. example.com but lists
        // /actuator from app.example.com and /phpinfo from
        // unrelated.com as if they were on the same target).
        let mut by_host: std::collections::HashMap<String, Vec<&Finding>> =
            std::collections::HashMap::new();
        for f in findings {
            let lower = f.title().to_lowercase();
            if !DEBUG_SIGNALS.iter().any(|sig| lower.contains(sig)) {
                continue;
            }
            if !matches!(f.severity(), Severity::High | Severity::Critical) {
                continue;
            }
            by_host
                .entry(normalize_host(f.target()))
                .or_default()
                .push(f);
        }

        let mut chains = Vec::new();
        for (_host, group) in by_host {
            if group.is_empty() {
                continue;
            }
            let endpoint_names: Vec<String> = group
                .iter()
                .map(|f| f.title().to_string())
                .take(5)
                .collect();

            let chain = Finding::builder("correlation", group[0].target(), Severity::Critical)
                .title("Exposed Debug Endpoints → Potential RCE")
                .detail(format!(
                    "{} high-severity debug/diagnostic endpoint(s) detected on the same target. \
                     These often expose environment variables (credentials, API keys), \
                     application internals, or provide direct code execution capabilities \
                     (Spring Boot restart, Django debug shell). Endpoints: {}",
                    group.len(),
                    endpoint_names.join(", ")
                ))
                .kind(FindingKind::Vulnerability)
                .tag("chain")
                .tag("debug")
                .tag("rce")
                .build_or_log();

            chains.extend(chain);
        }
        chains
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CorrelationRule;

    fn finding(scanner: &str, target: &str, title: &str, sev: Severity) -> Finding {
        Finding::builder(scanner, target, sev)
            .title(title)
            .build()
            .expect("test finding")
    }

    /// Pre-fix: a single chain was emitted spanning multiple hosts.
    /// Now: one chain per host so the target field accurately names
    /// where the listed endpoints live.
    #[test]
    fn debug_rce_emits_one_chain_per_host() {
        let rule = DebugRceRule;
        let findings = vec![
            finding(
                "hidden",
                "app.example.com",
                "actuator/env exposed",
                Severity::High,
            ),
            finding(
                "hidden",
                "app.example.com",
                "phpinfo() output exposed",
                Severity::High,
            ),
            finding(
                "hidden",
                "ops.unrelated.com",
                "actuator/heapdump exposed",
                Severity::High,
            ),
        ];
        let chains = rule.check(&findings, &[]);
        assert_eq!(chains.len(), 2);
        let targets: std::collections::HashSet<_> =
            chains.iter().map(|c| c.target().to_string()).collect();
        assert!(targets.contains("app.example.com"));
        assert!(targets.contains("ops.unrelated.com"));
    }

    #[test]
    fn debug_rce_skips_low_severity_debug_findings() {
        let rule = DebugRceRule;
        let findings = vec![finding(
            "hidden",
            "app.example.com",
            "actuator/info exposed",
            Severity::Low,
        )];
        assert!(rule.check(&findings, &[]).is_empty());
    }
}
