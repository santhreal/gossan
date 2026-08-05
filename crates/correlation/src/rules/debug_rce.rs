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

/// Endpoints that can plausibly lead to code execution or live
/// credential/heap extraction, the only class for which a Critical
/// "Potential RCE" claim is factually defensible:
///
/// * `actuator`: Spring Boot /actuator/{env,heapdump,restart,jolokia}:
///   live secrets, heap dumps, and in some configs restart/exec.
/// * `phpinfo`: full server environment incl. secrets and paths;
///   a strong RCE-enabler for chained attacks.
/// * `profiler`: Symfony/Whoops profilers: token/credential leak
///   and request replay.
/// * `debug`: framework debug consoles (Werkzeug/Django debug
///   shell, Rails web-console): direct code execution.
///
/// Pure information-disclosure exposures (`swagger`, `graphql
/// introspection`, `stack trace`, `verbose error`, `diagnostics`) were
/// previously in this list, which meant a lone "Swagger UI exposed"
/// (High) was relabeled as a Critical "Potential RCE", a factual
/// mislabel and a severity inflation. Those exposures are real but are
/// reported at their true severity by their own scanners; they do not
/// constitute RCE and must not drive this chain.
const DEBUG_SIGNALS: &[&str] = &["actuator", "phpinfo", "profiler", "debug"];

pub struct DebugRceRule;

impl super::super::CorrelationRule for DebugRceRule {
    fn name(&self) -> &'static str {
        "debug_rce"
    }

    fn check(&self, findings: &[Finding], _targets: &[Target]) -> Vec<Finding> {
        // Group debug-titled findings by normalized host. Each host
        // gets its own chain, emitting a single chain that lists
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

    /// ADVERSARIAL: pure information-disclosure exposures are NOT RCE.
    /// A lone Swagger / GraphQL-introspection / stack-trace / verbose-
    /// error / diagnostics finding (even at High) must NOT be relabeled
    /// as a Critical "Potential RCE" chain. Pre-fix every one of these
    /// produced exactly that false Critical.
    #[test]
    fn debug_rce_does_not_relabel_info_disclosure_as_rce() {
        let rule = DebugRceRule;
        for title in [
            "Swagger UI exposed at /swagger-ui.html",
            "GraphQL introspection enabled",
            "Stack trace leaked in HTTP 500 response",
            "Verbose error message reveals framework version",
            "Application diagnostics page reachable",
        ] {
            let findings = vec![finding("web", "app.example.com", title, Severity::High)];
            assert!(
                rule.check(&findings, &[]).is_empty(),
                "info-disclosure finding {title:?} was falsely relabeled as RCE"
            );
        }
    }

    /// PROVING: genuinely RCE/credential-dump-capable endpoints must
    /// still raise the Critical chain (the fix must not weaken real
    /// detection (anti-rigging)).
    #[test]
    fn debug_rce_still_fires_for_rce_capable_endpoints() {
        let rule = DebugRceRule;
        for title in [
            "Spring Boot actuator/heapdump exposed",
            "actuator/env exposed without authentication",
            "phpinfo() page exposed",
            "Werkzeug debug console enabled (debug=True)",
            "Symfony profiler exposed",
        ] {
            let findings = vec![finding("hidden", "app.example.com", title, Severity::High)];
            let chains = rule.check(&findings, &[]);
            assert_eq!(
                chains.len(),
                1,
                "RCE-capable endpoint {title:?} must still chain"
            );
            assert!(chains[0].title().contains("Potential RCE"));
        }
    }
}
