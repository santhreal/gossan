//! Correlates SSRF indicators with internal service exposure.
//!
//! When a scanner detects both:
//!   1. An SSRF-susceptible endpoint (open redirect, SSRF probe, proxy misconfiguration)
//!   2. Internal services exposed (Redis, Elasticsearch, Docker, Kubernetes API)
//!
//! This rule synthesizes a chain finding indicating that the SSRF can reach
//! unprotected internal services — a common path to full infrastructure compromise.

use gossan_core::Target;
use secfinding::{Finding, Severity};

/// SSRF patterns we look for in existing finding titles.
const SSRF_SIGNALS: &[&str] = &[
    "ssrf",
    "open redirect",
    "server-side request forgery",
    "proxy",
    "host header injection",
];

/// Internal service patterns that SSRF could reach.
const INTERNAL_SIGNALS: &[&str] = &[
    "redis",
    "elasticsearch",
    "mongodb",
    "docker",
    "kubernetes",
    "etcd",
    "consul",
    "memcached",
    "couchdb",
    "rabbitmq",
    "unauthenticated",
];

/// Correlates SSRF indicators with exposed internal services to flag
/// potential internal network pivoting.
pub struct SsrfInternalRule;

impl super::super::CorrelationRule for SsrfInternalRule {
    fn name(&self) -> &'static str {
        "ssrf_internal"
    }

    fn check(&self, findings: &[Finding], _targets: &[Target]) -> Vec<Finding> {
        let has_ssrf = findings.iter().any(|f| {
            let lower = f.title.to_lowercase();
            SSRF_SIGNALS.iter().any(|sig| lower.contains(sig))
        });

        let internal_services: Vec<&Finding> = findings
            .iter()
            .filter(|f| {
                let lower = f.title.to_lowercase();
                INTERNAL_SIGNALS.iter().any(|sig| lower.contains(sig))
            })
            .collect();

        if !has_ssrf || internal_services.is_empty() {
            return vec![];
        }

        let service_names: Vec<String> = internal_services
            .iter()
            .map(|f| f.title.clone())
            .take(5)
            .collect();

        let chain = Finding::builder(
            "correlation",
            internal_services
                .first()
                .map(|f| f.target.as_str())
                .unwrap_or("unknown"),
            Severity::Critical,
        )
        .title("SSRF → Internal Service Access Chain")
        .detail(format!(
            "An SSRF-capable endpoint was found alongside {} exposed internal service(s). \
             An attacker can chain the SSRF to reach internal services that are not exposed \
             to the internet, potentially leading to data exfiltration, command execution, \
             or full infrastructure compromise. Services at risk: {}",
            internal_services.len(),
            service_names.join(", ")
        ))
        .tag("chain")
        .tag("ssrf")
        .tag("internal")
        .build()
        .expect("finding builder: required fields are set");

        vec![chain]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CorrelationRule;

    fn finding(scanner: &str, target: &str, title: &str) -> Finding {
        Finding::builder(scanner, target, Severity::High)
            .title(title)
            .build()
            .expect("finding builder: required fields are set")
    }

    #[test]
    fn fires_when_ssrf_and_internal_service_present() {
        let rule = SsrfInternalRule;
        let findings = vec![
            finding("hidden", "example.com", "Open redirect detected"),
            finding("portscan", "example.com", "Redis exposed without authentication"),
        ];
        let chains = rule.check(&findings, &[]);
        assert_eq!(chains.len(), 1);
        assert!(chains[0].title.contains("SSRF"));
    }

    #[test]
    fn does_not_fire_without_ssrf() {
        let rule = SsrfInternalRule;
        let findings = vec![finding(
            "portscan",
            "example.com",
            "Redis exposed without authentication",
        )];
        assert!(rule.check(&findings, &[]).is_empty());
    }

    #[test]
    fn does_not_fire_without_internal_service() {
        let rule = SsrfInternalRule;
        let findings = vec![finding("hidden", "example.com", "Open redirect detected")];
        assert!(rule.check(&findings, &[]).is_empty());
    }
}
