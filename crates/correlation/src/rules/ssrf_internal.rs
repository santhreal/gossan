//! Correlates SSRF indicators with internal service exposure.
//!
//! When a scanner detects both:
//!   1. An SSRF-susceptible endpoint (open redirect, SSRF probe, proxy misconfiguration)
//!   2. Internal services exposed (Redis, Elasticsearch, Docker, Kubernetes API)
//!
//! This rule synthesizes a chain finding indicating that the SSRF can reach
//! unprotected internal services — a common path to full infrastructure compromise.

use gossan_core::Target;
use secfinding::{Finding, FindingKind, Severity};

use crate::utils::normalize_host;

fn parent_domain(host: &str) -> String {
    // Coarse "registrable parent" heuristic — last two labels. Good
    // enough for the same-blast-radius check; a public-suffix-list
    // implementation would be more precise but pulls in publicsuffix
    // crate weight for marginal gain.
    let labels: Vec<&str> = host.split('.').filter(|s| !s.is_empty()).collect();
    if labels.len() < 2 {
        return host.to_string();
    }
    labels[labels.len() - 2..].join(".")
}

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
        let ssrf_parents: std::collections::HashSet<String> = findings
            .iter()
            .filter(|f| {
                let lower = f.title().to_lowercase();
                SSRF_SIGNALS.iter().any(|sig| lower.contains(sig))
            })
            .map(|f| parent_domain(&normalize_host(f.target())))
            .collect();

        if ssrf_parents.is_empty() {
            return vec![];
        }

        // Internal services only count when they live under the same
        // registrable parent as a known SSRF — otherwise an SSRF on
        // example.com and an exposed Redis on totally-unrelated.com
        // (both legitimately in the scan target list) would emit a
        // false-positive Critical chain claiming attacker pivot.
        let internal_services: Vec<&Finding> = findings
            .iter()
            .filter(|f| {
                let lower = f.title().to_lowercase();
                if !INTERNAL_SIGNALS.iter().any(|sig| lower.contains(sig)) {
                    return false;
                }
                let parent = parent_domain(&normalize_host(f.target()));
                ssrf_parents.contains(&parent)
            })
            .collect();

        if internal_services.is_empty() {
            return vec![];
        }

        let service_names: Vec<String> = internal_services
            .iter()
            .map(|f| f.title().to_string())
            .take(5)
            .collect();

        let chain = Finding::builder(
            "correlation",
            internal_services[0].target(),
            Severity::Critical,
        )
        .title("SSRF → Internal Service Access Chain")
        .detail(format!(
            "An SSRF-capable endpoint was found alongside {} exposed internal service(s) \
                 under the same parent domain. An attacker can chain the SSRF to reach internal \
                 services that are not exposed to the internet, potentially leading to data \
                 exfiltration, command execution, or full infrastructure compromise. Services \
                 at risk: {}",
            internal_services.len(),
            service_names.join(", ")
        ))
        .kind(FindingKind::Vulnerability)
        .tag("chain")
        .tag("ssrf")
        .tag("internal")
        .build_or_log();

        chain.into_iter().collect()
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
            .expect("test finding")
    }

    #[test]
    fn fires_when_ssrf_and_internal_service_present() {
        let rule = SsrfInternalRule;
        let findings = vec![
            finding("hidden", "example.com", "Open redirect detected"),
            finding(
                "portscan",
                "example.com",
                "Redis exposed without authentication",
            ),
        ];
        let chains = rule.check(&findings, &[]);
        assert_eq!(chains.len(), 1);
        assert!(chains[0].title().contains("SSRF"));
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

    /// Adversarial: SSRF on host A and internal service on unrelated
    /// host B MUST NOT chain — they don't share a parent domain.
    /// Pre-fix the rule chained any SSRF anywhere with any internal
    /// service anywhere.
    #[test]
    fn ssrf_internal_does_not_fire_across_unrelated_parent_domains() {
        let rule = SsrfInternalRule;
        let findings = vec![
            finding("hidden", "app.example.com", "Open redirect detected"),
            finding(
                "portscan",
                "redis.unrelated-target.com",
                "Redis exposed without authentication",
            ),
        ];
        assert!(
            rule.check(&findings, &[]).is_empty(),
            "cross-parent ssrf+internal chain emitted as false positive"
        );
    }

    /// Same parent → still chains. The fix didn't over-correct.
    #[test]
    fn ssrf_internal_fires_when_parent_domain_matches() {
        let rule = SsrfInternalRule;
        let findings = vec![
            finding("hidden", "app.example.com", "Open redirect detected"),
            finding(
                "portscan",
                "redis.example.com",
                "Redis exposed without authentication",
            ),
        ];
        let chains = rule.check(&findings, &[]);
        assert_eq!(chains.len(), 1);
    }
}
