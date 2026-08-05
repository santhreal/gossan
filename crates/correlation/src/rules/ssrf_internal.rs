//! Correlates SSRF indicators with internal service exposure.
//!
//! When a scanner detects both:
//!   1. An SSRF-susceptible endpoint (open redirect, SSRF probe, proxy misconfiguration)
//!   2. Internal services exposed (Redis, Elasticsearch, Docker, Kubernetes API)
//!
//! This rule synthesizes a chain finding indicating that the SSRF can reach
//! unprotected internal services (a common path to full infrastructure compromise).

use gossan_core::Target;
use secfinding::{Finding, FindingKind, Severity};

use crate::utils::{normalize_host, parent_domain};

/// SSRF patterns we look for in existing finding titles.
const SSRF_SIGNALS: &[&str] = &[
    "ssrf",
    "open redirect",
    "server-side request forgery",
    "proxy",
    "host header injection",
];

/// Internal service patterns that SSRF could reach. Strictly the
/// datastore / orchestration services named in this rule's contract.
///
/// `"unauthenticated"` was previously in this list, which made *any*
/// finding whose title contained that word (e.g. "Unauthenticated
/// /metrics endpoint", "Unauthenticated API route") count as an
/// exposed internal service and produce a false Critical
/// "SSRF → Internal Service Access" chain. Auth state is not an
/// internal-service signal; the real internal services below already
/// match their own specific token (e.g. "Redis exposed without
/// authentication" matches `redis`), so dropping the generic word
/// strengthens precision without losing any real detection.
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
];

/// Correlates SSRF indicators with exposed internal services to flag
/// potential internal network pivoting.
pub struct SsrfInternalRule;

impl super::super::CorrelationRule for SsrfInternalRule {
    fn name(&self) -> &'static str {
        "ssrf_internal"
    }

    fn check(&self, findings: &[Finding], _targets: &[Target]) -> Vec<Finding> {
        // Group SSRF and internal-service findings by registrable parent so that
        // unrelated targets (e.g. example.com vs unrelated.com) never merge into
        // a single chain. Each parent gets its own chain finding.
        let mut by_parent: std::collections::HashMap<
            String,
            (Vec<&Finding>, Vec<&Finding>),
        > = std::collections::HashMap::new();

        for f in findings {
            let parent = parent_domain(&normalize_host(f.target()));
            let lower = f.title().to_lowercase();

            if SSRF_SIGNALS.iter().any(|sig| lower.contains(sig)) {
                by_parent.entry(parent.clone()).or_default().0.push(f);
            }
            if INTERNAL_SIGNALS.iter().any(|sig| lower.contains(sig)) {
                by_parent.entry(parent).or_default().1.push(f);
            }
        }

        let mut chains = Vec::new();
        for (parent, (ssrf_findings, internal_services)) in by_parent {
            if ssrf_findings.is_empty() || internal_services.is_empty() {
                continue;
            }

            let service_names: Vec<String> = internal_services
                .iter()
                .map(|f| f.title().to_string())
                .take(5)
                .collect();

            let chain = Finding::builder("correlation", &parent, Severity::Critical)
                .title("SSRF → Internal Service Access Chain")
                .detail(format!(
                    "An SSRF-capable endpoint was found alongside {} exposed internal service(s) \
                     under {}. An attacker can chain the SSRF to reach internal \
                     services that are not exposed to the internet, potentially leading to data \
                     exfiltration, command execution, or full infrastructure compromise. Services \
                     at risk: {}",
                    internal_services.len(),
                    parent,
                    service_names.join(", ")
                ))
                .kind(FindingKind::Vulnerability)
                .tag("chain")
                .tag("ssrf")
                .tag("internal")
                .build_or_log();

            if let Some(chain) = chain {
                chains.push(chain);
            }
        }

        chains
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
    /// host B MUST NOT chain (they don't share a parent domain).
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

    /// ADVERSARIAL: a generic unauthenticated web finding is NOT an
    /// exposed internal service. Pre-fix, `"unauthenticated"` was an
    /// INTERNAL_SIGNAL, so an SSRF plus any "Unauthenticated X" finding
    /// under the same parent fired a false Critical claiming the SSRF
    /// could reach internal infrastructure.
    #[test]
    fn ssrf_internal_does_not_treat_generic_unauthenticated_as_internal_service() {
        let rule = SsrfInternalRule;
        let findings = vec![
            finding("hidden", "app.example.com", "Open redirect detected"),
            finding(
                "hidden",
                "app.example.com",
                "Unauthenticated /metrics endpoint reachable",
            ),
        ];
        assert!(
            rule.check(&findings, &[]).is_empty(),
            "generic unauthenticated endpoint wrongly treated as exposed internal service"
        );
    }

    /// Per-parent chain emission: two unrelated parents each with a
    /// matching SSRF + internal service pair MUST produce two separate
    /// chain findings, not one merged chain targeting the first host.
    #[test]
    fn ssrf_internal_emits_one_chain_per_parent_domain() {
        let rule = SsrfInternalRule;
        let findings = vec![
            finding("hidden", "app.example.com", "Open redirect detected"),
            finding(
                "portscan",
                "redis.example.com",
                "Redis exposed without authentication",
            ),
            finding("hidden", "app.unrelated.com", "Open redirect detected"),
            finding(
                "portscan",
                "mongo.unrelated.com",
                "MongoDB exposed without authentication",
            ),
        ];
        let chains = rule.check(&findings, &[]);
        assert_eq!(
            chains.len(),
            2,
            "expected one chain per parent domain, got {chains:?}"
        );
        let targets: std::collections::HashSet<String> =
            chains.iter().map(|c| c.target().to_string()).collect();
        assert!(
            targets.contains("example.com"),
            "missing example.com chain; targets={targets:?}"
        );
        assert!(
            targets.contains("unrelated.com"),
            "missing unrelated.com chain; targets={targets:?}"
        );
    }
}
