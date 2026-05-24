//! Correlates SSRF indicators with internal service exposure.
//!
//! When a scanner detects both:
//!   1. An SSRF-susceptible endpoint (open redirect, SSRF probe, proxy misconfiguration)
//!   2. Internal services exposed (Redis, Elasticsearch, Docker, Kubernetes API)
//!
//! This rule synthesizes a chain finding indicating that the SSRF can reach
//! unprotected internal services  -  a common path to full infrastructure compromise.

use gossan_core::Target;
use secfinding::{Finding, FindingKind, Severity};

use crate::correlation::scope;

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
        let is_ssrf = |f: &Finding| {
            let lower = f.title().to_lowercase();
            SSRF_SIGNALS.iter().any(|sig| lower.contains(sig))
        };
        let is_internal = |f: &Finding| {
            let lower = f.title().to_lowercase();
            INTERNAL_SIGNALS.iter().any(|sig| lower.contains(sig))
        };

        let mut chains = Vec::new();

        // Group by registrable parent domain, then require an SSRF
        // finding AND a *distinct* exposed-internal-service finding
        // under the same parent. The grouping + distinct-pair guard are
        // the audited `scope` primitive (this was a hand-rolled
        // `ssrf_parents` HashSet + `ptr::eq` self-chain loop). Same
        // parent is mandatory: an SSRF on example.com and an exposed
        // Redis on totally-unrelated.com (both legitimately in the scan
        // target list) must not emit a false Critical pivot chain. A
        // single finding like "SSRF in Docker registry" matches both
        // predicates but is one finding already reported by its own
        // scanner  -  the distinct-object requirement suppresses that
        // self-chain.
        for (_parent, group) in scope::group_by(findings, scope::parent_scope) {
            if scope::distinct_pair(&group, &is_ssrf, &is_internal).is_none() {
                continue;
            }
            let internal_services: Vec<&Finding> =
                group.iter().copied().filter(|&f| is_internal(f)).collect();

            let service_names: Vec<String> = internal_services
                .iter()
                .map(|f| f.title().to_string())
                .take(5)
                .collect();

            if let Some(finding) = Finding::builder(
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
            .build_or_log()
            {
                chains.push(finding);
            }
        }

        chains
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::correlation::CorrelationRule;

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
    /// host B MUST NOT chain  -  they don't share a parent domain.
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

    /// ADVERSARIAL: a single finding whose title matches BOTH an SSRF
    /// word and an internal-service word must NOT self-chain. These are
    /// realistic single scanner titles already reported on their own.
    #[test]
    fn ssrf_internal_does_not_self_chain_single_finding() {
        let rule = SsrfInternalRule;
        for title in [
            "SSRF in Docker registry API",
            "Open redirect on Kubernetes dashboard",
            "Proxy misconfiguration exposes etcd",
            "Server-side request forgery reaching Redis",
        ] {
            let findings = vec![finding("hidden", "app.example.com", title)];
            let chains = rule.check(&findings, &[]);
            assert!(
                chains.is_empty(),
                "single finding {title:?} self-chained: {:?}",
                chains.iter().map(Finding::title).collect::<Vec<_>>()
            );
        }
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

    /// PROVING (regression twin): the dual-word finding, when joined by
    /// a *distinct* SSRF finding under the same parent, must still
    /// chain  -  the distinctness guard suppresses only the self-chain.
    #[test]
    fn ssrf_internal_chains_dual_word_finding_with_distinct_ssrf_partner() {
        let rule = SsrfInternalRule;
        let findings = vec![
            finding(
                "portscan",
                "registry.example.com",
                "SSRF in Docker registry API",
            ),
            finding("hidden", "app.example.com", "Open redirect detected"),
        ];
        let chains = rule.check(&findings, &[]);
        assert_eq!(
            chains.len(),
            1,
            "dual-word internal finding + distinct SSRF finding must still chain"
        );
    }
}
