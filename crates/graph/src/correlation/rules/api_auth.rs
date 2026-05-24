use crate::correlation::scope;
use crate::correlation::CorrelationRule;
use gossan_core::Target;
use secfinding::{Finding, FindingKind, Severity};

/// Rule: Old API version exposed without authentication.
pub struct ApiAuthRule;

impl CorrelationRule for ApiAuthRule {
    fn name(&self) -> &'static str {
        "api-auth"
    }

    fn check(&self, findings: &[Finding], _targets: &[Target]) -> Vec<Finding> {
        let mut chains = Vec::new();

        let is_version =
            |f: &Finding| f.tags().iter().any(|t| t.as_ref() == "api-version");
        // `host_scope` strips the port from `f.target()`, so a portscan
        // finding on `example.com:27017` ("MongoDB responds  -  likely
        // unauthenticated", tag `no-auth`) buckets with an api-version
        // finding from `https://example.com/api/v1` and a pure title-
        // substring match for "unauthenticated" was producing a false
        // Critical "Unauthenticated legacy API version" chain whose
        // no-auth signal was actually a database on a different,
        // non-HTTP port. Restrict the no-auth partner to (a) a finding
        // tagged `auth-bypass` (the canonical web-no-auth marker,
        // emitted by hidden/swagger + hidden/tech_probes), OR (b) a
        // title-substring match whose target is explicitly an HTTP URL.
        let is_no_auth = |f: &Finding| {
            if f.tags().iter().any(|t| t.as_ref() == "auth-bypass") {
                return true;
            }
            let target = f.target();
            let looks_http =
                target.starts_with("http://") || target.starts_with("https://");
            if !looks_http {
                return false;
            }
            let t = f.title().to_lowercase();
            t.contains("no authentication") || t.contains("unauthenticated")
        };

        // Group by NORMALIZED host (http://app vs https://app vs
        // app:443 cluster together; otherwise the version finding and
        // the missing-auth finding land in separate buckets and never
        // chain) then require an api-version finding AND a *distinct*
        // missing-auth finding. The grouping + distinct-pair guard are
        // the audited `scope` primitive (was a hand-rolled by_target
        // HashMap + `ptr::eq` self-chain loop). A single
        // api-version-tagged finding whose title says "unauthenticated"
        // (e.g. "Legacy /api/v1 reachable unauthenticated") matches
        // both predicates but is one finding already reported by its
        // own scanner  -  the distinct-object requirement suppresses that
        // self-chain.
        for (target, group) in scope::group_by(findings, scope::host_scope) {
            if scope::distinct_pair(&group, &is_version, &is_no_auth).is_none() {
                continue;
            }
            let versions: Vec<&Finding> =
                group.iter().copied().filter(|&f| is_version(f)).collect();

            gossan_core::try_push_finding(
                Finding::builder("correlation", &target, Severity::Critical)
                    .title("Unauthenticated legacy API version")
                    .detail(format!(
                        "Target {} exposes legacy API versions ({}) that appear to lack authentication. \
                         Attackers can use these endpoints to bypass security controls on newer API versions.",
                        target,
                        versions.iter().map(|f| f.title()).collect::<Vec<_>>().join(", ")
                    ))
                    .tag("correlation")
                    .tag("attack-chain")
                    .tag("api-security")
                    .kind(FindingKind::Vulnerability),
                &mut chains,
            );
        }

        chains
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(target: &str, title: &str, tags: &[&str]) -> Finding {
        let mut b = Finding::builder("hidden", target, Severity::High).title(title);
        for t in tags {
            b = b.tag(*t);
        }
        b.build().expect("test finding")
    }

    /// ADVERSARIAL: one api-version-tagged finding whose title already
    /// says "unauthenticated" must NOT self-chain  -  it is a single
    /// finding already reported by its own scanner.
    #[test]
    fn api_auth_does_not_self_chain_single_finding() {
        for title in [
            "Legacy /api/v1 reachable unauthenticated",
            "API version v1 exposed with no authentication",
        ] {
            let f = finding("https://api.example.com", title, &["api-version"]);
            let chains = ApiAuthRule.check(&[f], &[]);
            assert!(
                chains.is_empty(),
                "single combined finding {title:?} self-chained: {:?}",
                chains.iter().map(|c| c.title().to_string()).collect::<Vec<_>>()
            );
        }
    }

    /// PROVING: an api-version finding plus a *distinct* missing-auth
    /// finding (tagged `auth-bypass`, as hidden/swagger emits) on the
    /// same host still chains.
    #[test]
    fn api_auth_chains_two_distinct_findings() {
        let findings = vec![
            finding(
                "https://api.example.com/v1",
                "API version enumeration",
                &["api-version"],
            ),
            // `auth-bypass` is the canonical web-no-auth tag (hidden/
            // swagger.rs, hidden/tech_probes.rs).
            finding(
                "https://api.example.com",
                "5 API endpoint(s) with no authentication requirement",
                &["auth-bypass", "swagger"],
            ),
        ];
        let chains = ApiAuthRule.check(&findings, &[]);
        assert_eq!(chains.len(), 1);
        assert_eq!(chains[0].severity(), Severity::Critical);
    }

    /// PROVING (regression twin): the dual-signal finding, joined by a
    /// distinct api-version finding, must still chain  -  distinctness
    /// guard suppresses only the self-chain.
    #[test]
    fn api_auth_chains_combined_finding_with_distinct_version_partner() {
        let findings = vec![
            finding(
                "https://api.example.com/v1",
                "Legacy /api/v1 reachable unauthenticated",
                &["api-version"],
            ),
            finding(
                "https://api.example.com/v2",
                "API v2 version banner disclosed",
                &["api-version"],
            ),
        ];
        let chains = ApiAuthRule.check(&findings, &[]);
        assert_eq!(
            chains.len(),
            1,
            "combined finding + distinct api-version finding must still chain"
        );
    }

    /// PRECISION (the real defect  -  pre-2026-05-22). `scope::host_scope`
    /// strips the port, so a portscan finding on `example.com:27017`
    /// ("MongoDB responds  -  likely unauthenticated", tag `no-auth`)
    /// shared a bucket with an api-version finding on
    /// `https://example.com/api/v1`. The old title-substring matcher
    /// hit "unauthenticated" in the MongoDB title and chained to a
    /// false Critical "Unauthenticated legacy API version" whose
    /// no-auth signal was actually a database on a different,
    /// non-HTTP port.
    #[test]
    fn api_auth_does_not_use_portscan_db_no_auth_as_chain_partner() {
        let findings = vec![
            finding(
                "https://example.com/api/v1",
                "API version enumeration",
                &["api-version"],
            ),
            // Exact portscan emission for MongoDB on a host:port target.
            finding(
                "example.com:27017",
                "MongoDB responds  -  likely unauthenticated",
                &["banner", "mongodb", "no-auth"],
            ),
        ];
        assert!(
            ApiAuthRule.check(&findings, &[]).is_empty(),
            "portscan DB `unauthenticated` finding wrongly partnered an api-version chain"
        );
    }

    /// PRECISION: same class  -  Elasticsearch on a non-HTTP port.
    #[test]
    fn api_auth_does_not_use_portscan_elasticsearch_no_auth_as_partner() {
        let findings = vec![
            finding(
                "https://example.com/api/v1",
                "API version enumeration",
                &["api-version"],
            ),
            finding(
                "example.com:9200",
                "Elasticsearch responds  -  likely unauthenticated",
                &["banner", "elasticsearch", "no-auth"],
            ),
        ];
        assert!(
            ApiAuthRule.check(&findings, &[]).is_empty(),
            "portscan Elasticsearch `unauthenticated` finding wrongly partnered an api-version chain"
        );
    }

    /// PROVING: a real web auth-bypass tag (not a no-scheme target)
    /// still chains  -  the precision fix did not over-correct.
    #[test]
    fn api_auth_still_chains_when_no_auth_carries_auth_bypass_tag_only() {
        let findings = vec![
            finding(
                "https://example.com/api/v1",
                "API version enumeration",
                &["api-version"],
            ),
            // No "unauthenticated" in title  -  relies solely on the
            // auth-bypass tag path (e.g. hidden/tech_probes Strapi).
            finding(
                "https://example.com/admin",
                "Strapi admin panel exposed without registration lock",
                &["strapi", "auth-bypass", "exposure"],
            ),
        ];
        let chains = ApiAuthRule.check(&findings, &[]);
        assert_eq!(chains.len(), 1);
    }
}
