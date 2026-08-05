use crate::utils::normalize_host;
use crate::CorrelationRule;
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

        // Group by NORMALIZED target so http://app vs https://app vs
        // app:443 cluster together, otherwise an api-version finding
        // on `https://app.example.com/v1` and an unauthenticated
        // finding on `http://app.example.com/v1` would land in
        // separate buckets and never chain.
        let mut by_target: std::collections::HashMap<String, Vec<&Finding>> =
            std::collections::HashMap::new();
        for f in findings {
            by_target
                .entry(normalize_host(f.target()))
                .or_default()
                .push(f);
        }

        for (target, fs) in by_target {
            let versions: Vec<&Finding> = fs
                .iter()
                .copied()
                .filter(|f| f.tags().iter().any(|t| t.as_ref() == "api-version"))
                .collect();

            // Restrict no-auth partner to the canonical web tag OR an
            // HTTP-URL target, prevents portscan DB banners ("MongoDB
            // responds, likely unauthenticated", no-scheme target) from
            // driving a false Critical "Unauthenticated legacy API" chain.
            let no_auth_findings: Vec<&Finding> = fs
                .iter()
                .copied()
                .filter(|f| {
                    if f.tags().iter().any(|t| t.as_ref() == "auth-bypass") {
                        return true;
                    }
                    let tgt = f.target();
                    let tgt_l = tgt.to_ascii_lowercase();
                    // Reject non-HTTP schemes (mongodb://, ftp://, etc.)
                    if tgt_l.contains("://")
                        && !tgt_l.starts_with("http://")
                        && !tgt_l.starts_with("https://")
                    {
                        return false;
                    }
                    // Reject bare host:port / IP:port banners, but keep
                    // http(s) URLs that legitimately include non-default ports.
                    let is_http = tgt_l.starts_with("http://") || tgt_l.starts_with("https://");
                    if !is_http
                        && tgt.chars().rev().take_while(|c| c.is_ascii_digit()).count() > 0
                        && tgt.chars().rev().skip_while(|c| c.is_ascii_digit()).next() == Some(':')
                    {
                        return false;
                    }
                    let t = f.title().to_lowercase();
                    t.contains("no authentication") || t.contains("unauthenticated")
                })
                .collect();

            // Self-chain guard: require a *distinct* no-auth finding. A
            // single api-version-tagged finding whose title says
            // "unauthenticated" is one finding already reported by its
            // own scanner, not a two-signal correlation.
            let has_distinct_pair = versions
                .iter()
                .any(|v| no_auth_findings.iter().any(|n| !std::ptr::eq(*v, *n)));

            if !versions.is_empty() && has_distinct_pair {
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
        }

        chains
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CorrelationRule;
    use secfinding::Severity;

    fn finding(target: &str, title: &str, tags: &[&str]) -> Finding {
        let mut b = Finding::builder("hidden", target, Severity::High).title(title);
        for t in tags {
            b = b.tag(*t);
        }
        b.build().expect("test finding")
    }

    /// ADVERSARIAL: one api-version-tagged finding whose title already
    /// says "unauthenticated" must NOT self-chain, it is a single
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
    /// finding (tagged `auth-bypass`) on the same host still chains.
    #[test]
    fn api_auth_chains_two_distinct_findings() {
        let findings = vec![
            finding(
                "https://api.example.com/v1",
                "API version enumeration",
                &["api-version"],
            ),
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

    /// PRECISION: a portscan DB finding ("MongoDB responds, likely
    /// unauthenticated", no-scheme target) must NOT partner an
    /// api-version finding in the chain.
    #[test]
    fn api_auth_does_not_use_portscan_db_no_auth_as_chain_partner() {
        let findings = vec![
            finding(
                "https://example.com/api/v1",
                "API version enumeration",
                &["api-version"],
            ),
            finding(
                "example.com:27017",
                "MongoDB responds, likely unauthenticated",
                &["banner", "mongodb", "no-auth"],
            ),
        ];
        assert!(
            ApiAuthRule.check(&findings, &[]).is_empty(),
            "portscan DB `unauthenticated` finding wrongly partnered an api-version chain"
        );
    }
}
