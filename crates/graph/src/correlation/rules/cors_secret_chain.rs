//! Correlates CORS misconfiguration with exposed secrets for credential theft.
//!
//! When both are present:
//!   1. CORS allows arbitrary origins (origin reflection with credentials)
//!   2. Secrets found in JavaScript source code
//!
//! An attacker on any domain can make authenticated cross-origin requests
//! AND the application already has secrets in client-side code. This is a
//! direct path to credential theft.

use gossan_core::Target;
use secfinding::{Finding, FindingKind, Severity};

use crate::correlation::scope;

pub struct CorsSecretChainRule;

impl super::super::CorrelationRule for CorsSecretChainRule {
    fn name(&self) -> &'static str {
        "cors_secret_chain"
    }

    fn check(&self, findings: &[Finding], _targets: &[Target]) -> Vec<Finding> {
        // The chain claims an attacker on any domain can make AUTHENTICATED
        // cross-origin requests AND read the response  -  the precondition is
        // that a browser will actually honour the misconfig. `gossan_hidden::
        // cors` emits "CORS: wildcard origin with credentials" at Medium
        // precisely because browsers REJECT `Access-Control-Allow-Origin: *`
        // combined with credentials (spec-required); it's a config-correctness
        // bug, not a live credential-theft path. Inflating that Medium into a
        // Critical "Credential Theft" chain was a false claim against a
        // browser-mitigated case. Real credential-theft titles
        // ("CORS: arbitrary origin reflected with credentials", "(preflight)",
        // "CORS: null origin trusted with credentials") are all emitted at
        // Critical by the same scanner, so a severity gate of High|Critical
        // is the right precision floor here.
        let is_cors_with_creds = |f: &&Finding| -> bool {
            if !matches!(f.severity(), Severity::High | Severity::Critical) {
                return false;
            }
            let lower = f.title().to_lowercase();
            lower.contains("cors") && lower.contains("credential")
        };
        let is_secret = |f: &&Finding| -> bool {
            f.tags()
                .iter()
                .any(|t| t.as_ref() == "secret" || t.as_ref() == "keyhog")
        };

        // Group by normalized host via the audited `scope` primitive
        // (was a hand-rolled by_host HashMap). The chain only fires
        // when both signals are on the SAME target  -  otherwise
        // unrelated findings (CORS misconfig on app.example.com +
        // secret on unrelated.com) would emit a false-positive Critical
        // chain claiming attacker movement between them.
        let mut chains = Vec::new();
        for (_host, group) in scope::group_by(findings, scope::host_scope) {
            let has_cors_with_creds = group.iter().any(is_cors_with_creds);
            let secret_findings: Vec<&Finding> = group.iter().copied().filter(is_secret).collect();

            if !has_cors_with_creds || secret_findings.is_empty() {
                continue;
            }

            let chain = Finding::builder(
                "correlation",
                secret_findings[0].target(),
                Severity::Critical,
            )
            .title("CORS Origin Reflection + JS Secrets = Credential Theft")
            .detail(format!(
                "CORS allows arbitrary origins with credentials AND {} secret(s) found in \
                 JavaScript on the same target. An attacker on any domain can: (1) make \
                 authenticated cross-origin requests to steal user session data, (2) access API \
                 endpoints using the leaked credentials from JS. Combined, this enables full \
                 account takeover without any user interaction beyond visiting a page.",
                secret_findings.len()
            ))
            .kind(FindingKind::Vulnerability)
            .tag("chain")
            .tag("cors")
            .tag("secret")
            .build_or_log();

            chains.extend(chain);
        }
        chains
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::correlation::CorrelationRule;

    fn finding(scanner: &str, target: &str, title: &str, tags: &[&str]) -> Finding {
        finding_sev(scanner, target, title, tags, Severity::High)
    }

    fn finding_sev(
        scanner: &str,
        target: &str,
        title: &str,
        tags: &[&str],
        sev: Severity,
    ) -> Finding {
        let mut b = Finding::builder(scanner, target, sev).title(title);
        for t in tags {
            b = b.tag(*t);
        }
        b.build().expect("test finding")
    }

    /// Adversarial: CORS misconfig on host A and secret on unrelated
    /// host B MUST NOT chain. Pre-fix the rule fired any time both
    /// signals existed anywhere in the same scan.
    #[test]
    fn cors_secret_chain_does_not_fire_across_unrelated_hosts() {
        let rule = CorsSecretChainRule;
        let findings = vec![
            finding(
                "hidden",
                "app.example.com",
                "CORS allows arbitrary origin with credentials",
                &[],
            ),
            finding(
                "js",
                "unrelated-target.com",
                "AWS Access Key in JS",
                &["secret"],
            ),
        ];
        assert!(
            rule.check(&findings, &[]).is_empty(),
            "cross-host cors+secret chain emitted as a false positive"
        );
    }

    #[test]
    fn cors_secret_chain_fires_when_both_on_same_host() {
        let rule = CorsSecretChainRule;
        let findings = vec![
            finding_sev(
                "hidden",
                "app.example.com",
                "CORS: arbitrary origin reflected with credentials",
                &["cors"],
                Severity::Critical,
            ),
            finding("js", "app.example.com", "AWS Access Key in JS", &["secret"]),
        ];
        let chains = rule.check(&findings, &[]);
        assert_eq!(chains.len(), 1);
        assert_eq!(chains[0].target(), "app.example.com");
    }

    /// PRECISION (the real defect  -  pre-2026-05-22). `gossan_hidden::cors`
    /// emits "CORS: wildcard origin with credentials" at Medium with an
    /// explicit comment noting that browsers reject `*+credentials`. The
    /// chain claims an attacker can read authenticated cross-origin
    /// responses  -  a claim the browser invalidates for this exact case.
    /// A Medium browser-rejected misconfig MUST NOT escalate to Critical
    /// "Credential Theft" when paired with a JS secret.
    #[test]
    fn cors_secret_chain_does_not_fire_on_browser_rejected_wildcard_creds() {
        let rule = CorsSecretChainRule;
        let findings = vec![
            finding_sev(
                "hidden",
                "app.example.com",
                "CORS: wildcard origin with credentials",
                &["cors", "misconfiguration"],
                Severity::Medium,
            ),
            finding("js", "app.example.com", "AWS Access Key in JS", &["secret"]),
        ];
        assert!(
            rule.check(&findings, &[]).is_empty(),
            "browser-rejected `*+credentials` finding wrongly escalated to credential-theft chain"
        );
    }

    /// PROVING: each real credential-theft CORS title still chains  - 
    /// the severity gate must not over-correct away the real cases.
    #[test]
    fn cors_secret_chain_still_fires_on_each_real_credential_theft_title() {
        let rule = CorsSecretChainRule;
        for (title, sev) in [
            (
                "CORS: arbitrary origin reflected with credentials",
                Severity::Critical,
            ),
            (
                "CORS: arbitrary origin reflected with credentials (preflight)",
                Severity::Critical,
            ),
            (
                "CORS: null origin trusted with credentials",
                Severity::Critical,
            ),
        ] {
            let findings = vec![
                finding_sev("hidden", "app.example.com", title, &["cors"], sev),
                finding("js", "app.example.com", "AWS Access Key in JS", &["secret"]),
            ];
            let chains = rule.check(&findings, &[]);
            assert_eq!(
                chains.len(),
                1,
                "real credential-theft title {title:?} must still chain"
            );
        }
    }

    /// ADVERSARIAL: a Low/Info finding whose title happens to contain
    /// both "cors" and "credential" (e.g. a docs/recon notice) must not
    /// chain  -  the severity gate is the precision lever.
    #[test]
    fn cors_secret_chain_ignores_low_severity_creds_findings() {
        let rule = CorsSecretChainRule;
        let findings = vec![
            finding_sev(
                "hidden",
                "app.example.com",
                "CORS exposes /credentials path (info)",
                &["cors"],
                Severity::Low,
            ),
            finding("js", "app.example.com", "AWS Access Key in JS", &["secret"]),
        ];
        assert!(
            rule.check(&findings, &[]).is_empty(),
            "Low-severity CORS finding wrongly drove a Critical chain"
        );
    }
}
