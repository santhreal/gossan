//! Correlates source code exposure with hardcoded secret detection.
//!
//! When a scanner detects:
//!   1. Source code exposure (.git, .env, source maps, swagger/openapi, debug endpoints)
//!   2. Hardcoded secrets in JavaScript or debug output
//!
//! This chain means the attacker has a direct path from discoverable source code
//! to extractable credentials. The severity is always Critical because the
//! attack chain is: discover source → extract secret → authenticate as app.

use gossan_core::Target;
use secfinding::{Finding, FindingKind, Severity};

use crate::correlation::scope;

/// Patterns indicating source code has been exposed.
const SOURCE_SIGNALS: &[&str] = &[
    ".git",
    ".env",
    "source map",
    "sourcemap",
    "swagger",
    "openapi",
    "directory listing",
    "backup file",
    "debug",
    "profiler",
    "phpinfo",
    "actuator",
];

/// Patterns indicating hardcoded secrets were found.
const SECRET_SIGNALS: &[&str] = &[
    "secret",
    "api key",
    "access key",
    "private key",
    "token",
    "credential",
    "password",
    "aws",
    "stripe",
    "github pat",
    "jwt",
];

/// Correlates source code exposure with hardcoded secret findings.
pub struct SourceCodeSecretsRule;

impl super::super::CorrelationRule for SourceCodeSecretsRule {
    fn name(&self) -> &'static str {
        "source_code_secrets"
    }

    fn check(&self, findings: &[Finding], _targets: &[Target]) -> Vec<Finding> {
        let is_source = |f: &Finding| {
            let lower = f.title().to_lowercase();
            SOURCE_SIGNALS.iter().any(|sig| lower.contains(sig))
        };
        let is_secret = |f: &Finding| {
            let lower = f.title().to_lowercase();
            SECRET_SIGNALS.iter().any(|sig| lower.contains(sig))
        };

        // Cluster by normalized host so the chain only fires when BOTH
        // a source exposure and a secret are present on the SAME host
        // (an unrelated `.git` on example.com and an AWS key on
        // unrelated.com must not chain), and require *two distinct*
        // findings  -  a single title that contains both vocabularies
        // ("Source map exposes API key") is one finding, not a
        // correlation. Both rules now come from the audited
        // `scope` primitive instead of a hand-rolled `ptr::eq` loop.
        let mut chains = Vec::new();
        for (_host, group) in scope::group_by(findings, scope::host_scope) {
            if !scope::has_distinct_pair(&group, is_source, is_secret) {
                continue;
            }
            let source_exposures: Vec<&Finding> =
                group.iter().copied().filter(|&f| is_source(f)).collect();
            let secret_findings: Vec<&Finding> =
                group.iter().copied().filter(|&f| is_secret(f)).collect();

            let source_types: Vec<String> = source_exposures
                .iter()
                .map(|f| f.title().to_string())
                .take(3)
                .collect();
            let secret_types: Vec<String> = secret_findings
                .iter()
                .map(|f| f.title().to_string())
                .take(3)
                .collect();

            let chain = Finding::builder(
                "correlation",
                source_exposures[0].target(),
                Severity::Critical,
            )
            .title("Source Code Exposure → Credential Extraction Chain")
            .detail(format!(
                "Source code is exposed ({}) and contains hardcoded secrets ({}) on the same target. \
                 An attacker can follow this chain: discover exposed source → \
                 extract credentials → authenticate as the application. \
                 This is a direct path to compromise. \
                 Fix: remove source code from production AND rotate all exposed credentials.",
                source_types.join(", "),
                secret_types.join(", "),
            ))
            .kind(FindingKind::Vulnerability)
            .tag("chain")
            .tag("source-exposure")
            .tag("credential-leak")
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

    fn finding(scanner: &str, target: &str, title: &str) -> Finding {
        Finding::builder(scanner, target, Severity::High)
            .title(title)
            .build()
            .expect("test finding")
    }

    #[test]
    fn fires_when_source_and_secrets_present() {
        let rule = SourceCodeSecretsRule;
        let findings = vec![
            finding("hidden", "example.com", ".git/config exposed"),
            finding("js", "example.com", "AWS Access Key in JavaScript"),
        ];
        let chains = rule.check(&findings, &[]);
        assert_eq!(chains.len(), 1);
        assert!(chains[0].title().contains("Source Code Exposure"));
    }

    #[test]
    fn does_not_fire_with_only_source_exposure() {
        let rule = SourceCodeSecretsRule;
        let findings = vec![finding("hidden", "example.com", ".git/config exposed")];
        assert!(rule.check(&findings, &[]).is_empty());
    }

    #[test]
    fn does_not_fire_with_only_secrets() {
        let rule = SourceCodeSecretsRule;
        let findings = vec![finding("js", "example.com", "AWS Access Key in JavaScript")];
        assert!(rule.check(&findings, &[]).is_empty());
    }

    /// Adversarial: source exposure on host A and secret on host B
    /// MUST NOT chain. Pre-fix, both being present anywhere in the
    /// finding set fired a Critical chain claiming attacker movement
    /// between unrelated targets.
    #[test]
    fn does_not_chain_across_unrelated_hosts() {
        let rule = SourceCodeSecretsRule;
        let findings = vec![
            finding("hidden", "example.com", ".git/config exposed"),
            finding("js", "unrelated-target.com", "AWS Access Key in JavaScript"),
        ];
        let chains = rule.check(&findings, &[]);
        assert!(
            chains.is_empty(),
            "cross-host chain emitted: {:?}",
            chains.iter().map(Finding::title).collect::<Vec<_>>()
        );
    }

    /// ADVERSARIAL: a *single* finding whose title contains both a
    /// source-exposure word and a secret word must NOT self-chain.
    /// These are real scanner titles ("Spring Boot Actuator
    /// /actuator/env exposes credentials" → "actuator"+"credential";
    /// "Source map exposes API key" → "source map"+"api key";
    /// "Debug endpoint leaks JWT token" → "debug"+"jwt"/"token"). The
    /// chain models two *independent* findings; one finding restating
    /// both halves is already reported by its own scanner and must not
    /// be duplicated as a Critical correlation.
    #[test]
    fn single_finding_matching_both_vocabularies_does_not_self_chain() {
        let rule = SourceCodeSecretsRule;
        for title in [
            "Spring Boot Actuator /actuator/env exposes credentials",
            "Source map exposes API key",
            "Debug endpoint leaks JWT token",
            "phpinfo() page reveals database password",
        ] {
            let findings = vec![finding("hidden", "example.com", title)];
            let chains = rule.check(&findings, &[]);
            assert!(
                chains.is_empty(),
                "single finding {title:?} self-chained into {:?}",
                chains.iter().map(Finding::title).collect::<Vec<_>>()
            );
        }
    }

    /// PROVING (regression twin): the same dual-vocabulary finding,
    /// when accompanied by a genuinely *distinct* second finding of the
    /// complementary type on the same host, MUST still chain  -  the fix
    /// suppresses self-chains without suppressing real two-finding
    /// chains that merely include a dual-vocabulary title.
    #[test]
    fn dual_vocab_finding_plus_distinct_partner_still_chains() {
        let rule = SourceCodeSecretsRule;
        let findings = vec![
            // Dual-vocab (source+secret) ...
            finding("hidden", "example.com", "Debug endpoint leaks JWT token"),
            // ... plus a distinct pure-source finding on the same host.
            finding("hidden", "example.com", ".git/config exposed"),
        ];
        let chains = rule.check(&findings, &[]);
        assert_eq!(
            chains.len(),
            1,
            "two distinct findings (one dual-vocab) must still chain"
        );
        assert_eq!(chains[0].target(), "example.com");
    }

    #[test]
    fn chains_when_source_and_secret_on_same_host() {
        let rule = SourceCodeSecretsRule;
        let findings = vec![
            finding("hidden", "example.com", ".git/config exposed"),
            finding("js", "example.com", "AWS Access Key in JavaScript"),
            finding("hidden", "other-host.com", ".git/config exposed"), // alone, ignored
        ];
        let chains = rule.check(&findings, &[]);
        assert_eq!(chains.len(), 1);
        assert_eq!(chains[0].target(), "example.com");
    }
}
