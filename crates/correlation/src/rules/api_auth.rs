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

        // 1. Group findings by target domain
        let mut by_target = std::collections::HashMap::new();
        for f in findings {
            by_target.entry(f.target()).or_insert_with(Vec::new).push(f);
        }

        // 2. For each target, look for version disclosure + missing auth
        for (target, fs) in by_target {
            let versions: Vec<_> = fs
                .iter()
                .filter(|f| f.tags().iter().any(|t| t.as_ref() == "api-version"))
                .collect();

            let no_auth = fs.iter().any(|f| {
                f.title().to_lowercase().contains("no authentication")
                    || f.title().to_lowercase().contains("unauthenticated")
            });

            if !versions.is_empty() && no_auth {
                gossan_core::try_push_finding(
                    Finding::builder("correlation", target, Severity::Critical)
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
