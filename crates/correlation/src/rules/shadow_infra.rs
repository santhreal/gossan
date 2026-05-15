use crate::CorrelationRule;
use gossan_core::Target;
use secfinding::{Evidence, Finding, FindingKind, Severity};

/// Detects "Shadow Infrastructure" by correlating TLS SANs across IP targets.
pub struct ShadowInfrastructureRule;

impl CorrelationRule for ShadowInfrastructureRule {
    fn name(&self) -> &'static str {
        "shadow_infra"
    }

    fn check(&self, findings: &[Finding], targets: &[Target]) -> Vec<Finding> {
        let mut chains = Vec::new();
        let mut known_domains = std::collections::HashSet::new();

        // 1. Gather all domains we already know about
        for t in targets {
            if let Some(d) = t.domain() {
                known_domains.insert(normalize_domain(d));
            }
        }

        // 2. Look for TLS findings on IP targets
        for f in findings {
            // We only care about findings on IP-like targets (Host)
            if !f.target().chars().next().is_some_and(|c| c.is_ascii_digit()) {
                continue;
            }

            for ev in f.evidence() {
                if let Evidence::Certificate { subject, san, .. } = ev {
                    let mut shadow_domains = Vec::new();
                    
                    let subject_norm = normalize_domain(subject);
                    if !known_domains.contains(&subject_norm) && is_interesting_domain(&subject_norm) {
                        shadow_domains.push(subject_norm);
                    }

                    for s in san {
                        let s_norm = normalize_domain(s);
                        if !known_domains.contains(&s_norm) && is_interesting_domain(&s_norm) {
                            shadow_domains.push(s_norm);
                        }
                    }

                    if !shadow_domains.is_empty() {
                        shadow_domains.sort();
                        shadow_domains.dedup();

                        gossan_core::try_push_finding(
                            Finding::builder("correlation", f.target(), Severity::High)
                                .title("Shadow Infrastructure Identified")
                                .detail(format!(
                                    "IP address {} was found to host TLS certificates for domains not in the initial scan seed: {}. \
                                     This indicates the host is part of the organization's infrastructure but was not publicly mapped via DNS.",
                                    f.target(),
                                    shadow_domains.join(", ")
                                ))
                                .tag("shadow-infra")
                                .tag("tls-correlation")
                                .tag("recon")
                                .kind(FindingKind::Exposure)
                                .evidence(ev.clone()),
                            &mut chains
                        );
                    }
                }
            }
        }

        chains
    }
}

fn is_interesting_domain(domain: &str) -> bool {
    let lower = domain.to_lowercase();
    !(lower.ends_with(".cloudfront.net") ||
      lower.ends_with(".azureedge.net") ||
      lower.ends_with(".github.io") ||
      lower.ends_with(".amazonaws.com") ||
      lower == "google.com" ||
      lower.ends_with(".google.com") ||
      lower.is_empty())
}

fn normalize_domain(d: &str) -> String {
    let lower = d.to_lowercase();
    if let Some(stripped) = lower.strip_prefix("*.") {
        stripped.to_string()
    } else {
        lower
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_domain() {
        assert_eq!(normalize_domain("*.example.com"), "example.com");
        assert_eq!(normalize_domain("EXAMPLE.COM"), "example.com");
        assert_eq!(normalize_domain("api.example.com"), "api.example.com");
    }

    #[test]
    fn test_is_interesting_domain() {
        assert!(is_interesting_domain("example.com"));
        assert!(is_interesting_domain("googlesearch.mydomain.com"));
        assert!(!is_interesting_domain("foo.cloudfront.net"));
        assert!(!is_interesting_domain("my.azureedge.net"));
        assert!(!is_interesting_domain("google.com"));
        assert!(!is_interesting_domain("mail.google.com"));
    }
}
