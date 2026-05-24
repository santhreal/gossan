use crate::correlation::CorrelationRule;
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
            // We only care about findings whose target is a literal IP
            // address (the rule's premise: an IP hosting certs for
            // domains that were never mapped via DNS). The old
            // "starts with an ASCII digit" proxy both *misfired* on
            // digit-leading hostnames (1password.com, 23andme.com,
            // 7-eleven.com → a bogus "IP address 1password.com hosts
            // TLS certs" finding) and *missed* every IPv6 host (fe80::,
            // ::1 don't start with a digit). Parse it as an actual IP.
            if !target_is_ip(f.target()) {
                continue;
            }

            for ev in f.evidence() {
                if let Evidence::Certificate { subject, san, .. } = ev {
                    let mut shadow_domains = Vec::new();

                    let subject_norm = normalize_domain(subject);
                    if !known_domains.contains(&subject_norm)
                        && is_interesting_domain(&subject_norm)
                    {
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

/// True iff `target` is a literal IPv4/IPv6 address, tolerating an
/// optional scheme, `:port`, and bracketed-IPv6 (`[::1]:443`) form.
/// A digit-leading *hostname* (e.g. `1password.com`) is NOT an IP and
/// must return false.
fn target_is_ip(target: &str) -> bool {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    let host = target.trim();
    let host = host
        .strip_prefix("https://")
        .or_else(|| host.strip_prefix("http://"))
        .unwrap_or(host);
    let host = host.split('/').next().unwrap_or(host);

    // Bracketed IPv6, with or without a port: [::1] / [::1]:443
    if let Some(rest) = host.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            return rest[..end].parse::<Ipv6Addr>().is_ok();
        }
        return false;
    }

    // Bare address (covers IPv4 and unbracketed IPv6 with no port).
    if host.parse::<IpAddr>().is_ok() {
        return true;
    }

    // IPv4 with a port: exactly one colon, left side is an IPv4.
    if let Some((h, _port)) = host.rsplit_once(':') {
        if !h.contains(':') {
            return h.parse::<Ipv4Addr>().is_ok();
        }
    }
    false
}

fn is_interesting_domain(domain: &str) -> bool {
    let lower = domain.to_lowercase();
    !(lower.ends_with(".cloudfront.net")
        || lower.ends_with(".azureedge.net")
        || lower.ends_with(".github.io")
        || lower.ends_with(".amazonaws.com")
        || lower == "google.com"
        || lower.ends_with(".google.com")
        || lower.is_empty())
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

    fn cert_finding(target: &str, subject: &str, san: &[&str]) -> Finding {
        Finding::builder("portscan", target, Severity::High)
            .title("TLS Certificate")
            .evidence(Evidence::Certificate {
                subject: subject.into(),
                issuer: "Let's Encrypt".into(),
                san: san.iter().map(|s| (*s).into()).collect(),
                expires: "2030".into(),
            })
            .build()
            .expect("test finding")
    }

    #[test]
    fn target_is_ip_accepts_real_ips_rejects_digit_leading_hosts() {
        assert!(target_is_ip("203.0.113.10"));
        assert!(target_is_ip("203.0.113.10:443"));
        assert!(target_is_ip("2001:db8::1"));
        assert!(target_is_ip("[2001:db8::1]:443"));
        assert!(target_is_ip("https://198.51.100.7/"));
        assert!(!target_is_ip("1password.com"));
        assert!(!target_is_ip("23andme.com"));
        assert!(!target_is_ip("7-eleven.com"));
        assert!(!target_is_ip("99designs.com:443"));
        assert!(!target_is_ip("3.example.com"));
    }

    /// PROVING: a TLS cert on a real IP that reveals an unmapped domain
    /// still produces the shadow-infra finding  -  including IPv6 hosts,
    /// which the old digit heuristic skipped entirely (false negative).
    #[test]
    fn shadow_infra_fires_on_ipv4_and_ipv6_targets() {
        let rule = ShadowInfrastructureRule;
        for ip in ["203.0.113.10", "2001:db8::1", "203.0.113.10:443"] {
            let f = cert_finding(
                ip,
                "shadowcorp-internal.example",
                &["vpn.shadowcorp-internal.example"],
            );
            let chains = rule.check(&[f], &[]);
            assert_eq!(chains.len(), 1, "expected shadow-infra finding for IP {ip}");
            assert!(chains[0].title().contains("Shadow Infrastructure"));
        }
    }

    /// ADVERSARIAL: a digit-leading *hostname* is not an IP. Pre-fix
    /// this emitted a factually wrong "IP address 1password.com was
    /// found to host TLS certificates" finding.
    #[test]
    fn shadow_infra_does_not_fire_on_digit_leading_hostname() {
        let rule = ShadowInfrastructureRule;
        for host in ["1password.com", "23andme.com", "7-eleven.com", "99designs.com"] {
            let f = cert_finding(host, "shadowcorp-internal.example", &[]);
            let chains = rule.check(&[f], &[]);
            assert!(
                chains.is_empty(),
                "digit-leading hostname {host:?} misclassified as IP, emitted: {:?}",
                chains
                    .iter()
                    .map(|c| c.title().to_string())
                    .collect::<Vec<_>>()
            );
        }
    }
}
