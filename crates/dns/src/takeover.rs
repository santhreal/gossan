//! Subdomain takeover detection via dangling DNS records.
//!
//! Detects three classes of takeover:
//!
//! 1. **CNAME takeover**: Domain has a CNAME pointing to a service (GitHub Pages,
//!    Heroku, Azure, etc.) that no longer claims the hostname. An attacker
//!    registers on the service and captures the subdomain.
//!
//! 2. **NS takeover**: Nameserver delegation points to a domain that doesn't
//!    resolve or is available for registration.
//!
//! 3. **MX takeover**: MX records point to unclaimed mail servers — an attacker
//!    can receive email for the domain.
//!
//! # Fingerprint database
//!
//! The CNAME fingerprint database is embedded at compile time from `takeovers.txt`.
//! To add a service: append `service-cname-suffix:Service Name` to the file.

use gossan_core::Target;
use hickory_resolver::{proto::rr::RecordType, TokioAsyncResolver};
use secfinding::{Evidence, Finding, Severity};

/// CNAME takeover fingerprints loaded at compile time.
static FINGERPRINTS: &str = include_str!("takeovers.txt");

/// Run all takeover checks: CNAME, NS, and MX.
pub async fn check(
    resolver: &TokioAsyncResolver,
    domain: &str,
    target: &Target,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    findings.extend(check_cname(resolver, domain, target).await);
    findings.extend(check_ns(resolver, domain, target).await);
    findings.extend(check_mx(resolver, domain, target).await);
    findings
}

/// Parse the fingerprint database into (suffix, service_name) pairs.
fn fingerprints() -> Vec<(&'static str, &'static str)> {
    FINGERPRINTS
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .filter_map(|l| {
            let (suffix, name) = l.split_once(':')?;
            Some((suffix.trim(), name.trim()))
        })
        .collect()
}

// ── CNAME takeover ──────────────────────────────────────────────────────────

/// Detect dangling CNAMEs pointing at 60+ service fingerprints.
///
/// A CNAME is considered dangling when:
/// 1. The CNAME target matches a known service suffix, AND
/// 2. The CNAME target itself does not resolve (NXDOMAIN or SERVFAIL)
async fn check_cname(
    resolver: &TokioAsyncResolver,
    domain: &str,
    target: &Target,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    let cname = match resolver.lookup(domain, RecordType::CNAME).await {
        Ok(response) => {
            let records: Vec<String> = response
                .iter()
                .filter_map(|r| {
                    if let hickory_resolver::proto::rr::RData::CNAME(c) = r {
                        Some(c.to_string().trim_end_matches('.').to_string())
                    } else {
                        None
                    }
                })
                .collect();
            if records.is_empty() {
                return findings;
            }
            records[0].clone()
        }
        Err(_) => return findings,
    };

    let fps = fingerprints();
    let matched_service = fps
        .iter()
        .find(|(suffix, _)| cname.ends_with(suffix));

    let (suffix, service) = match matched_service {
        Some(s) => *s,
        None => return findings,
    };

    // Check if the CNAME target actually resolves
    let dangling = resolver.lookup(domain, RecordType::A).await.is_err();

    if dangling {
        findings.push(
            Finding::builder("dns", target.domain().unwrap_or("?"), Severity::Critical)
                .title(format!("Subdomain takeover: dangling CNAME → {service}"))
                .detail(format!(
                    "{domain} has CNAME → {cname} (matches {suffix} → {service}) \
                     but the target does not resolve. An attacker can register this \
                     hostname on {service} and serve arbitrary content on {domain}."
                ))
                .evidence(Evidence::DnsRecord {
                    record_type: "CNAME".into(),
                    value: cname.clone(),
                })
                .tag("takeover")
                .tag("cname")
                .tag("critical")
                .build()
                .expect("finding builder: required fields are set"),
        );
    } else {
        // CNAME resolves but points at known service — informational
        findings.push(
            Finding::builder("dns", target.domain().unwrap_or("?"), Severity::Info)
                .title(format!("CNAME → {service} (currently resolves)"))
                .detail(format!(
                    "{domain} has CNAME → {cname} pointed at {service}. \
                     Currently resolving, but will become takeover-vulnerable if \
                     the {service} account is deleted."
                ))
                .tag("takeover").tag("monitoring")
                .build()
                .expect("finding builder: required fields are set"),
        );
    }

    findings
}

// ── NS takeover ─────────────────────────────────────────────────────────────

/// Detect dangling nameserver delegations.
///
/// If a domain's NS record points to a nameserver that doesn't resolve,
/// an attacker who registers that nameserver domain controls all DNS for
/// the victim domain — the most severe form of takeover.
async fn check_ns(
    resolver: &TokioAsyncResolver,
    domain: &str,
    target: &Target,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    let ns_records = match resolver.lookup(domain, RecordType::NS).await {
        Ok(r) => r,
        Err(_) => return findings,
    };

    let nameservers: Vec<String> = ns_records
        .iter()
        .filter_map(|r| {
            if let hickory_resolver::proto::rr::RData::NS(ns) = r {
                Some(ns.to_string().trim_end_matches('.').to_string())
            } else {
                None
            }
        })
        .collect();

    for ns in &nameservers {
        if resolver
            .lookup(ns.as_str(), RecordType::A)
            .await
            .is_err()
        {
            findings.push(
                Finding::builder("dns", target.domain().unwrap_or("?"), Severity::Critical)
                    .title(format!("NS takeover: dangling nameserver {ns}"))
                    .detail(format!(
                        "{domain} delegates DNS to {ns} which does not resolve. \
                         If an attacker registers {ns}, they control ALL DNS records \
                         for {domain} — full domain hijack."
                    ))
                    .evidence(Evidence::DnsRecord {
                        record_type: "NS".into(),
                        value: ns.clone(),
                    })
                    .tag("takeover")
                    .tag("ns")
                    .tag("critical")
                    .build()
                    .expect("finding builder: required fields are set"),
            );
        }
    }

    // NS count resilience
    if nameservers.len() < 2 {
        findings.push(
            Finding::builder("dns", target.domain().unwrap_or("?"), Severity::Low)
                .title(format!("Only {} nameserver(s) — no redundancy", nameservers.len()))
                .detail(format!(
                    "{domain} has {count} NS record(s). RFC 2182 recommends ≥2. \
                     Single nameserver failure = total domain outage.",
                    count = nameservers.len()
                ))
                .tag("dns").tag("resilience")
                .build()
                .expect("finding builder: required fields are set"),
        );
    }

    findings
}

// ── MX takeover ─────────────────────────────────────────────────────────────

/// Detect dangling MX records pointing to unresolvable mail servers.
///
/// An attacker who controls the MX target can receive all email sent to
/// the domain — password resets, MFA codes, confidential communications.
async fn check_mx(
    resolver: &TokioAsyncResolver,
    domain: &str,
    target: &Target,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    let mx_records = match resolver.mx_lookup(domain).await {
        Ok(r) => r,
        Err(_) => return findings,
    };

    let exchanges: Vec<String> = mx_records
        .iter()
        .map(|mx| mx.exchange().to_string().trim_end_matches('.').to_string())
        .collect();

    for mx in &exchanges {
        if mx == "." {
            continue; // null MX (RFC 7505) — intentional
        }
        if resolver.lookup(mx.as_str(), RecordType::A).await.is_err() {
            findings.push(
                Finding::builder("dns", target.domain().unwrap_or("?"), Severity::High)
                    .title(format!("MX takeover risk: dangling mail server {mx}"))
                    .detail(format!(
                        "{domain} MX record points to {mx} which does not resolve. \
                         If an attacker claims this hostname, they receive all email \
                         for {domain} — password resets, MFA codes, confidential data."
                    ))
                    .evidence(Evidence::DnsRecord {
                        record_type: "MX".into(),
                        value: mx.clone(),
                    })
                    .tag("takeover")
                    .tag("mx")
                    .build()
                    .expect("finding builder: required fields are set"),
            );
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_database_loads() {
        let fps = fingerprints();
        assert!(
            fps.len() >= 50,
            "should have 50+ service fingerprints, got {}",
            fps.len()
        );
    }

    #[test]
    fn fingerprints_have_valid_format() {
        for (suffix, name) in fingerprints() {
            assert!(!suffix.is_empty(), "empty suffix found");
            assert!(!name.is_empty(), "empty name for suffix: {suffix}");
            assert!(
                suffix.contains('.'),
                "suffix should be a domain: {suffix}"
            );
        }
    }

    #[test]
    fn known_services_present() {
        let fps = fingerprints();
        let suffixes: Vec<&str> = fps.iter().map(|(s, _)| *s).collect();
        for expected in [
            "github.io",
            "herokuapp.com",
            "amazonaws.com",
            "azurewebsites.net",
            "netlify.app",
            "vercel.app",
        ] {
            assert!(
                suffixes.contains(&expected),
                "missing fingerprint: {expected}"
            );
        }
    }

    #[test]
    fn no_duplicate_suffixes() {
        let fps = fingerprints();
        let mut seen = std::collections::HashSet::new();
        for (suffix, name) in &fps {
            assert!(
                seen.insert(*suffix),
                "duplicate suffix: {suffix} ({name})"
            );
        }
    }
}
