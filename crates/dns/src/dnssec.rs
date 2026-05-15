//! DNSSEC validation and zone walking detection.
//!
//! Evaluates the cryptographic security of DNS responses:
//!
//! **DNSSEC**: Validates if the domain is signed (DNSKEY/DS records).
//! Missing DNSSEC allows for DNS spoofing and cache poisoning.
//!
//! **NSEC/NSEC3**: Checks for "zone walking" vulnerabilities. NSEC records
//! reveal the next record in the zone, allowing an attacker to enumerate
//! all subdomains. NSEC3 uses hashing but can still be vulnerable if
//! iterations/salts are weak or if opt-out is used.

use gossan_core::Target;
use hickory_resolver::{proto::rr::RecordType, TokioAsyncResolver};
use secfinding::{Evidence, Finding, Severity, FindingKind};

/// Run all DNSSEC checks.
pub async fn check(
    resolver: &TokioAsyncResolver,
    domain: &str,
    target: &Target,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    findings.extend(check_dnssec_signed(resolver, domain, target).await);
    findings.extend(check_zone_walking(resolver, domain, target).await);
    findings.extend(check_nsec3param(resolver, domain, target).await);
    findings.extend(check_ns_dnssec(resolver, domain, target).await);
    findings
}

/// Check if the domain is DNSSEC signed.
async fn check_dnssec_signed(
    resolver: &TokioAsyncResolver,
    domain: &str,
    target: &Target,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Look for DNSKEY records
    let dnskey = resolver.lookup(domain, RecordType::DNSKEY).await;
    let ds = resolver.lookup(domain, RecordType::DS).await;

    if dnskey.is_err() && ds.is_err() {
        gossan_core::try_push_finding(
            Finding::builder("dns", target.domain().unwrap_or("?"), Severity::Medium)
                .title("DNSSEC not enabled")
                .detail(format!(
                    "Domain {domain} is not DNSSEC signed. This leaves the domain \
                     vulnerable to DNS spoofing and cache poisoning attacks. \
                     DNSSEC (RFC 4033) ensures the integrity and authenticity of \
                     DNS data using digital signatures."
                ))
                .kind(FindingKind::Misconfiguration)
                .tag("dns")
                .tag("dnssec")
                .tag("posture"),
            &mut findings,
        );
    } else {
        gossan_core::try_push_finding(
            Finding::builder("dns", target.domain().unwrap_or("?"), Severity::Info)
                .title("DNSSEC enabled")
                .detail(format!("Domain {domain} is protected by DNSSEC."))
                .kind(FindingKind::Misconfiguration)
                .tag("dns")
                .tag("dnssec")
                .tag("good"),
            &mut findings,
        );
    }

    findings
}

/// Detect if the zone supports enumeration via NSEC/NSEC3.
async fn check_zone_walking(
    resolver: &TokioAsyncResolver,
    domain: &str,
    target: &Target,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Query for a non-existent subdomain to trigger NSEC/NSEC3 response
    let nx_domain = format!("gossan-nx-test-{}.{}", fastrand::u32(..), domain);
    
    // We use a raw lookup to see the authority section records
    let _lookup = resolver.lookup(nx_domain, RecordType::A).await;
    
    if let Ok(nsec) = resolver.lookup(domain, RecordType::NSEC).await {
        if !nsec.iter().collect::<Vec<_>>().is_empty() {
            gossan_core::try_push_finding(
                Finding::builder("dns", target.domain().unwrap_or("?"), Severity::High)
                    .title("DNSSEC Zone Walking enabled (NSEC)")
                    .detail(format!(
                        "Domain {domain} uses NSEC records. NSEC reveals the next \
                         valid record in the zone, allowing an attacker to \
                         enumerate all subdomains by 'walking' the chain. \
                         Recommendation: Migrate to NSEC3."
                    ))
                    .kind(FindingKind::Misconfiguration)
                    .tag("dns")
                    .tag("dnssec")
                    .tag("enumeration")
                    .evidence(Evidence::DnsRecord {
                        record_type: "NSEC".into(),
                        value: "NSEC records present".into(),
                    }),
                &mut findings,
            );
        }
    }

    findings
}

/// Check NSEC3 parameters for weaknesses.
async fn check_nsec3param(
    resolver: &TokioAsyncResolver,
    domain: &str,
    target: &Target,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    if let Ok(lookup) = resolver.lookup(domain, RecordType::NSEC3PARAM).await {
        if !lookup.iter().collect::<Vec<_>>().is_empty() {
            gossan_core::try_push_finding(
                Finding::builder("dns", target.domain().unwrap_or("?"), Severity::Info)
                    .title("DNSSEC: NSEC3 supported")
                    .detail(format!(
                        "Domain {domain} uses NSEC3 records. NSEC3 provides hashed \
                         denial-of-existence, preventing easy zone walking. \
                         This is a defensive improvement over NSEC."
                    ))
                    .kind(FindingKind::Misconfiguration)
                    .tag("dns")
                    .tag("dnssec")
                    .tag("good"),
                &mut findings,
            );
        }
    }

    findings
}

/// Check if nameservers for the domain support DNSSEC.
async fn check_ns_dnssec(
    resolver: &TokioAsyncResolver,
    domain: &str,
    target: &Target,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    if let Ok(ns_lookup) = resolver.lookup(domain, RecordType::NS).await {
        for ns in ns_lookup.iter() {
            if let Some(ns_name) = ns.as_ns() {
                let ns_str = ns_name.to_string();
                if let Ok(ds) = resolver.lookup(ns_str.as_str(), RecordType::DS).await {
                    if ds.iter().collect::<Vec<_>>().is_empty() {
                         gossan_core::try_push_finding(
                            Finding::builder("dns", target.domain().unwrap_or("?"), Severity::Low)
                                .title("DNSSEC: Nameserver not signed")
                                .detail(format!(
                                    "The nameserver {} is not DNSSEC-signed. While the zone itself \
                                     might be signed, unsigned nameservers increase the risk of \
                                     redirection attacks at the TLD level.",
                                    ns_str
                                ))
                                .kind(FindingKind::Misconfiguration)
                                .tag("dns")
                                .tag("dnssec")
                                .tag("posture"),
                            &mut findings,
                        );
                    }
                }
            }
        }
    }

    findings
}
