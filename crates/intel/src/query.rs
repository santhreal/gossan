//! Target lookup against the passive intel database and online enrichment.

use gossan_core::Target;
use secfinding;

use crate::db::{IntelDb, IntelRecord};
use crate::enrichment::IntelEnrichment;

/// Offline SQLite lookup for a target.
pub fn lookup_target_offline(
    db: &IntelDb,
    target: &Target,
    input: &gossan_core::ScanInput,
) -> anyhow::Result<()> {
    let ip = target.ip();
    let domain = target.domain();

    // 1. Lookup by IP
    if let Some(ip_addr) = ip {
        let ip_str = ip_addr.to_string();
        let records = db.query_by_ip(&ip_str)?;
        for r in records {
            if let Some(finding) = record_to_finding(&r) {
                input.emit(finding);
            }
        }
    }

    // 2. Lookup by Hostname
    if let Some(host) = domain {
        let records = db.query_by_host(host)?;
        for r in records {
            if let Some(finding) = record_to_finding(&r) {
                input.emit(finding);
            }
        }
    }

    Ok(())
}

pub fn record_to_finding(r: &IntelRecord) -> Option<secfinding::Finding> {
    let title = format!("Passive Intel: {}/{}", r.port, r.protocol);
    let mut detail = format!("IP: {}\nPort: {}\nProtocol: {}", r.ip, r.port, r.protocol);
    if let Some(ref b) = r.banner {
        detail.push_str(&format!("\nBanner: {b}"));
    }

    let mut builder = secfinding::Finding::builder("intel", &r.ip, secfinding::Severity::Info)
        .title(title)
        .detail(detail)
        .kind(secfinding::FindingKind::InfoDisclosure)
        .tag("passive")
        .tag("intel");

    for tech in &r.tech_stack {
        builder = builder.tag(format!("tech:{tech}"));
    }

    let f = builder.build().ok()?;

    Some(f)
}

/// Convert an online enrichment into a finding.
pub fn enrichment_to_finding(e: &IntelEnrichment) -> Option<secfinding::Finding> {
    let target = &e.target_value;
    let title = format!("Intel enrichment from {}: {}", e.source, e.target_value);
    let mut detail = format!("Source: {}\nTarget: {}\n", e.source, e.target_value);

    if let Some(ref classification) = e.classification {
        detail.push_str(&format!("Classification: {classification}\n"));
    }
    if let Some(ref asn) = e.asn {
        detail.push_str(&format!("ASN: {} ({})", asn.asn, asn.org.as_deref().unwrap_or("unknown")));
    }

    let mut builder = secfinding::Finding::builder("intel", target, secfinding::Severity::Info)
        .title(title)
        .detail(detail)
        .kind(secfinding::FindingKind::InfoDisclosure)
        .tag("enrichment")
        .tag(&e.source);

    for tag in &e.tags {
        builder = builder.tag(tag.as_str());
    }
    for tech in &e.technologies {
        builder = builder.tag(format!("tech:{tech}"));
    }
    for svc in &e.services {
        builder = builder.tag(format!("port:{}/{}", svc.port, svc.protocol));
    }
    builder = builder.tag(format!("intel_version:{}", e.version));

    let finding = builder.build().ok()?;

    Some(finding)
}
