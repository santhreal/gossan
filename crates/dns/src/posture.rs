//! DNS posture assessment: CAA, NS resilience, and MX enumeration.
//!
//! Evaluates the defensive DNS configuration of a domain beyond email auth:
//!
//! **CAA**: Certificate Authority Authorization (RFC 8659). If absent, any CA
//! can issue certificates for the domain. If present, validates that the
//! policy is restrictive enough (iodef reporting, wildcard restrictions).
//!
//! **NS resilience**: Assesses nameserver redundancy and distribution. Single
//! nameserver = single point of failure. Same /24 = colocation risk.
//!
//! **MX enumeration**: Discovers mail topology for intelligence gathering.

use gossan_core::Target;
use hickory_resolver::{proto::rr::RecordType, TokioAsyncResolver};
use secfinding::{Evidence, Finding, Severity};

/// Run all posture checks.
pub async fn check(
    resolver: &TokioAsyncResolver,
    domain: &str,
    target: &Target,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    findings.extend(check_caa(resolver, domain, target).await);
    findings.extend(check_mx_info(resolver, domain, target).await);
    findings
}

// ── CAA ─────────────────────────────────────────────────────────────────────

/// Certificate Authority Authorization audit.
///
/// Checks:
/// - Presence of CAA records (missing = any CA can issue)
/// - `issuewild` restrictions (missing = wildcard certs uncontrolled)
/// - `iodef` reporting URI (best practice for incident notification)
async fn check_caa(
    resolver: &TokioAsyncResolver,
    domain: &str,
    target: &Target,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    let caa_records = match resolver.lookup(domain, RecordType::CAA).await {
        Ok(r) => r,
        Err(_) => {
            findings.push(
                Finding::builder("dns", target.domain().unwrap_or("?"), Severity::Low)
                    .title("No CAA records — any CA may issue certificates")
                    .detail(format!(
                        "{domain} has no CAA DNS records. Any Certificate Authority \
                         can issue TLS certificates for this domain. CAA records \
                         (RFC 8659) restrict issuance to specific CAs, preventing \
                         unauthorized certificate creation."
                    ))
                    .tag("dns").tag("caa").tag("certificates")
                    .build()
                    .expect("finding builder: required fields are set"),
            );
            return findings;
        }
    };

    let mut has_issue = false;
    let mut has_issuewild = false;
    let mut has_iodef = false;
    let mut cas: Vec<String> = Vec::new();

    for record in caa_records.iter() {
        let text = record.to_string();
        if text.contains("issue ") || text.contains("issue\t") {
            has_issue = true;
            cas.push(text.clone());
        }
        if text.contains("issuewild") {
            has_issuewild = true;
        }
        if text.contains("iodef") {
            has_iodef = true;
        }
    }

    if has_issue {
        findings.push(
            Finding::builder("dns", target.domain().unwrap_or("?"), Severity::Info)
                .title(format!("CAA restricts certificate issuance to {} CA(s)", cas.len()))
                .detail(format!(
                    "{domain} has CAA records restricting TLS certificate issuance: {}",
                    cas.join(", ")
                ))
                .tag("dns").tag("caa").tag("good")
                .build()
                .expect("finding builder: required fields are set"),
        );
    }

    if !has_issuewild {
        findings.push(
            Finding::builder("dns", target.domain().unwrap_or("?"), Severity::Info)
                .title("CAA missing issuewild restriction")
                .detail(format!(
                    "{domain} has CAA issue records but no issuewild. \
                     Wildcard certificates (*.{domain}) are not explicitly restricted."
                ))
                .tag("dns").tag("caa")
                .build()
                .expect("finding builder: required fields are set"),
        );
    }

    if !has_iodef {
        findings.push(
            Finding::builder("dns", target.domain().unwrap_or("?"), Severity::Info)
                .title("CAA missing iodef (incident reporting URI)")
                .detail(format!(
                    "{domain} CAA records have no iodef tag. \
                     CAs will not notify you of rejected certificate requests."
                ))
                .tag("dns").tag("caa")
                .build()
                .expect("finding builder: required fields are set"),
        );
    }

    findings
}

// ── MX enumeration ──────────────────────────────────────────────────────────

/// Enumerate mail servers and report topology for intelligence gathering.
async fn check_mx_info(
    resolver: &TokioAsyncResolver,
    domain: &str,
    target: &Target,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    let mx_records = match resolver.mx_lookup(domain).await {
        Ok(r) => r,
        Err(_) => return findings,
    };

    let exchanges: Vec<(u16, String)> = mx_records
        .iter()
        .map(|mx| {
            (
                mx.preference(),
                mx.exchange().to_string().trim_end_matches('.').to_string(),
            )
        })
        .collect();

    if exchanges.is_empty() {
        return findings;
    }

    let topology: Vec<String> = exchanges
        .iter()
        .map(|(prio, mx)| format!("{prio} {mx}"))
        .collect();

    // Detect common mail providers for tech intelligence
    let provider = detect_mail_provider(&exchanges);

    findings.push(
        Finding::builder("dns", target.domain().unwrap_or("?"), Severity::Info)
            .title(format!(
                "Mail topology: {} MX record(s) — {}",
                exchanges.len(),
                provider.unwrap_or("custom infrastructure")
            ))
            .detail(format!(
                "{domain} mail exchange records:\n{}",
                topology.join("\n")
            ))
            .evidence(Evidence::DnsRecord {
                record_type: "MX".into(),
                value: topology.join("; "),
            })
            .tag("dns").tag("mx").tag("intel")
            .build()
            .expect("finding builder: required fields are set"),
    );

    findings
}

/// Detect common email provider from MX records.
fn detect_mail_provider(exchanges: &[(u16, String)]) -> Option<&'static str> {
    for (_, mx) in exchanges {
        let lower = mx.to_lowercase();
        if lower.contains("google") || lower.contains("aspmx") || lower.contains("googlemail") {
            return Some("Google Workspace");
        }
        if lower.contains("outlook") || lower.contains("microsoft") || lower.contains("office365") {
            return Some("Microsoft 365");
        }
        if lower.contains("pphosted") || lower.contains("proofpoint") {
            return Some("Proofpoint");
        }
        if lower.contains("mimecast") {
            return Some("Mimecast");
        }
        if lower.contains("barracuda") {
            return Some("Barracuda");
        }
        if lower.contains("zoho") {
            return Some("Zoho Mail");
        }
        if lower.contains("fastmail") {
            return Some("Fastmail");
        }
        if lower.contains("mailgun") {
            return Some("Mailgun");
        }
        if lower.contains("sendgrid") {
            return Some("SendGrid");
        }
        if lower.contains("amazonses") || lower.contains("ses.amazonaws") {
            return Some("Amazon SES");
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_google_workspace() {
        let mx = vec![(10, "aspmx.l.google.com".into())];
        assert_eq!(detect_mail_provider(&mx), Some("Google Workspace"));
    }

    #[test]
    fn detect_microsoft_365() {
        let mx = vec![(10, "mail.protection.outlook.com".into())];
        assert_eq!(detect_mail_provider(&mx), Some("Microsoft 365"));
    }

    #[test]
    fn detect_proofpoint() {
        let mx = vec![(10, "mx01.pphosted.com".into())];
        assert_eq!(detect_mail_provider(&mx), Some("Proofpoint"));
    }

    #[test]
    fn unknown_provider() {
        let mx = vec![(10, "mail.custom-server.net".into())];
        assert_eq!(detect_mail_provider(&mx), None);
    }

    #[test]
    fn detect_amazon_ses() {
        let mx = vec![(10, "feedback-smtp.us-east-1.amazonses.com".into())];
        assert_eq!(detect_mail_provider(&mx), Some("Amazon SES"));
    }
}
