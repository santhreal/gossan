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
use secfinding::{Evidence, Finding, Severity, FindingKind};

/// Run all posture checks.
pub async fn check(
    resolver: &TokioAsyncResolver,
    domain: &str,
    target: &Target,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    findings.extend(check_caa(resolver, domain, target).await);
    findings.extend(check_mx_info(resolver, domain, target).await);
    findings.extend(check_ns_resilience(resolver, domain, target).await);
    findings.extend(check_soa(resolver, domain, target).await);
    findings
}

// ── SOA ─────────────────────────────────────────────────────────────────────

/// Start of Authority (SOA) record audit.
async fn check_soa(
    resolver: &TokioAsyncResolver,
    domain: &str,
    target: &Target,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    let soa_records = match resolver.lookup(domain, RecordType::SOA).await {
        Ok(r) => r,
        Err(_) => return findings,
    };

    if let Some(hickory_resolver::proto::rr::RData::SOA(soa)) = soa_records.iter().next() {
        let serial = soa.serial();
        let _refresh = soa.refresh();
        let _retry = soa.retry();
        let expire = soa.expire();

        // Check if serial follows YYYYMMDDNN format
        let serial_str = serial.to_string();
        if serial_str.len() == 10 {
            let year: i32 = serial_str[0..4].parse().unwrap_or(0);
            if !(1990..=2100).contains(&year) {
                // Not YYYYMMDDNN
            }
        } else {
            // Not standard format — often just an incrementing counter, which is fine
            // but YYYYMMDDNN is preferred for human auditing.
        }

        if expire < 604800 {
            // Less than 7 days
            gossan_core::try_push_finding(
                Finding::builder("dns", target.domain().unwrap_or("?"), Severity::Low)
                    .title("SOA expiry time too low")
                    .detail(format!(
                        "Domain {domain} has an SOA expire value of {expire}s. \
                         RFC 1912 recommends 2-4 weeks (1209600 - 2419200s). \
                         If secondary nameservers cannot reach the primary for this duration, \
                         they will stop serving the zone."
                    ))
                    .kind(FindingKind::Misconfiguration)
                    .tag("dns")
                    .tag("soa")
                    .tag("posture"),
                &mut findings,
            );
        }
    }

    findings
}

// ── NS Resilience ───────────────────────────────────────────────────────────

/// Nameserver redundancy and distribution audit (RFC 2182).
///
/// Checks:
/// - Multiple nameservers (redundancy)
/// - IP distribution (colocation risk)
/// - Provider identification (tech intel)
async fn check_ns_resilience(
    resolver: &TokioAsyncResolver,
    domain: &str,
    target: &Target,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    let ns_records = match resolver.ns_lookup(domain).await {
        Ok(r) => r,
        Err(_) => return findings,
    };

    let nameservers: Vec<String> = ns_records
        .iter()
        .map(|ns| ns.to_string().trim_end_matches('.').to_string())
        .collect();

    if nameservers.is_empty() {
        return findings;
    }

    // Detect nameserver provider
    let provider = detect_ns_provider(&nameservers);

    if nameservers.len() < 2 {
        gossan_core::try_push_finding(
            Finding::builder("dns", target.domain().unwrap_or("?"), Severity::Medium)
                .title("Single point of failure: Only one nameserver")
                .detail(format!(
                    "Domain {domain} only has one authoritative nameserver ({}). \
                     If this server goes down, the domain becomes unreachable. \
                     RFC 2182 recommends at least three nameservers for resilience.",
                    nameservers[0]
                ))
                .kind(FindingKind::Misconfiguration)
                .tag("dns")
                .tag("ns")
                .tag("resilience"),
            &mut findings,
        );
    }

    gossan_core::try_push_finding(
        Finding::builder("dns", target.domain().unwrap_or("?"), Severity::Info)
            .title(format!(
                "Nameserver infrastructure: {} — {}",
                provider.unwrap_or("custom/managed"),
                nameservers.len()
            ))
            .detail(format!(
                "{domain} authoritative nameservers:\n{}",
                nameservers.join("\n")
            ))
            .kind(FindingKind::Misconfiguration)
            .tag("dns")
            .tag("ns")
            .tag("intel"),
        &mut findings,
    );

    // Check for IP colocation risk
    let mut ips = Vec::new();
    for ns in &nameservers {
        if let Ok(lookup) = resolver.lookup_ip(ns.as_str()).await {
            ips.extend(lookup.iter());
        }
    }

    if !ips.is_empty() {
        // Group by /24 subnet (IPv4)
        let mut subnets = std::collections::HashSet::new();
        for ip in &ips {
            if let std::net::IpAddr::V4(ipv4) = ip {
                let octets = ipv4.octets();
                subnets.insert(format!("{}.{}.{}", octets[0], octets[1], octets[2]));
            }
        }

        if subnets.len() == 1 && ips.len() > 1 {
            gossan_core::try_push_finding(
                Finding::builder("dns", target.domain().unwrap_or("?"), Severity::Low)
                    .title("Nameserver colocation risk")
                    .detail(format!(
                        "All nameservers for {domain} appear to be in the same /24 subnet. \
                         A local network outage or routing issue could take down all nameservers \
                         simultaneously. Recommend distributing nameservers across different \
                         networks and providers."
                    ))
                    .kind(FindingKind::Misconfiguration)
                    .tag("dns")
                    .tag("ns")
                    .tag("resilience"),
                &mut findings,
            );
        }
    }

    findings
}

/// Detect common DNS providers from nameserver hostnames.
fn detect_ns_provider(nameservers: &[String]) -> Option<&'static str> {
    for ns in nameservers {
        let lower = ns.to_lowercase();
        if lower.contains("awsdns") { return Some("AWS Route 53"); }
        if lower.contains("cloudflare") { return Some("Cloudflare"); }
        if lower.contains("googledomains") || lower.contains("google.com") { return Some("Google DNS"); }
        if lower.contains("azure-dns") { return Some("Azure DNS"); }
        if lower.contains("cscdns") { return Some("CSC Digital Brand Services"); }
        if lower.contains("ultradns") { return Some("Vercara (UltraDNS)"); }
        if lower.contains("dynect") { return Some("Oracle Dyn"); }
        if lower.contains("akam") { return Some("Akamai"); }
        if lower.contains("dnsmadeeasy") { return Some("DigiCert (DNS Made Easy)"); }
        if lower.contains("nsone") { return Some("IBM NS1"); }
        if lower.contains("digitalocean") { return Some("DigitalOcean"); }
        if lower.contains("linode") { return Some("Linode"); }
    }
    None
}

// ── CAA ─────────────────────────────────────────────────────────────────────

/// One row of a CAA RRset (RFC 8659).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaaEntry {
    /// Critical bit (high bit of flags). Unknown property + critical = ignore the cert.
    pub critical: bool,
    /// Property tag: `issue`, `issuewild`, `iodef`, or vendor-extension.
    pub tag: String,
    /// Value: typically a CA domain like `letsencrypt.org` or a `mailto:` URL.
    pub value: String,
}

/// Parse a CAA record textual form: `<flags> <tag> "<value>"`.
///
/// Examples this accepts:
///
/// ```text
/// 0 issue "letsencrypt.org"
/// 128 issuewild ";"
/// 0 iodef "mailto:abuse@example.com"
/// ```
///
/// Returns `None` when the input doesn't match the three-token shape.
/// Quoted values are unquoted; unquoted values are accepted too.
#[must_use]
pub fn parse_caa(record: &str) -> Option<CaaEntry> {
    let s = record.trim();
    let mut it = s.splitn(3, char::is_whitespace);
    let flags_s = it.next()?.trim();
    let tag = it.next()?.trim().to_string();
    let value_raw = it.next()?.trim();
    let flags: u8 = flags_s.parse().ok()?;
    let value = value_raw
        .trim_matches('"')
        .to_string();
    Some(CaaEntry {
        critical: flags & 0x80 != 0,
        tag,
        value,
    })
}

/// Parse a full CAA RRset and bucket entries by tag.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CaaRrset {
    /// All `issue` rows.
    pub issue: Vec<CaaEntry>,
    /// All `issuewild` rows.
    pub issuewild: Vec<CaaEntry>,
    /// All `iodef` rows.
    pub iodef: Vec<CaaEntry>,
    /// Anything else (vendor-extension tags).
    pub other: Vec<CaaEntry>,
}

impl CaaRrset {
    /// Build from an iterator of CAA record strings. Unparseable rows are
    /// dropped silently.
    pub fn from_records<I, S>(records: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut out = Self::default();
        for r in records {
            let Some(e) = parse_caa(r.as_ref()) else {
                continue;
            };
            match e.tag.as_str() {
                "issue" => out.issue.push(e),
                "issuewild" => out.issuewild.push(e),
                "iodef" => out.iodef.push(e),
                _ => out.other.push(e),
            }
        }
        out
    }

    /// CAs explicitly authorized for plain (non-wildcard) issuance.
    /// `";"` value means "no CA may issue".
    #[must_use]
    pub fn authorized_cas(&self) -> Vec<String> {
        self.issue
            .iter()
            .filter(|e| e.value != ";")
            .map(|e| e.value.clone())
            .collect()
    }

    /// True if any `issue ";"` row is present (issuance forbidden).
    #[must_use]
    pub fn issuance_disabled(&self) -> bool {
        self.issue.iter().any(|e| e.value == ";")
    }
}


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
            gossan_core::try_push_finding(Finding::builder("dns", target.domain().unwrap_or("?"), Severity::Low)
                    .title("No CAA records — any CA may issue certificates")
                    .detail(format!(
                        "{domain} has no CAA DNS records. Any Certificate Authority \
                         can issue TLS certificates for this domain. CAA records \
                         (RFC 8659) restrict issuance to specific CAs, preventing \
                         unauthorized certificate creation."
                    ))
                    .kind(FindingKind::Misconfiguration)
                    .tag("dns").tag("caa").tag("certificates"), &mut findings);
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
        gossan_core::try_push_finding(Finding::builder("dns", target.domain().unwrap_or("?"), Severity::Info)
                .title(format!("CAA restricts certificate issuance to {} CA(s)", cas.len()))
                .detail(format!(
                    "{domain} has CAA records restricting TLS certificate issuance: {}",
                    cas.join(", ")
                ))
                .kind(FindingKind::Misconfiguration)
                .tag("dns").tag("caa").tag("good"), &mut findings);
    }

    if !has_issuewild {
        gossan_core::try_push_finding(Finding::builder("dns", target.domain().unwrap_or("?"), Severity::Info)
                .title("CAA missing issuewild restriction")
                .detail(format!(
                    "{domain} has CAA issue records but no issuewild. \
                     Wildcard certificates (*.{domain}) are not explicitly restricted."
                ))
                .kind(FindingKind::Misconfiguration)
                .tag("dns").tag("caa"), &mut findings);
    }

    if !has_iodef {
        gossan_core::try_push_finding(Finding::builder("dns", target.domain().unwrap_or("?"), Severity::Info)
                .title("CAA missing iodef (incident reporting URI)")
                .detail(format!(
                    "{domain} CAA records have no iodef tag. \
                     CAs will not notify you of rejected certificate requests."
                ))
                .kind(FindingKind::Misconfiguration)
                .tag("dns").tag("caa"), &mut findings);
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

    gossan_core::try_push_finding(Finding::builder("dns", target.domain().unwrap_or("?"), Severity::Info)
            .title(format!(
                "Mail topology: {} MX record(s) — {}",
                exchanges.len(),
                provider.unwrap_or("custom infrastructure")
            ))
            .detail(format!(
                "{domain} mail exchange records:\n{}",
                topology.join("\n")
            ))
            .kind(FindingKind::Misconfiguration)
            .evidence(Evidence::DnsRecord {
                record_type: "MX".into(),
                value: topology.join("; ").into(),
            })
            .tag("dns").tag("mx").tag("intel"), &mut findings);

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

    #[test]
    fn parse_caa_issue_letsencrypt() {
        let e = parse_caa(r#"0 issue "letsencrypt.org""#).unwrap();
        assert!(!e.critical);
        assert_eq!(e.tag, "issue");
        assert_eq!(e.value, "letsencrypt.org");
    }

    #[test]
    fn parse_caa_critical_bit() {
        let e = parse_caa(r#"128 issuewild "digicert.com""#).unwrap();
        assert!(e.critical);
        assert_eq!(e.tag, "issuewild");
        assert_eq!(e.value, "digicert.com");
    }

    #[test]
    fn parse_caa_iodef_mailto() {
        let e = parse_caa(r#"0 iodef "mailto:abuse@example.com""#).unwrap();
        assert_eq!(e.tag, "iodef");
        assert_eq!(e.value, "mailto:abuse@example.com");
    }

    #[test]
    fn parse_caa_unquoted_value_ok() {
        let e = parse_caa("0 issue letsencrypt.org").unwrap();
        assert_eq!(e.value, "letsencrypt.org");
    }

    #[test]
    fn parse_caa_rejects_malformed() {
        assert!(parse_caa("").is_none());
        assert!(parse_caa("0 issue").is_none());
        assert!(parse_caa("notaflag issue \"x\"").is_none());
    }

    #[test]
    fn caa_rrset_buckets_by_tag() {
        let records = [
            r#"0 issue "letsencrypt.org""#,
            r#"0 issue "sectigo.com""#,
            r#"0 issuewild ";""#,
            r#"0 iodef "mailto:sec@example.com""#,
            r#"0 contactemail "sec@example.com""#,
        ];
        let rrset = CaaRrset::from_records(records);
        assert_eq!(rrset.issue.len(), 2);
        assert_eq!(rrset.issuewild.len(), 1);
        assert_eq!(rrset.iodef.len(), 1);
        assert_eq!(rrset.other.len(), 1);
    }

    #[test]
    fn caa_authorized_cas_filters_disable_marker() {
        let records = [
            r#"0 issue "letsencrypt.org""#,
            r#"0 issue ";""#,
        ];
        let rrset = CaaRrset::from_records(records);
        let cas = rrset.authorized_cas();
        assert_eq!(cas, vec!["letsencrypt.org".to_string()]);
    }

    #[test]
    fn caa_issuance_disabled_detects_semicolon() {
        let rrset = CaaRrset::from_records([r#"0 issue ";""#]);
        assert!(rrset.issuance_disabled());
        let rrset = CaaRrset::from_records([r#"0 issue "letsencrypt.org""#]);
        assert!(!rrset.issuance_disabled());
    }
}
