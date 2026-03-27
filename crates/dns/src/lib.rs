//! DNS security posture scanner.
//! Checks SPF, DMARC, DKIM (13 selectors), CAA, NS resilience,
//! subdomain takeover (19 CNAME patterns), MX disclosure, zone transfer (AXFR).

use async_trait::async_trait;
use futures::StreamExt;
use gossan_core::{Config, ScanInput, ScanOutput, Scanner, Target};
use hickory_resolver::{
    config::{NameServerConfigGroup, ResolverConfig, ResolverOpts},
    proto::rr::RecordType,
    TokioAsyncResolver,
};
use secfinding::{Evidence, Finding, FindingBuilder, Severity};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const DKIM_SELECTORS: &[&str] = &[
    "default",
    "google",
    "mail",
    "k1",
    "k2",
    "selector1",
    "selector2",
    "smtp",
    "dkim",
    "mandrill",
    "mailchimp",
    "sendgrid",
    "postmark",
];

const TAKEOVERS_RAW: &str = include_str!("takeovers.txt");
pub struct DnsScanner;

fn finding_builder(
    target: &Target,
    severity: Severity,
    title: impl Into<String>,
    detail: impl Into<String>,
) -> FindingBuilder {
    Finding::builder("dns", target.domain().unwrap_or("?"), severity)
        .title(title)
        .detail(detail)
}

#[async_trait]
impl Scanner for DnsScanner {
    fn name(&self) -> &'static str {
        "dns"
    }
    fn tags(&self) -> &[&'static str] {
        &["active", "dns", "email"]
    }
    fn accepts(&self, target: &Target) -> bool {
        matches!(target, Target::Domain(_))
    }

    async fn run(&self, input: ScanInput, config: &Config) -> anyhow::Result<ScanOutput> {
        let mut out = ScanOutput::empty();
        let resolver = build_resolver(config)?;

        let owned: Vec<Target> = input
            .targets
            .into_iter()
            .filter(|t| self.accepts(t))
            .collect();

        let timeout = config.timeout();
        let findings: Vec<Vec<Finding>> = futures::stream::iter(owned)
            .map(|target| {
                let resolver = resolver.clone();
                let proxy_opt = config.proxy.clone();
                async move {
                    let domain = target.domain().unwrap_or("").to_string();
                    audit_domain(&resolver, &domain, &target, timeout, proxy_opt.as_deref()).await
                }
            })
            .buffer_unordered(config.concurrency)
            .collect()
            .await;

        for batch in findings {
            out.findings.extend(batch);
        }
        Ok(out)
    }
}

async fn audit_domain(
    resolver: &TokioAsyncResolver,
    domain: &str,
    target: &Target,
    timeout: std::time::Duration,
    proxy: Option<&str>,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Zone transfer — attempt AXFR against every NS for the domain
    if let Ok(ns_records) = resolver.lookup(domain, RecordType::NS).await {
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
            if let Some(axfr) = axfr_attempt(ns, domain, timeout, proxy).await {
                let record_count = axfr.lines().count();
                findings.push(
                    finding_builder(
                        target,
                        Severity::Critical,
                        format!("DNS zone transfer (AXFR) succeeds on {}", ns),
                        format!(
                            "Nameserver {} allows unauthenticated AXFR for {}. \
                                 {} DNS records exposed — complete subdomain inventory disclosed.",
                            ns, domain, record_count
                        ),
                    )
                    .evidence(Evidence::DnsRecord {
                        record_type: "AXFR".to_string(),
                        value: axfr.lines().take(20).collect::<Vec<_>>().join("\n"),
                    })
                    .tag("zone-transfer")
                    .tag("critical")
                    .tag("dns")
                    .build()
                    .expect("finding builder: required fields are set"),
                );
                break; // one successful transfer is enough
            }
        }
    }

    // SPF
    if let Ok(records) = lookup_txt(resolver, domain).await {
        let spf_rec = records.iter().find(|r| r.starts_with("v=spf1"));
        if spf_rec.is_none() {
            findings.push(
                finding_builder(
                    target,
                    Severity::Medium,
                    "No SPF record",
                    format!("{} has no SPF record — email spoofing is possible.", domain),
                )
                .tag("email-security")
                .tag("spf")
                .build()
                .expect("finding builder: required fields are set"),
            );
        } else if let Some(rec) = spf_rec {
            if rec.contains("~all") {
                findings.push(
                    finding_builder(
                        target,
                        Severity::Low,
                        "SPF softfail (~all) — not enforced",
                        format!(
                            "{} uses ~all — emails failing SPF are still delivered.",
                            domain
                        ),
                    )
                    .tag("email-security")
                    .tag("spf")
                    .build()
                    .expect("finding builder: required fields are set"),
                );
            } else if rec.contains("+all") {
                findings.push(
                    finding_builder(
                        target,
                        Severity::High,
                        "SPF allows all senders (+all)",
                        format!(
                            "{} SPF has +all — any server can send as this domain.",
                            domain
                        ),
                    )
                    .tag("email-security")
                    .tag("spf")
                    .build()
                    .expect("finding builder: required fields are set"),
                );
            }
        }
    }

    // DMARC
    let dmarc_domain = format!("_dmarc.{}", domain);
    match lookup_txt(resolver, &dmarc_domain).await {
        Ok(records) => {
            let dmarc_rec = records.iter().find(|r| r.starts_with("v=DMARC1"));
            if dmarc_rec.is_none() {
                findings.push(
                    finding_builder(
                        target,
                        Severity::Medium,
                        "No DMARC record",
                        format!(
                            "{} has no DMARC record — phishing via email spoofing is unmitigated.",
                            domain
                        ),
                    )
                    .tag("email-security")
                    .tag("dmarc")
                    .build()
                    .expect("finding builder: required fields are set"),
                );
            } else if let Some(rec) = dmarc_rec {
                if rec.contains("p=none") {
                    findings.push(
                        finding_builder(
                            target,
                            Severity::Low,
                            "DMARC policy is p=none (monitor only)",
                            format!(
                                "{} DMARC does not reject or quarantine — unenforced.",
                                domain
                            ),
                        )
                        .tag("email-security")
                        .tag("dmarc")
                        .build()
                        .expect("finding builder: required fields are set"),
                    );
                } else if rec.contains("p=quarantine") {
                    findings.push(
                        finding_builder(
                            target,
                            Severity::Info,
                            "DMARC policy is p=quarantine (not fully locked down)",
                            format!(
                                "{} DMARC quarantines but does not outright reject spoofed emails.",
                                domain
                            ),
                        )
                        .tag("email-security")
                        .tag("dmarc")
                        .build()
                        .expect("finding builder: required fields are set"),
                    );
                }

                if !rec.contains("sp=reject") && !rec.contains("p=none") {
                    findings.push(
                        finding_builder(target, Severity::Low,
                            "DMARC missing sp=reject (subdomain spoofing risk)",
                            format!("{} DMARC lacks sp=reject, leaving unconfigured subdomains vulnerable to spoofing.", domain))
                        .tag("email-security").tag("dmarc")
                        .build().expect("finding builder: required fields are set"),
                    );
                }
                // rua disclosure
                if let Some(part) = rec.split(';').find(|p| p.trim().starts_with("rua=")) {
                    let addr = part.trim().trim_start_matches("rua=");
                    findings.push(
                        finding_builder(
                            target,
                            Severity::Info,
                            "DMARC aggregate report recipient",
                            format!("{} aggregate DMARC reports go to: {}", domain, addr),
                        )
                        .evidence(Evidence::DnsRecord {
                            record_type: "TXT".into(),
                            value: rec.clone(),
                        })
                        .tag("email-security")
                        .tag("disclosure")
                        .build()
                        .expect("finding builder: required fields are set"),
                    );
                }
            }
        }
        Err(_) => {
            findings.push(
                finding_builder(
                    target,
                    Severity::Medium,
                    "No DMARC record",
                    format!("{} has no DMARC record.", domain),
                )
                .tag("email-security")
                .tag("dmarc")
                .build()
                .expect("finding builder: required fields are set"),
            );
        }
    }

    // DKIM — probe common selectors
    let mut dkim_found = false;
    for selector in DKIM_SELECTORS {
        let dkim_name = format!("{}._domainkey.{}", selector, domain);
        if let Ok(records) = lookup_txt(resolver, &dkim_name).await {
            if records
                .iter()
                .any(|r| r.contains("v=DKIM1") || r.contains("p="))
            {
                dkim_found = true;
                findings.push(
                    finding_builder(
                        target,
                        Severity::Info,
                        format!("DKIM selector active: {}", selector),
                        format!(
                            "{} DKIM selector '{}' resolves — email signing configured.",
                            domain, selector
                        ),
                    )
                    .evidence(Evidence::DnsRecord {
                        record_type: "TXT".into(),
                        value: records.first().cloned().unwrap_or_default(),
                    })
                    .tag("email-security")
                    .tag("dkim")
                    .build()
                    .expect("finding builder: required fields are set"),
                );
                break;
            }
        }
    }
    if !dkim_found {
        findings.push(
            finding_builder(
                target,
                Severity::Low,
                "No DKIM record found",
                format!(
                    "{} — none of {} common DKIM selectors resolved.",
                    domain,
                    DKIM_SELECTORS.len()
                ),
            )
            .tag("email-security")
            .tag("dkim")
            .build()
            .expect("finding builder: required fields are set"),
        );
    }

    // CAA
    match resolver.lookup(domain, RecordType::CAA).await {
        Ok(lookup) if lookup.records().is_empty() => {
            findings.push(
                finding_builder(
                    target,
                    Severity::Low,
                    "No CAA record",
                    format!("{} has no CAA record — any CA can issue certs.", domain),
                )
                .tag("certificate")
                .tag("caa")
                .build()
                .expect("finding builder: required fields are set"),
            );
        }
        Err(_) => {
            findings.push(
                finding_builder(
                    target,
                    Severity::Low,
                    "No CAA record",
                    format!("{} has no CAA record.", domain),
                )
                .tag("certificate")
                .tag("caa")
                .build()
                .expect("finding builder: required fields are set"),
            );
        }
        _ => {}
    }

    // NS resilience
    if let Ok(ns_lookup) = resolver.lookup(domain, RecordType::NS).await {
        let ns_count = ns_lookup.records().len();
        if ns_count == 1 {
            findings.push(
                finding_builder(
                    target,
                    Severity::Low,
                    "Single name server",
                    format!(
                        "{} has only one NS record — single point of failure.",
                        domain
                    ),
                )
                .tag("dns")
                .tag("resilience")
                .build()
                .expect("finding builder: required fields are set"),
            );
        }
    }

    // MX disclosure
    if let Ok(mx_lookup) = resolver.lookup(domain, RecordType::MX).await {
        let mx_vals: Vec<String> = mx_lookup
            .records()
            .iter()
            .filter_map(|r| r.data().map(|d| d.to_string()))
            .collect();
        if !mx_vals.is_empty() {
            findings.push(
                finding_builder(
                    target,
                    Severity::Info,
                    "MX records enumerated",
                    format!("{} mail: {}", domain, mx_vals.join(", ")),
                )
                .evidence(Evidence::DnsRecord {
                    record_type: "MX".into(),
                    value: mx_vals.join("; "),
                })
                .tag("dns")
                .tag("email")
                .build()
                .expect("finding builder: required fields are set"),
            );
        }
    }

    // Subdomain takeover: CNAME to unclaimed service
    if let Ok(cname_lookup) = resolver.lookup(domain, RecordType::CNAME).await {
        for record in cname_lookup.records() {
            let cname_val = record.data().map(|d| d.to_string()).unwrap_or_default();
            for (pattern, service) in takeover_signals() {
                if cname_val.contains(pattern) {
                    let resolves = resolver
                        .lookup_ip(cname_val.trim_end_matches('.'))
                        .await
                        .is_ok();
                    if !resolves {
                        findings.push(
                            finding_builder(target, Severity::High,
                                format!("Potential subdomain takeover ({}) — {}", service, domain),
                                format!("{} CNAME -> {} (does not resolve). {} account may be unclaimed.", domain, cname_val, service))
                            .evidence(Evidence::DnsRecord {
                                record_type: "CNAME".into(),
                                value: cname_val.clone(),
                            })
                            .tag("takeover").tag("dns")
                            .build().expect("finding builder: required fields are set"),
                        );
                    }
                }
            }
        }
    }

    findings
}

async fn lookup_txt(resolver: &TokioAsyncResolver, name: &str) -> anyhow::Result<Vec<String>> {
    let lookup = resolver.txt_lookup(name).await?;
    let records: Vec<String> = lookup
        .iter()
        .flat_map(|txt| txt.iter().map(|d| String::from_utf8_lossy(d).to_string()))
        .collect();
    Ok(records)
}

/// Attempt a DNS zone transfer (AXFR) over TCP against a specific nameserver.
/// Returns the raw zone text if the server allows it, None otherwise.
/// Protocol: DNS-over-TCP, message length prefix (2 bytes BE), AXFR query type = 252.
async fn axfr_attempt(
    nameserver: &str,
    zone: &str,
    timeout: std::time::Duration,
    proxy: Option<&str>,
) -> Option<String> {
    // Resolve nameserver hostname → IP (async — must not block the Tokio thread)
    let addr = tokio::net::lookup_host(format!("{}:53", nameserver))
        .await
        .ok()?
        .next()?;

    let mut stream = tokio::time::timeout(
        timeout,
        gossan_core::net::connect_tcp(&addr.ip().to_string(), addr.port(), proxy),
    )
    .await
    .ok()?
    .ok()?;

    // Build AXFR DNS query
    let query = build_axfr_query(zone);

    // DNS-over-TCP: 2-byte length prefix + message
    let mut msg = ((query.len() as u16).to_be_bytes()).to_vec();
    msg.extend_from_slice(&query);
    tokio::time::timeout(timeout, stream.write_all(&msg))
        .await
        .ok()?
        .ok()?;

    // Read response — zone transfers can be large; read up to 512 KB
    let mut buf = Vec::with_capacity(65536);
    let _ = tokio::time::timeout(timeout * 2, async {
        let mut tmp = [0u8; 4096];
        loop {
            match stream.read(&mut tmp).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    buf.extend_from_slice(&tmp[..n]);
                    if buf.len() > 512 * 1024 {
                        break;
                    }
                }
            }
        }
    })
    .await
    .ok();

    if buf.len() < 6 {
        return None;
    }

    // Parse the first response message: skip 2-byte length, check RCODE
    let first_msg = buf.get(2..)?;
    if first_msg.len() < 4 {
        return None;
    }

    let rcode = first_msg[3] & 0x0f;
    if rcode != 0 {
        return None;
    } // REFUSED / SERVFAIL / etc.

    // ANCOUNT: bytes 6-7 of the DNS message (after 2-byte length prefix)
    let ancount = u16::from_be_bytes([first_msg[6], first_msg[7]]);
    if ancount == 0 {
        return None;
    }

    // We got records — convert what we can to text
    let excerpt = format!(
        "; AXFR response from {} for zone {}\n; {} answer records in first message\n; {} bytes received\n[raw zone data — {} bytes]",
        nameserver, zone, ancount, buf.len(), buf.len()
    );

    tracing::warn!(
        ns = nameserver,
        zone = zone,
        bytes = buf.len(),
        "AXFR zone transfer succeeded"
    );
    Some(excerpt)
}

/// Build a minimal DNS AXFR query for the given zone name.
/// Returns the raw wire-format DNS message (without the 2-byte TCP length prefix).
fn build_axfr_query(zone: &str) -> Vec<u8> {
    let mut msg = Vec::new();

    // Header: ID=0x1337, QR=0, OPCODE=0, AA=0, TC=0, RD=0, RA=0, Z=0, RCODE=0
    msg.extend_from_slice(&[0x13, 0x37]); // ID
    msg.extend_from_slice(&[0x00, 0x00]); // Flags: standard query
    msg.extend_from_slice(&[0x00, 0x01]); // QDCOUNT = 1
    msg.extend_from_slice(&[0x00, 0x00]); // ANCOUNT = 0
    msg.extend_from_slice(&[0x00, 0x00]); // NSCOUNT = 0
    msg.extend_from_slice(&[0x00, 0x00]); // ARCOUNT = 0

    // QNAME: encode each label
    for label in zone.trim_end_matches('.').split('.') {
        msg.push(label.len() as u8);
        msg.extend_from_slice(label.as_bytes());
    }
    msg.push(0x00); // root label

    msg.extend_from_slice(&[0x00, 0xfc]); // QTYPE = AXFR (252)
    msg.extend_from_slice(&[0x00, 0x01]); // QCLASS = IN

    msg
}

fn takeover_signals() -> Vec<(&'static str, &'static str)> {
    TAKEOVERS_RAW
        .lines()
        .filter(|l| !l.is_empty())
        .filter_map(|l| l.split_once(':'))
        .collect()
}

fn build_resolver(config: &Config) -> anyhow::Result<TokioAsyncResolver> {
    let servers = if config.resolvers.is_empty() {
        NameServerConfigGroup::cloudflare()
    } else {
        NameServerConfigGroup::from_ips_clear(&config.resolvers, 53, true)
    };
    let rc = ResolverConfig::from_parts(None, vec![], servers);
    let mut opts = ResolverOpts::default();
    opts.timeout = config.timeout();
    opts.attempts = 2;
    Ok(TokioAsyncResolver::tokio(rc, opts))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_axfr_query_encodes_header_and_question() {
        let msg = build_axfr_query("example.com");
        assert_eq!(&msg[..2], &[0x13, 0x37]);
        assert_eq!(&msg[4..6], &[0x00, 0x01]);
        assert!(msg.ends_with(&[0x00, 0xfc, 0x00, 0x01]));
    }

    #[test]
    fn build_axfr_query_encodes_multi_label_zone() {
        let msg = build_axfr_query("api.example.com.");
        assert!(msg.windows(3).any(|w| w == [3, b'a', b'p']));
        assert!(msg
            .windows(8)
            .any(|w| w == [7, b'e', b'x', b'a', b'm', b'p', b'l', b'e']));
    }

    #[test]
    fn takeover_signals_parse_service_mappings() {
        let signals = takeover_signals();
        assert!(!signals.is_empty());
        assert!(signals
            .iter()
            .all(|(pattern, service)| !pattern.is_empty() && !service.is_empty()));
    }

    #[test]
    fn dkim_selector_list_contains_common_providers() {
        for selector in ["default", "google", "mailchimp", "sendgrid", "postmark"] {
            assert!(DKIM_SELECTORS.contains(&selector));
        }
    }

    #[test]
    fn build_resolver_accepts_custom_resolvers() {
        let config = Config {
            resolvers: vec!["1.1.1.1".parse().unwrap()],
            ..Config::default()
        };
        assert!(build_resolver(&config).is_ok());
    }
}
