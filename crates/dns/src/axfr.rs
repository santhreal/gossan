//! DNS zone transfer (AXFR) detection via raw wire protocol.
//!
//! Constructs a minimal DNS AXFR query at the wire level (no external DNS
//! library — pure byte manipulation), sends it over TCP to each authoritative
//! nameserver, and parses the response to determine if the zone is exposed.
//!
//! # Wire protocol
//!
//! DNS-over-TCP uses a 2-byte big-endian length prefix before each message.
//! The AXFR query type is 252 (0xFC). A successful transfer returns RCODE 0
//! with ANCOUNT > 0 in the response header.
//!
//! # Security impact
//!
//! A successful zone transfer discloses the complete subdomain inventory,
//! internal hostname patterns, mail server topology, and often internal IP
//! address ranges — providing a full attack surface map.

use gossan_core::Target;
use hickory_resolver::{proto::rr::RecordType, TokioAsyncResolver};
use secfinding::{Evidence, Finding, Severity};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Check all authoritative nameservers for AXFR vulnerability.
pub async fn check(
    resolver: &TokioAsyncResolver,
    domain: &str,
    target: &Target,
    timeout: std::time::Duration,
    proxy: Option<&str>,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    let nameservers = match resolve_nameservers(resolver, domain).await {
        Some(ns) => ns,
        None => return findings,
    };

    for ns in &nameservers {
        if let Some(axfr_result) = attempt(ns, domain, timeout, proxy).await {
            findings.push(
                Finding::builder("dns", target.domain().unwrap_or("?"), Severity::Critical)
                    .title(format!("DNS zone transfer (AXFR) succeeds on {ns}"))
                    .detail(format!(
                        "Nameserver {ns} allows unauthenticated AXFR for {domain}. \
                         {record_count} DNS records exposed — complete subdomain inventory, \
                         internal hostnames, and mail topology disclosed.",
                        record_count = axfr_result.record_count
                    ))
                    .evidence(Evidence::DnsRecord {
                        record_type: "AXFR".into(),
                        value: axfr_result.excerpt,
                    })
                    .tag("zone-transfer")
                    .tag("critical")
                    .tag("dns")
                    .build()
                    .expect("finding builder: required fields are set"),
            );
            break; // one successful transfer is sufficient evidence
        }
    }

    findings
}

/// Result of a successful AXFR attempt.
struct AxfrResult {
    /// Number of answer records in the first response message.
    record_count: u16,
    /// Human-readable excerpt of the transfer.
    excerpt: String,
}

/// Resolve NS records for a domain.
async fn resolve_nameservers(
    resolver: &TokioAsyncResolver,
    domain: &str,
) -> Option<Vec<String>> {
    let ns_records = resolver.lookup(domain, RecordType::NS).await.ok()?;
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
    if nameservers.is_empty() {
        None
    } else {
        Some(nameservers)
    }
}

/// Attempt a zone transfer against a single nameserver.
///
/// Returns `Some(AxfrResult)` if the server responds with RCODE 0 and
/// at least one answer record, `None` otherwise.
async fn attempt(
    nameserver: &str,
    zone: &str,
    timeout: std::time::Duration,
    proxy: Option<&str>,
) -> Option<AxfrResult> {
    let addr = tokio::net::lookup_host(format!("{nameserver}:53"))
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

    // Build and send AXFR query
    let query = build_query(zone);
    let mut msg = (query.len() as u16).to_be_bytes().to_vec();
    msg.extend_from_slice(&query);
    tokio::time::timeout(timeout, stream.write_all(&msg))
        .await
        .ok()?
        .ok()?;

    // Read response — zone transfers can be large; cap at 512 KB
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

    parse_response(&buf, nameserver, zone)
}

/// Parse the raw AXFR response to extract record count and generate an excerpt.
fn parse_response(buf: &[u8], nameserver: &str, zone: &str) -> Option<AxfrResult> {
    if buf.len() < 6 {
        return None;
    }

    // Skip 2-byte TCP length prefix
    let first_msg = buf.get(2..)?;
    if first_msg.len() < 8 {
        return None;
    }

    // RCODE is in the lower 4 bits of byte 3
    let rcode = first_msg[3] & 0x0f;
    if rcode != 0 {
        return None; // REFUSED, SERVFAIL, etc.
    }

    // ANCOUNT: bytes 6-7 of DNS message
    let ancount = u16::from_be_bytes([first_msg[6], first_msg[7]]);
    if ancount == 0 {
        return None;
    }

    tracing::warn!(
        ns = nameserver,
        zone = zone,
        bytes = buf.len(),
        records = ancount,
        "AXFR zone transfer succeeded"
    );

    Some(AxfrResult {
        record_count: ancount,
        excerpt: format!(
            "; AXFR response from {nameserver} for zone {zone}\n\
             ; {ancount} answer records in first message\n\
             ; {bytes} bytes received",
            bytes = buf.len()
        ),
    })
}

/// Build a minimal DNS AXFR query in wire format.
///
/// Returns the raw DNS message (without the 2-byte TCP length prefix).
/// Uses a fixed transaction ID of 0x1337 and standard query flags.
fn build_query(zone: &str) -> Vec<u8> {
    let mut msg = Vec::with_capacity(64);

    // Header: ID=0x1337, standard query, QDCOUNT=1
    msg.extend_from_slice(&[0x13, 0x37]); // ID
    msg.extend_from_slice(&[0x00, 0x00]); // Flags
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_query_encodes_header_and_question() {
        let msg = build_query("example.com");
        assert_eq!(&msg[..2], &[0x13, 0x37], "transaction ID");
        assert_eq!(&msg[4..6], &[0x00, 0x01], "QDCOUNT = 1");
        assert!(msg.ends_with(&[0x00, 0xfc, 0x00, 0x01]), "QTYPE=AXFR, QCLASS=IN");
    }

    #[test]
    fn build_query_encodes_multi_label_zone() {
        let msg = build_query("api.example.com.");
        assert!(msg.windows(3).any(|w| w == [3, b'a', b'p']), "label 'api'");
        assert!(
            msg.windows(8).any(|w| w == [7, b'e', b'x', b'a', b'm', b'p', b'l', b'e']),
            "label 'example'"
        );
    }

    #[test]
    fn parse_response_rejects_short_buffer() {
        assert!(parse_response(&[0, 0, 0], "ns", "z").is_none());
    }

    #[test]
    fn parse_response_rejects_refused() {
        // RCODE = 5 (REFUSED) at byte offset 5 (msg byte 3 after 2-byte len prefix)
        let buf = [0, 20, 0x13, 0x37, 0x80, 0x05, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert!(parse_response(&buf, "ns", "z").is_none());
    }

    #[test]
    fn parse_response_accepts_valid_transfer() {
        // RCODE = 0, ANCOUNT = 5
        let buf = [0, 20, 0x13, 0x37, 0x80, 0x00, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let result = parse_response(&buf, "ns1.example.com", "example.com");
        assert!(result.is_some());
        assert_eq!(result.as_ref().unwrap().record_count, 5);
        assert!(result.unwrap().excerpt.contains("5 answer records"));
    }
}
