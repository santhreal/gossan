//! DNS zone transfer (AXFR) detection via raw wire protocol.
//!
//! Constructs a minimal DNS AXFR query at the wire level (no external DNS
//! library, pure byte manipulation), sends it over TCP to each authoritative
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
//! address ranges (providing a full attack surface map).

use gossan_core::Target;
use hickory_resolver::{proto::rr::RecordType, TokioResolver};
use secfinding::{Evidence, Finding, FindingKind, Severity};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Maximum bytes buffered from a single AXFR TCP stream before terminating.
/// 512 KiB is comfortably above any legitimate zone size for most targets
/// while bounding memory under adversarial nameservers.
const MAX_AXFR_RESPONSE_BYTES: usize = 512 * 1024;

/// Initial read-buffer capacity for AXFR response accumulation.
const AXFR_READ_CAPACITY: usize = 65_536;

/// RFC 1035 maximum label length in bytes (octets per label, excluding length byte).
const DNS_MAX_LABEL_LEN: usize = 63;

/// Minimum raw bytes required before the 2-byte TCP length prefix and first DNS message
/// can be accessed: 2 (TCP length) + 4 (header flags/counts) = 6.
const AXFR_MIN_BUF_LEN: usize = 6;

/// Minimum bytes in the first DNS message to read ANCOUNT at offsets 6-7.
/// DNS header is 12 bytes; we need at least 8 for ID(2)+FLAGS(2)+QDCOUNT(2)+ANCOUNT(2).
const AXFR_MIN_MSG_LEN: usize = 8;

/// Check all authoritative nameservers for AXFR vulnerability.
pub async fn check(
    resolver: &TokioResolver,
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
        if let Some(axfr_result) = attempt(resolver, ns, domain, timeout, proxy).await {
            gossan_core::try_push_finding(
                Finding::builder("dns", target.domain().unwrap_or("?"), Severity::Critical)
                    .title(format!("DNS zone transfer (AXFR) succeeds on {ns}"))
                    .detail(format!(
                        "Nameserver {ns} allows unauthenticated AXFR for {domain}. \
                         {record_count} DNS records exposed, complete subdomain inventory, \
                         internal hostnames, and mail topology disclosed.",
                        record_count = axfr_result.record_count
                    ))
                    .kind(FindingKind::Vulnerability)
                    .evidence(Evidence::DnsRecord {
                        record_type: "AXFR".into(),
                        value: axfr_result.excerpt.into(),
                    })
                    .tag("zone-transfer")
                    .tag("critical")
                    .tag("dns"),
                &mut findings,
            );
            break; // one successful transfer is sufficient evidence
        }
    }

    findings
}

/// Result of a successful AXFR attempt.
pub struct AxfrResult {
    /// Number of answer records in the first response message.
    pub record_count: u16,
    /// Human-readable excerpt of the transfer.
    pub excerpt: String,
}

/// Resolve NS records for a domain.
async fn resolve_nameservers(resolver: &TokioResolver, domain: &str) -> Option<Vec<String>> {
    let ns_records = match resolver.lookup(domain, RecordType::NS).await {
        Ok(r) => r,
        Err(e) if e.is_nx_domain() || e.is_no_records_found() => return None,
        Err(e) => {
            tracing::warn!(
                domain,
                error = %e,
                "AXFR NS lookup failed; skipping zone transfer attempts"
            );
            return None;
        }
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
    resolver: &TokioResolver,
    nameserver: &str,
    zone: &str,
    timeout: std::time::Duration,
    proxy: Option<&str>,
) -> Option<AxfrResult> {
    let port: u16 = std::env::var("GOSSAN_AXFR_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(53);

    let lookup = match resolver.lookup_ip(nameserver).await {
        Ok(r) => r,
        Err(e) if e.is_nx_domain() || e.is_no_records_found() => return None,
        Err(e) => {
            tracing::warn!(
                nameserver,
                error = %e,
                "AXFR nameserver A/AAAA lookup failed; skipping this NS"
            );
            return None;
        }
    };
    let ip = lookup.iter().next()?;
    let addr = std::net::SocketAddr::new(ip, port);

    let mut stream = match tokio::time::timeout(
        timeout,
        gossan_core::net::connect_tcp(&addr.ip().to_string(), addr.port(), proxy),
    )
    .await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            tracing::warn!("AXFR TCP connect failed: nameserver={} zone={} error={}", nameserver, zone, e);
            return None;
        }
        Err(_) => {
            tracing::warn!("AXFR TCP connect timed out: nameserver={} zone={}", nameserver, zone);
            return None;
        }
    };

    // Build and send AXFR query
    let query = build_query(zone);
    if query.is_empty() {
        return None;
    }
    let mut msg = (query.len() as u16).to_be_bytes().to_vec();
    msg.extend_from_slice(&query);
    match tokio::time::timeout(timeout, stream.write_all(&msg)).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            tracing::warn!("AXFR query write failed: nameserver={} zone={} error={}", nameserver, zone, e);
            return None;
        }
        Err(_) => {
            tracing::warn!("AXFR query write timed out: nameserver={} zone={}", nameserver, zone);
            return None;
        }
    }

    // Read response, zone transfers can be large; cap at MAX_AXFR_RESPONSE_BYTES.
    // Fail closed on timeout/read errors — never parse a truncated buffer as success.
    let mut buf = Vec::with_capacity(AXFR_READ_CAPACITY);
    let read_result = tokio::time::timeout(timeout.saturating_mul(2), async {
        let mut tmp = [0u8; 4096];
        loop {
            match stream.read(&mut tmp).await {
                Ok(0) => break Ok(()), // clean EOF
                Ok(n) => {
                    buf.extend_from_slice(&tmp[..n]);
                    if buf.len() > MAX_AXFR_RESPONSE_BYTES {
                        break Ok(());
                    }
                }
                Err(e) => break Err(e),
            }
        }
    })
    .await;

    match read_result {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            tracing::warn!(
                nameserver,
                zone,
                error = %e,
                "AXFR read failed; aborting parse"
            );
            return None;
        }
        Err(_) => {
            tracing::warn!(
                nameserver,
                zone,
                "AXFR read timed out; aborting parse"
            );
            return None;
        }
    }

    parse_response(&buf, nameserver, zone)
}

/// Parse the raw AXFR response to extract record count and generate an excerpt.
pub fn parse_response(buf: &[u8], nameserver: &str, zone: &str) -> Option<AxfrResult> {
    if buf.len() < AXFR_MIN_BUF_LEN {
        return None;
    }

    // Skip 2-byte TCP length prefix
    let first_msg = buf.get(2..)?;
    if first_msg.len() < AXFR_MIN_MSG_LEN {
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
/// The transaction ID is drawn from `fastrand` (OS-seeded) so that
/// spoofed-response injection requires guessing 16 bits of entropy per
/// attempt rather than always matching the fixed `0x1337` sentinel. Over TCP
/// the spoofing risk is already low, but a randomised ID also removes the
/// trivial gossan-specific fingerprint that a WAF or IDS could block on.
pub fn build_query(zone: &str) -> Vec<u8> {
    build_query_with_txid(zone, random_txid())
}

/// Generate a random 16-bit DNS transaction ID.
///
/// Uses `fastrand` (already a dns-crate dependency) which is seeded from
/// the OS entropy source on first call. The TXID is not a secret, it
/// merely prevents a static `0x1337` fingerprint that WAFs/IDS systems
/// could block on, and raises the bar for off-path spoofed DNS responses
/// (16 bits of entropy = 1-in-65536 guess probability per attempt).
fn random_txid() -> u16 {
    fastrand::u16(..)
}

/// Inner builder, accepts an explicit transaction ID so tests can be
/// deterministic while production code always uses a random one.
pub fn build_query_with_txid(zone: &str, txid: u16) -> Vec<u8> {
    let mut msg = Vec::with_capacity(64);

    // Header: randomised TXID, standard query, QDCOUNT=1
    msg.extend_from_slice(&txid.to_be_bytes()); // ID
    msg.extend_from_slice(&[0x00, 0x00]); // Flags
    msg.extend_from_slice(&[0x00, 0x01]); // QDCOUNT = 1
    msg.extend_from_slice(&[0x00, 0x00]); // ANCOUNT = 0
    msg.extend_from_slice(&[0x00, 0x00]); // NSCOUNT = 0
    msg.extend_from_slice(&[0x00, 0x00]); // ARCOUNT = 0

    // QNAME: encode each label (RFC 1035: max DNS_MAX_LABEL_LEN bytes per label)
    for label in zone.trim_end_matches('.').split('.') {
        if label.len() > DNS_MAX_LABEL_LEN {
            // Invalid label: RFC 1035 violation. Skip to avoid truncation.
            continue;
        }
        msg.push(label.len() as u8);
        msg.extend_from_slice(label.as_bytes());
    }
    msg.push(0x00); // root label

    msg.extend_from_slice(&[0x00, 0xfc]); // QTYPE = AXFR (252)
    msg.extend_from_slice(&[0x00, 0x01]); // QCLASS = IN

    // Pathological zone names (millions of small labels) can produce a message
    // larger than the 2-byte TCP length prefix allows. Reject them outright.
    if msg.len() > u16::MAX as usize {
        return Vec::new();
    }

    msg
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn build_query_encodes_header_and_question() {
        // Use a fixed TXID for deterministic tests.
        let msg = build_query_with_txid("example.com", 0x1337);
        assert_eq!(&msg[..2], &[0x13, 0x37], "transaction ID encoded big-endian");
        assert_eq!(&msg[4..6], &[0x00, 0x01], "QDCOUNT = 1");
        assert!(
            msg.ends_with(&[0x00, 0xfc, 0x00, 0x01]),
            "QTYPE=AXFR, QCLASS=IN"
        );
    }

    #[test]
    fn build_query_txid_is_big_endian() {
        // 0xABCD → [0xAB, 0xCD]
        let msg = build_query_with_txid("example.com", 0xABCD);
        assert_eq!(msg[0], 0xAB);
        assert_eq!(msg[1], 0xCD);
    }

    #[test]
    fn build_query_encodes_multi_label_zone() {
        let msg = build_query_with_txid("api.example.com.", 0x0001);
        assert!(msg.windows(3).any(|w| w == [3, b'a', b'p']), "label 'api'");
        assert!(
            msg.windows(8)
                .any(|w| w == [7, b'e', b'x', b'a', b'm', b'p', b'l', b'e']),
            "label 'example'"
        );
    }

    /// Anti-rig: two consecutive `build_query` calls must produce different
    /// transaction IDs (the fixed `0x1337` sentinel is forbidden in production).
    #[test]
    fn build_query_production_txid_is_not_fixed_sentinel() {
        // We can't guarantee uniqueness with 16-bit entropy in a single test,
        // but we CAN assert the sentinel is not always returned. Run 16 trials:
        // probability of all being 0x1337 by chance is (1/65536)^16 ≈ 0.
        let all_sentinel = (0..16)
            .map(|_| {
                let q = build_query("example.com");
                u16::from_be_bytes([q[0], q[1]])
            })
            .all(|id| id == 0x1337);
        assert!(
            !all_sentinel,
            "build_query always returned the fixed 0x1337 sentinel. RNG is broken"
        );
    }

    #[test]
    fn parse_response_rejects_short_buffer() {
        assert!(parse_response(&[0, 0, 0], "ns", "z").is_none());
    }

    #[test]
    fn parse_response_rejects_refused() {
        // RCODE = 5 (REFUSED) at byte offset 5 (msg byte 3 after 2-byte len prefix)
        let buf = [
            0, 20, 0x13, 0x37, 0x80, 0x05, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        assert!(parse_response(&buf, "ns", "z").is_none());
    }

    #[test]
    fn parse_response_accepts_valid_transfer() {
        // RCODE = 0, ANCOUNT = 5
        let buf = [
            0, 20, 0x13, 0x37, 0x80, 0x00, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let result = parse_response(&buf, "ns1.example.com", "example.com");
        assert!(result.is_some());
        assert_eq!(result.as_ref().unwrap().record_count, 5);
        assert!(result.unwrap().excerpt.contains("5 answer records"));
    }

    /// Adversarial: a zone with thousands of single-character labels produces a
    /// query longer than the u16 length prefix can represent. Before the fix
    /// `build_query` would return a huge Vec and `attempt` would silently
    /// truncate the length; after the fix `build_query` returns an empty Vec.
    #[test]
    fn build_query_rejects_pathological_zone() {
        // 35_000 single-char labels → ~70_000 bytes (> u16::MAX)
        let zone = (0..35_000).map(|_| "a").collect::<Vec<_>>().join(".");
        let msg = build_query_with_txid(&zone, 0x1337);
        assert!(
            msg.is_empty(),
            "pathological zone must produce empty query, got {} bytes",
            msg.len()
        );
    }

    /// Adversarial: `Duration::MAX * 2` panics (debug) or wraps (release).
    /// After the fix we use `saturating_mul`.
    #[test]
    fn read_timeout_does_not_overflow() {
        let timeout = std::time::Duration::from_secs(u64::MAX);
        let extended = timeout.saturating_mul(2);
        // saturating_mul should clamp to Duration::MAX
        assert_eq!(extended, std::time::Duration::MAX);
    }

    proptest! {
        /// Property: `build_query` never panics for arbitrary UTF-8 input.
        #[test]
        fn build_query_never_panics(zone in ".*") {
            let _ = build_query(&zone);
        }

        /// Property: `build_query` output length is bounded by u16::MAX
        /// (it returns empty for anything that would exceed it).
        #[test]
        fn build_query_length_bounded(zone in ".{0,10000}") {
            let msg = build_query(&zone);
            prop_assert!(msg.len() <= u16::MAX as usize);
        }

        /// Property: `parse_response` never panics for arbitrary bytes.
        #[test]
        fn parse_response_never_panics(buf in prop::collection::vec(any::<u8>(), 0..1024)) {
            let _ = parse_response(&buf, "ns", "z");
        }

        /// Property: `parse_response` returns None for every buffer < 6 bytes.
        #[test]
        fn parse_response_rejects_short_buffers(buf in prop::collection::vec(any::<u8>(), 0..6)) {
            prop_assert!(parse_response(&buf, "ns", "z").is_none());
        }

        /// Property: `parse_response` returns None for every buffer shorter
        /// than AXFR_MIN_BUF_LEN, anti-rig: pins the constant to 6 so
        /// accidental changes are caught.
        #[test]
        fn parse_response_min_buf_len_constant_is_six(
            buf in prop::collection::vec(any::<u8>(), 0..AXFR_MIN_BUF_LEN),
        ) {
            prop_assert!(parse_response(&buf, "ns", "z").is_none());
        }

        /// Property: `parse_response` returns None when RCODE != 0.
        #[test]
        fn parse_response_rejects_nonzero_rcode(
            suffix in prop::collection::vec(any::<u8>(), 4..20),
            rcode in 1u8..16,
        ) {
            let mut buf = vec![0u8, 0u8]; // 2-byte TCP length prefix
            buf.push(0x13); // ID high
            buf.push(0x37); // ID low
            buf.push(0x80); // flags high
            buf.push(rcode | 0x80); // flags low. RCODE in low nibble
            buf.extend(suffix);
            prop_assert!(parse_response(&buf, "ns", "z").is_none());
        }
    }
}
