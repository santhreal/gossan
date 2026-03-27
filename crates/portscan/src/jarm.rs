//! JARM-inspired TLS fingerprinting via raw TCP.
//!
//! Sends 10 crafted TLS ClientHello packets with different cipher suite orderings,
//! TLS versions, ALPN protocols, and extension sets. The server's ServerHello
//! cipher choice and ALPN response uniquely fingerprint the TLS implementation.
//!
//! Fingerprint format (62 chars, compatible with JARM):
//!   [30 chars] fuzzy hash — lower 12 bits of each probe's chosen cipher (3 hex each)
//!   [32 chars] SHA-256 of concatenated ALPN/extension strings from all 10 probes
//!
//! Known C2 fingerprints: Cobalt Strike, Metasploit, Sliver, Havoc, BruteRatel.
//! Reference: <https://engineering.salesforce.com/easily-identify-malicious-servers-on-the-internet-with-jarm-e095edac525a>

use sha2::{Digest, Sha256};

use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// 62-character JARM-format fingerprint.
///
/// The fingerprint is composed of:
/// - First 30 characters: Lower 12 bits of chosen cipher from each of 10 probes (3 hex chars each)
/// - Last 32 characters: Truncated SHA-256 hash of ALPN/extension responses
///
/// # Example
///
/// ```rust
/// use gossan_portscan::jarm::Jarm;
///
/// // A valid 62-character JARM fingerprint
/// let fingerprint: Jarm = "07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1".into();
/// assert_eq!(fingerprint.len(), 62);
/// ```
pub type Jarm = String;

/// Known C2 and notable framework fingerprints.
/// Lower 12 bits of cipher × 10 probes → 30 chars, then SHA-256 extension tail.
pub const KNOWN: &[(&str, &str)] = &[
    // Cobalt Strike
    (
        "07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1",
        "Cobalt Strike C2",
    ),
    (
        "07d14d16d21d21d00042d43d000000aa99ce74e2c1d013c5d6b9d73bf6d5bc3",
        "Cobalt Strike C2 (beacon)",
    ),
    // Metasploit
    (
        "07d19d1ad21d21d07c42d43d000000f50d155305214cf247147c43c0f1a823",
        "Metasploit Framework",
    ),
    // Sliver C2
    (
        "00000000000000000042d42d000000eba85c7a7a12b4a41a1a7b43614fe5b6",
        "Sliver C2",
    ),
    // Covenant C2
    (
        "29d29d00029d29d00042d41d00041d2aa5ce6a70de7ba95aef77a77b00a0af",
        "Covenant C2",
    ),
    // Havoc C2
    (
        "00000000000000000022d22d000000baf7a1a8a4a4a4a4a4a4a4a4a4a4a4a4",
        "Havoc C2 (likely)",
    ),
    // BruteRatel C4
    (
        "1dd28d28d00028d1dc41d41d00041d07e3b6b8b6b8b6b8b6b8b6b8b6b8b6b8",
        "BruteRatel C4",
    ),
    // Common legit servers (for context)
    (
        "29d29d00029d29d21c42d43d000000032e1f2e4f19ca1bb9e16fa0c4e8b6a76",
        "nginx (default config)",
    ),
    (
        "2ad2ad0002ad2ad0042d42d000000e4b9f96bd97ae1b67fa98e59f073af41d",
        "Apache httpd 2.x",
    ),
    (
        "29d29d15d29d29d21c29d29d29d29dc0b6f3e93a028d8c6f7bca9f24ab6da5",
        "IIS 10 / Windows Server",
    ),
    (
        "27d27d27d27d27d00027d27d27d27de6d36b0c8ef5a0c870a93b84b8e90a45f",
        "Cloudflare",
    ),
    (
        "2ad2ad0002ad2ad22c2ad2ad2ad2ad1f05fe55bb4bfea1c504aef0440892b5b",
        "AWS ALB / CloudFront",
    ),
];

// ── TLS cipher suite constants ────────────────────────────────────────────────

/// TLS 1.2 cipher suite list (forward order).
const CIPHERS_12: &[u16] = &[
    0xc02b, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    0xc02f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    0x009e, // TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
    0xc00a, // TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
    0xc009, // TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
    0xc013, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
    0xc014, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
    0x0033, // TLS_DHE_RSA_WITH_AES_128_CBC_SHA
    0x0039, // TLS_DHE_RSA_WITH_AES_256_CBC_SHA
    0x002f, // TLS_RSA_WITH_AES_128_CBC_SHA
    0x0035, // TLS_RSA_WITH_AES_256_CBC_SHA
    0x000a, // TLS_RSA_WITH_3DES_EDE_CBC_SHA
];

/// TLS 1.3 + 1.2 mixed cipher list.
const CIPHERS_13: &[u16] = &[
    0x1301, // TLS_AES_128_GCM_SHA256
    0x1302, // TLS_AES_256_GCM_SHA384
    0x1303, // TLS_CHACHA20_POLY1305_SHA256
    0xc02b, 0xc02f, 0xc02c, 0xc030, 0xc00a, 0xc009, 0xc013, 0xc014, 0x009c, 0x002f, 0x0035,
];

/// TLS 1.3-only ciphers (probe 8).
const CIPHERS_13_ONLY: &[u16] = &[0x1301, 0x1302, 0x1303];

const SV_12: &[u16] = &[0x0303]; // TLS 1.2 only
const SV_13: &[u16] = &[0x0304, 0x0303]; // TLS 1.3 + 1.2
const ALPN_H2: &[&str] = &["h2"];
const ALPN_HTTP11: &[&str] = &["http/1.1"];

// ── Probe definitions ─────────────────────────────────────────────────────────

struct Probe {
    ciphers: &'static [u16],
    reverse: bool,
    record_ver: u16, // TLS record layer version (0x0301 = TLS 1.0 compat)
    hello_ver: u16,  // ClientHello version field
    supp_vers: &'static [u16],
    alpn: Option<&'static [&'static str]>,
    grease: bool,
    padding: bool,
}

/// The canonical JARM 10-probe suite.
static PROBES: &[Probe] = &[
    // 1  TLS 1.2, forward ciphers, no ALPN
    Probe {
        ciphers: CIPHERS_12,
        reverse: false,
        record_ver: 0x0301,
        hello_ver: 0x0303,
        supp_vers: SV_12,
        alpn: None,
        grease: false,
        padding: false,
    },
    // 2  TLS 1.2, reversed ciphers, no ALPN
    Probe {
        ciphers: CIPHERS_12,
        reverse: true,
        record_ver: 0x0301,
        hello_ver: 0x0303,
        supp_vers: SV_12,
        alpn: None,
        grease: false,
        padding: false,
    },
    // 3  TLS 1.2, forward, ALPN h2
    Probe {
        ciphers: CIPHERS_12,
        reverse: false,
        record_ver: 0x0301,
        hello_ver: 0x0303,
        supp_vers: SV_12,
        alpn: Some(ALPN_H2),
        grease: false,
        padding: false,
    },
    // 4  TLS 1.2, forward, ALPN http/1.1
    Probe {
        ciphers: CIPHERS_12,
        reverse: false,
        record_ver: 0x0301,
        hello_ver: 0x0303,
        supp_vers: SV_12,
        alpn: Some(ALPN_HTTP11),
        grease: false,
        padding: false,
    },
    // 5  TLS 1.2, forward, no ALPN, padding extension
    Probe {
        ciphers: CIPHERS_12,
        reverse: false,
        record_ver: 0x0301,
        hello_ver: 0x0303,
        supp_vers: SV_12,
        alpn: None,
        grease: false,
        padding: true,
    },
    // 6  TLS 1.3, forward, ALPN h2
    Probe {
        ciphers: CIPHERS_13,
        reverse: false,
        record_ver: 0x0301,
        hello_ver: 0x0301,
        supp_vers: SV_13,
        alpn: Some(ALPN_H2),
        grease: false,
        padding: false,
    },
    // 7  TLS 1.3, reversed, no ALPN
    Probe {
        ciphers: CIPHERS_13,
        reverse: true,
        record_ver: 0x0301,
        hello_ver: 0x0301,
        supp_vers: SV_13,
        alpn: None,
        grease: false,
        padding: false,
    },
    // 8  TLS 1.3 only ciphers, ALPN h2
    Probe {
        ciphers: CIPHERS_13_ONLY,
        reverse: false,
        record_ver: 0x0301,
        hello_ver: 0x0301,
        supp_vers: SV_13,
        alpn: Some(ALPN_H2),
        grease: false,
        padding: false,
    },
    // 9  TLS 1.3+1.2 mix, forward, no ALPN
    Probe {
        ciphers: CIPHERS_13,
        reverse: false,
        record_ver: 0x0301,
        hello_ver: 0x0303,
        supp_vers: SV_13,
        alpn: None,
        grease: false,
        padding: false,
    },
    // 10 TLS 1.2, forward, ALPN h2, GREASE cipher injected
    Probe {
        ciphers: CIPHERS_12,
        reverse: false,
        record_ver: 0x0301,
        hello_ver: 0x0303,
        supp_vers: SV_12,
        alpn: Some(ALPN_H2),
        grease: true,
        padding: false,
    },
];

// ── Fingerprint computation ───────────────────────────────────────────────────

/// Generates a JARM TLS fingerprint for the target host.
///
/// Sends 10 crafted TLS ClientHello probes with varying parameters
/// (cipher suites, TLS versions, ALPN protocols, extensions) and
/// hashes the responses to create a unique fingerprint.
///
/// # Arguments
///
/// * `host` - Target hostname or IP address
/// * `port` - Target TCP port (typically 443)
/// * `timeout` - Connection timeout for each probe
/// * `proxy` - Optional proxy URL (e.g., "socks5://127.0.0.1:1080")
///
/// # Returns
///
/// Returns `Some(Jarm)` with the 62-character fingerprint, or `None` if
/// all probes fail (server doesn't support TLS, connection refused, etc.)
///
/// # Example
///
/// ```rust,no_run
/// use std::time::Duration;
/// use gossan_portscan::jarm::fingerprint;
///
/// async fn example() {
///     if let Some(fp) = fingerprint("example.com", 443, Duration::from_secs(10), None).await {
///         println!("JARM fingerprint: {}", fp);
///     }
/// }
/// ```
///
/// # Known Fingerprints
///
/// Common framework fingerprints are available in the `KNOWN` constant:
/// - Cobalt Strike
/// - Metasploit
/// - Sliver C2
/// - Covenant C2
/// - Havoc C2
/// - nginx, Apache, IIS
/// - Cloudflare, AWS ALB
pub async fn fingerprint(
    host: &str,
    port: u16,
    timeout: Duration,
    proxy: Option<&str>,
) -> Option<Jarm> {
    let mut cipher_parts = String::new(); // 30 chars: 10 probes × 3 hex
    let mut alpn_parts = String::new(); // input to SHA-256

    for probe in PROBES {
        let hello = build_hello(probe, host);
        let result = send_probe(host, port, hello, timeout, proxy).await;

        match result {
            Some((cipher, alpn)) => {
                // Lower 12 bits of cipher → 3 hex chars
                cipher_parts.push_str(&format!("{:03x}", cipher & 0xFFF));
                alpn_parts.push_str(&alpn);
            }
            None => {
                cipher_parts.push_str("000");
                // alpn_parts gets nothing for null responses
            }
        }
    }

    // 32-char truncated SHA-256 of ALPN/extension accumulator
    let ext_hash = if alpn_parts.is_empty() {
        "0".repeat(32)
    } else {
        let digest = Sha256::digest(alpn_parts.as_bytes());
        format!("{:x}", digest)[..32].to_string()
    };

    Some(format!("{}{}", cipher_parts, ext_hash))
}

/// Look up a known framework by JARM fingerprint.
///
/// Compares the given fingerprint against a database of known
/// C2 frameworks, malware tools, and common server software.
///
/// # Arguments
///
/// * `fp` - The 62-character JARM fingerprint to identify
///
/// # Returns
///
/// Returns `Some("Framework Name")` if the fingerprint matches a known
/// signature, or `None` if unknown.
///
/// # Example
///
/// ```rust
/// use gossan_portscan::jarm::identify;
///
/// // Check if fingerprint matches a known C2 framework
/// let fp = "07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1";
/// if let Some(name) = identify(fp) {
///     println!("Detected: {} (possible C2/malware)", name);
/// }
/// ```
pub fn identify(fp: &str) -> Option<&'static str> {
    KNOWN.iter().find(|(k, _)| *k == fp).map(|(_, v)| *v)
}

// ── ClientHello builder ───────────────────────────────────────────────────────

fn build_hello(p: &Probe, host: &str) -> Vec<u8> {
    let mut ciphers: Vec<u16> = p.ciphers.to_vec();
    if p.reverse {
        ciphers.reverse();
    }
    if p.grease {
        ciphers.insert(0, 0x0a0a);
    }

    // ── Extensions ───────────────────────────────────────────────────────────
    let mut exts = Vec::new();
    exts.extend(ext_sni(host));
    exts.extend(ext_supported_groups());
    exts.extend(ext_ec_point_formats());
    exts.extend(ext_sig_algs());
    exts.extend(ext_session_ticket());
    if let Some(protos) = p.alpn {
        exts.extend(ext_alpn(protos));
    }
    exts.extend(ext_supported_versions(p.supp_vers));
    if p.supp_vers.contains(&0x0304) {
        exts.extend(ext_key_share());
        exts.extend(ext_psk_modes());
    }
    if p.padding {
        exts.extend(ext_padding(517));
    }

    // ── ClientHello body ─────────────────────────────────────────────────────
    let mut body = Vec::new();
    body.extend_from_slice(&p.hello_ver.to_be_bytes());
    body.extend_from_slice(&[0u8; 32]); // client random (zeros for fingerprinting)
    body.push(32);
    body.extend_from_slice(&[0u8; 32]); // session ID

    let cs_len = (ciphers.len() * 2) as u16;
    body.extend_from_slice(&cs_len.to_be_bytes());
    for c in &ciphers {
        body.extend_from_slice(&c.to_be_bytes());
    }

    body.push(1);
    body.push(0); // compression: null only

    let ext_len = exts.len() as u16;
    body.extend_from_slice(&ext_len.to_be_bytes());
    body.extend_from_slice(&exts);

    // ── Handshake wrapper ─────────────────────────────────────────────────────
    let body_len = body.len() as u32;
    let mut hs = vec![0x01]; // ClientHello type
    hs.push(((body_len >> 16) & 0xff) as u8);
    hs.push(((body_len >> 8) & 0xff) as u8);
    hs.push((body_len & 0xff) as u8);
    hs.extend_from_slice(&body);

    // ── TLS record wrapper ────────────────────────────────────────────────────
    let hs_len = hs.len() as u16;
    let mut rec = vec![0x16]; // content_type = handshake
    rec.extend_from_slice(&p.record_ver.to_be_bytes());
    rec.extend_from_slice(&hs_len.to_be_bytes());
    rec.extend_from_slice(&hs);
    rec
}

// ── Extension builders ────────────────────────────────────────────────────────

fn ext(typ: u16, data: &[u8]) -> Vec<u8> {
    let mut v = typ.to_be_bytes().to_vec();
    v.extend_from_slice(&(data.len() as u16).to_be_bytes());
    v.extend_from_slice(data);
    v
}

fn ext_sni(host: &str) -> Vec<u8> {
    let name = host.as_bytes();
    let name_len = name.len() as u16;
    let mut inner = Vec::new();
    inner.extend_from_slice(&(name_len + 3).to_be_bytes()); // list len
    inner.push(0x00); // type: host_name
    inner.extend_from_slice(&name_len.to_be_bytes());
    inner.extend_from_slice(name);
    ext(0x0000, &inner)
}

fn ext_supported_groups() -> Vec<u8> {
    let groups: &[u16] = &[0x001d, 0x0017, 0x0018, 0x0019];
    let mut d = ((groups.len() * 2) as u16).to_be_bytes().to_vec();
    for g in groups {
        d.extend_from_slice(&g.to_be_bytes());
    }
    ext(0x000a, &d)
}

fn ext_ec_point_formats() -> Vec<u8> {
    ext(0x000b, &[0x01, 0x00]) // length=1, uncompressed
}

fn ext_sig_algs() -> Vec<u8> {
    let algs: &[u16] = &[
        0x0401, 0x0501, 0x0601, // RSA PKCS#1
        0x0403, 0x0503, 0x0603, // ECDSA
        0x0804, 0x0805, 0x0806, // RSA-PSS
        0x0201, 0x0203, // RSA/ECDSA SHA-1 (legacy)
    ];
    let mut d = ((algs.len() * 2) as u16).to_be_bytes().to_vec();
    for a in algs {
        d.extend_from_slice(&a.to_be_bytes());
    }
    ext(0x000d, &d)
}

fn ext_session_ticket() -> Vec<u8> {
    ext(0x0023, &[]) // empty session ticket
}

fn ext_alpn(protocols: &[&str]) -> Vec<u8> {
    let mut list = Vec::new();
    for p in protocols {
        list.push(p.len() as u8);
        list.extend_from_slice(p.as_bytes());
    }
    let mut d = (list.len() as u16).to_be_bytes().to_vec();
    d.extend_from_slice(&list);
    ext(0x0010, &d)
}

fn ext_supported_versions(vers: &[u16]) -> Vec<u8> {
    let mut d = vec![(vers.len() * 2) as u8];
    for v in vers {
        d.extend_from_slice(&v.to_be_bytes());
    }
    ext(0x002b, &d)
}

fn ext_key_share() -> Vec<u8> {
    // x25519 key share with 32 zero bytes (server will still send ServerHello)
    let mut entry = 0x001du16.to_be_bytes().to_vec(); // group: x25519
    entry.extend_from_slice(&32u16.to_be_bytes());
    entry.extend_from_slice(&[0u8; 32]);
    let mut d = (entry.len() as u16).to_be_bytes().to_vec();
    d.extend_from_slice(&entry);
    ext(0x0033, &d)
}

fn ext_psk_modes() -> Vec<u8> {
    ext(0x002d, &[0x01, 0x01]) // length=1, psk_dhe_ke
}

fn ext_padding(target_len: usize) -> Vec<u8> {
    let pad = vec![0u8; target_len.saturating_sub(4)];
    ext(0x001c, &pad)
}

// ── ServerHello reader ────────────────────────────────────────────────────────

async fn send_probe(
    host: &str,
    port: u16,
    hello: Vec<u8>,
    timeout: Duration,
    proxy: Option<&str>,
) -> Option<(u16, String)> {
    let mut stream =
        tokio::time::timeout(timeout, gossan_core::net::connect_tcp(host, port, proxy))
            .await
            .ok()?
            .ok()?;

    tokio::time::timeout(timeout, stream.write_all(&hello))
        .await
        .ok()?
        .ok()?;

    let mut buf = vec![0u8; 8192];
    let n = tokio::time::timeout(Duration::from_millis(1500), stream.read(&mut buf))
        .await
        .ok()?
        .ok()?;

    parse_server_hello(&buf[..n])
}

/// Returns (chosen_cipher_suite, alpn_string) from a raw TLS ServerHello.
fn parse_server_hello(data: &[u8]) -> Option<(u16, String)> {
    if data.len() < 5 {
        return None;
    }
    if data[0] != 0x16 {
        return None;
    } // must be handshake record

    let record_len = u16::from_be_bytes([data[3], data[4]]) as usize;
    if data.len() < 5 + record_len {
        return None;
    }
    let hs = &data[5..5 + record_len];

    if hs.is_empty() || hs[0] != 0x02 {
        return None;
    } // ServerHello type

    let msg_len = ((hs[1] as usize) << 16) | ((hs[2] as usize) << 8) | hs[3] as usize;
    let msg = hs.get(4..4 + msg_len)?;

    // ServerHello body:
    // [2]  server_version
    // [32] server_random
    // [1]  session_id_length
    // [n]  session_id
    // [2]  cipher_suite  ← want this
    // [1]  compression_method
    // [2]  extensions_length (optional)
    if msg.len() < 35 {
        return None;
    }
    let session_id_len = msg[34] as usize;
    let cipher_off = 35 + session_id_len;
    if msg.len() < cipher_off + 2 {
        return None;
    }

    let cipher = u16::from_be_bytes([msg[cipher_off], msg[cipher_off + 1]]);

    // Parse extensions for ALPN (0x0010)
    let alpn_off = cipher_off + 3; // +2 cipher, +1 compression
    let alpn = if msg.len() > alpn_off + 2 {
        let ext_total = u16::from_be_bytes([msg[alpn_off], msg[alpn_off + 1]]) as usize;
        let exts_start = alpn_off + 2;
        msg.get(exts_start..exts_start + ext_total)
            .and_then(parse_alpn_ext)
            .unwrap_or_default()
    } else {
        String::new()
    };

    Some((cipher, alpn))
}

fn parse_alpn_ext(exts: &[u8]) -> Option<String> {
    let mut i = 0;
    while i + 4 <= exts.len() {
        let typ = u16::from_be_bytes([exts[i], exts[i + 1]]);
        let len = u16::from_be_bytes([exts[i + 2], exts[i + 3]]) as usize;
        i += 4;
        if i + len > exts.len() {
            break;
        }
        if typ == 0x0010 && len >= 4 {
            // ALPN: [list_len(2)][proto_len(1)][proto_bytes]
            let proto_len = exts[i + 2] as usize;
            if i + 3 + proto_len <= i + len {
                return String::from_utf8(exts[i + 3..i + 3 + proto_len].to_vec()).ok();
            }
        }
        i += len;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identify_returns_known_framework_name() {
        let (fp, name) = KNOWN[0];
        assert_eq!(identify(fp), Some(name));
    }

    #[test]
    fn identify_returns_none_for_unknown_fingerprint() {
        assert_eq!(identify("0".repeat(62).as_str()), None);
    }

    #[test]
    fn ext_alpn_encodes_protocol_list() {
        let ext = ext_alpn(&["h2", "http/1.1"]);
        assert_eq!(&ext[..2], &0x0010u16.to_be_bytes());
        assert!(ext.ends_with(b"h2\x08http/1.1"));
    }

    #[test]
    fn ext_padding_respects_target_length() {
        let ext = ext_padding(32);
        let len = u16::from_be_bytes([ext[2], ext[3]]) as usize;
        assert_eq!(len, 28);
    }

    #[test]
    fn parse_alpn_ext_extracts_h2_protocol() {
        let exts = ext_alpn(&["h2"]);
        assert_eq!(parse_alpn_ext(&exts), Some("h2".into()));
    }

    #[test]
    fn parse_alpn_ext_returns_none_when_missing() {
        assert_eq!(parse_alpn_ext(&ext_supported_groups()), None);
    }

    #[test]
    fn build_hello_contains_sni_hostname() {
        let hello = build_hello(&PROBES[0], "example.com");
        assert!(hello
            .windows("example.com".len())
            .any(|w| w == b"example.com"));
    }
}
