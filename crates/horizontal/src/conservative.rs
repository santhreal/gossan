//! Conservative campaign mapper — candidate generator for downstream consumers.
//!
//! Collects infrastructure signals from seed and candidate targets, then emits
//! structured findings with evidence for each correlated candidate. This module
//! intentionally produces **candidates**, not verdicts. Downstream tools
//! (Warpscan for static analysis, Sear for detonation) make independent decisions.
//!
//! # Signal Architecture
//!
//! Signals are classified into tiers by false-positive risk:
//!
//! | Tier | Signal                    | Use                            |
//! |------|---------------------------|--------------------------------|
//! | 0    | TLS cert, SSH key, etc.   | Strong evidence, low ambient   |
//! | 1    | Tracking IDs, API keys    | Account-bound, moderate noise  |
//! | 2    | Favicon, JARM, content    | Statistical, human review only |
//!
//! A candidate is emitted when the cumulative signal weight crosses the
//! configurable threshold. Each emitted finding carries full evidence so
//! downstream consumers can apply their own trust model.

use async_trait::async_trait;
use gossan_core::{Config, ScanInput, Scanner, Target};
use rustls::pki_types::ServerName;
use rustls::ClientConfig;
use secfinding::{Evidence, Severity};
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use x509_cert::der::Decode;
use x509_cert::Certificate;

// ---------------------------------------------------------------------------
// Signal types
// ---------------------------------------------------------------------------

/// A single infrastructure signal observed on a target.
#[derive(Debug, Clone)]
struct Signal {
    /// Human-readable name shown in findings.
    name: &'static str,
    /// Weight contribution toward the emission threshold.
    weight: u32,
    /// Detailed evidence string for the finding detail.
    detail: String,
    /// The matched value (for `matched_values` on the `Finding`).
    matched_value: String,
}

/// Minimum cumulative weight to emit a candidate.
///
/// Tuned so that a single strong signal (TLS cert = 40) is not enough alone,
/// requiring at least one corroborating signal. Two medium signals (e.g.,
/// favicon + tracking ID = 15 + 30 = 45) still fall short, preventing
/// statistical-only matches from reaching downstream consumers.
const EMISSION_THRESHOLD: u32 = 50;

// ---------------------------------------------------------------------------
// Ambient blocklists — values known to match across unrelated infrastructure
// ---------------------------------------------------------------------------

/// JARM fingerprints shared by major CDNs. Matching on these alone proves
/// nothing because millions of unrelated sites share the same CDN TLS stack.
const AMBIENT_JARM: &[&str] = &[
    "00000000000000000000000000000000000000000000000000000000000000", // empty
    "27d40d40d29d40d1dc42d43d00041d4689ee210f31b69966d2ca5cbdcea5a4", // Cloudflare
    "29d29d15d29d29d29d29d29d29d29de1a3c0b40e3adf9e5c3de16c8210fb1",  // Cloudflare alt
    "27d3ed3ed0003ed1dc42d43d00041d6183ff1bfae51ebd88d70e",           // Akamai
];

/// Default favicon mmh3 hashes that appear on millions of unrelated sites.
const AMBIENT_FAVICON: &[i32] = &[
    0,          // empty / failed fetch
    116323821,  // default Apache
    -547415799, // default nginx
    -782258017, // default IIS
];

/// RFC 1918 addresses too common to be organizational identifiers.
const AMBIENT_INTERNAL_IPS: &[&str] = &[
    "10.0.0.1",
    "10.0.0.2",
    "10.0.1.1",
    "192.168.0.1",
    "192.168.1.1",
    "192.168.1.254",
    "172.16.0.1",
    "127.0.0.1",
];

// ---------------------------------------------------------------------------
// Signal collectors
// ---------------------------------------------------------------------------

fn murmurhash3_x86_32(key: &[u8], seed: u32) -> i32 {
    let mut h1 = seed;
    let c1 = 0xcc9e2d51u32;
    let c2 = 0x1b873593u32;

    let mut chunks = key.chunks_exact(4);
    for chunk in &mut chunks {
        let mut k1 = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        k1 = k1.wrapping_mul(c1);
        k1 = k1.rotate_left(15);
        k1 = k1.wrapping_mul(c2);

        h1 ^= k1;
        h1 = h1.rotate_left(13);
        h1 = h1.wrapping_mul(5).wrapping_add(0xe6546b64);
    }

    let remainder = chunks.remainder();
    if !remainder.is_empty() {
        let mut k1 = 0u32;
        if remainder.len() >= 3 {
            k1 ^= (remainder[2] as u32) << 16;
        }
        if remainder.len() >= 2 {
            k1 ^= (remainder[1] as u32) << 8;
        }
        if !remainder.is_empty() {
            k1 ^= remainder[0] as u32;
        }
        k1 = k1.wrapping_mul(c1);
        k1 = k1.rotate_left(15);
        k1 = k1.wrapping_mul(c2);
        h1 ^= k1;
    }

    h1 ^= key.len() as u32;
    h1 ^= h1 >> 16;
    h1 = h1.wrapping_mul(0x85ebca6b);
    h1 ^= h1 >> 13;
    h1 = h1.wrapping_mul(0xc2b2ae35);
    h1 ^= h1 >> 16;

    i32::try_from(h1).unwrap_or(0)
}

/// Extract analytics/tracking property IDs from page body.
fn extract_tracking_ids(body: &str) -> HashSet<String> {
    use std::sync::OnceLock;
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        // GA, GTM, Google Ads, Facebook Pixel, Stripe publishable keys, Sentry DSN
        regex::Regex::new(
            r"(UA-\d{4,}-\d+|G-[A-Z0-9]{10}|AW-\d{9}|GTM-[A-Z0-9]+|fbq\('init',\s*'(\d{15,16})'|pk_live_[A-Za-z0-9]{20,})"
        ).expect("compile-time tracker-id regex literal must compile")
    });
    let mut ids = HashSet::new();
    for cap in re.captures_iter(body) {
        if let Some(m) = cap.get(1) {
            ids.insert(m.as_str().to_string());
        }
        if let Some(m) = cap.get(2) {
            ids.insert(m.as_str().to_string());
        }
    }
    ids
}

/// Extract leaked internal (RFC 1918) IPs from response headers.
fn extract_internal_ips(headers: &[(String, String)]) -> HashSet<String> {
    use std::sync::OnceLock;
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        regex::Regex::new(
            r"(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})"
        ).expect("compile-time RFC-1918 regex literal must compile")
    });
    let leak_headers = [
        "x-forwarded-for",
        "x-real-ip",
        "x-backend-server",
        "x-served-by",
        "x-host",
        "via",
        "x-forwarded-host",
    ];
    let mut ips = HashSet::new();
    for (name, value) in headers {
        if leak_headers.iter().any(|h| name.eq_ignore_ascii_case(h)) {
            for cap in re.captures_iter(value) {
                let ip = cap[1].to_string();
                if !AMBIENT_INTERNAL_IPS.contains(&ip.as_str()) {
                    ips.insert(ip);
                }
            }
        }
    }
    ips
}

/// Extract CSP report-uri or report-to endpoints.
fn extract_csp_report_uri(headers: &[(String, String)]) -> Option<String> {
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("content-security-policy")
            || name.eq_ignore_ascii_case("content-security-policy-report-only")
        {
            // report-uri directive
            if let Some(pos) = value.find("report-uri ") {
                let rest = &value[pos + 11..];
                let uri = rest.split([';', ' ']).next().unwrap_or("").trim();
                if !uri.is_empty() {
                    return Some(uri.to_string());
                }
            }
            // report-to directive (the endpoint name, not the URL itself)
            if let Some(pos) = value.find("report-to ") {
                let rest = &value[pos + 10..];
                let group = rest.split([';', ' ']).next().unwrap_or("").trim();
                if !group.is_empty() {
                    return Some(group.to_string());
                }
            }
        }
    }
    None
}

/// Extract non-public CORS allowed origins.
fn extract_cors_origins(headers: &[(String, String)]) -> HashSet<String> {
    let mut origins = HashSet::new();
    let public_patterns = ["*", "null", "https://fonts.googleapis.com"];
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("access-control-allow-origin") {
            let val = value.trim();
            if !public_patterns.contains(&val) && val.starts_with("http") {
                origins.insert(val.to_string());
            }
        }
    }
    origins
}

async fn get_dns_ips(
    resolver: &hickory_resolver::TokioAsyncResolver,
    host: &str,
) -> anyhow::Result<HashSet<IpAddr>> {
    let mut ips = HashSet::new();
    if let Ok(lookup) = resolver.lookup_ip(host).await {
        for ip in lookup.iter() {
            ips.insert(ip);
        }
    }
    if ips.is_empty() {
        anyhow::bail!("no dns records found for {}", host);
    }
    Ok(ips)
}

async fn get_jarm_fingerprint(host: &str) -> anyhow::Result<String> {
    let fp = gossan_portscan::jarm::fingerprint(host, 443, std::time::Duration::from_secs(5), None)
        .await;
    match fp {
        Some(jarm) => Ok(jarm),
        None => anyhow::bail!("failed to get jarm fingerprint for {}", host),
    }
}

async fn get_content_hash(
    client: &gossan_core::reqwest::Client,
    host: &str,
    max_size: usize,
) -> anyhow::Result<String> {
    let url = format!("http://{}/", host);
    let resp = client.get(&url).send().await?;
    let b = gossan_core::ratelimit::read_response_limited(resp, max_size).await?;

    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(&b);
    Ok(hex::encode(hasher.finalize()))
}

async fn get_favicon_hash(
    client: &gossan_core::reqwest::Client,
    host: &str,
    max_size: usize,
) -> anyhow::Result<i32> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let url = format!("http://{}/favicon.ico", host);
    let resp = client.get(&url).send().await?;
    let b = gossan_core::ratelimit::read_response_limited(resp, max_size).await?;
    let b64 = STANDARD.encode(&b);
    let mut formatted_b64 = String::with_capacity(b64.len() + b64.len() / 76);
    let mut chunks = b64.as_bytes().chunks_exact(76);
    for chunk in &mut chunks {
        formatted_b64.push_str(std::str::from_utf8(chunk).unwrap_or(""));
        formatted_b64.push('\n');
    }
    let remainder = chunks.remainder();
    if !remainder.is_empty() {
        formatted_b64.push_str(std::str::from_utf8(remainder).unwrap_or(""));
        formatted_b64.push('\n');
    }

    Ok(murmurhash3_x86_32(formatted_b64.as_bytes(), 0))
}

async fn get_ssh_host_key(host: &str) -> anyhow::Result<String> {
    let addr = format!("{}:22", host);
    let mut stream = TcpStream::connect(addr).await?;

    let mut banner = vec![0; 256];
    let n =
        tokio::time::timeout(std::time::Duration::from_secs(2), stream.read(&mut banner)).await??;
    if n == 0 {
        anyhow::bail!("ssh connection closed for {}", host);
    }

    stream.write_all(b"SSH-2.0-Gossan_1.0\r\n").await?;

    let mut kex = vec![0; 4096];
    let n =
        tokio::time::timeout(std::time::Duration::from_secs(2), stream.read(&mut kex)).await??;
    if n == 0 {
        anyhow::bail!("ssh connection closed after banner for {}", host);
    }

    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(&kex[..n]);
    Ok(hex::encode(hasher.finalize()))
}

async fn get_cert_serial(host: &str) -> anyhow::Result<Vec<u8>> {
    let addr = format!("{}:443", host);
    let stream = TcpStream::connect(addr).await?;

    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoAuthVerifier))
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(config));
    let server_name = ServerName::try_from(host.to_string())?.to_owned();

    let stream = connector.connect(server_name, stream).await?;
    let certs = stream
        .get_ref()
        .1
        .peer_certificates()
        .ok_or_else(|| anyhow::anyhow!("no certificates found for {}", host))?;

    if let Some(cert) = certs.first() {
        let parsed = Certificate::from_der(cert.as_ref())?;
        return Ok(parsed.tbs_certificate.serial_number.as_bytes().to_vec());
    }

    anyhow::bail!("failed to parse certificate for {}", host)
}

/// Fetch HTTP response and return status, headers, body text.
async fn fetch_http(
    client: &gossan_core::reqwest::Client,
    host: &str,
    max_size: usize,
) -> anyhow::Result<(u16, Vec<(String, String)>, String)> {
    let url = format!("http://{}/", host);
    let resp = client.get(&url).send().await?;
    let status = resp.status().as_u16();
    let headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();
    let body_bytes = gossan_core::ratelimit::read_response_limited(resp, max_size).await?;
    let body = String::from_utf8_lossy(&body_bytes).to_string();
    Ok((status, headers, body))
}

// ---------------------------------------------------------------------------
// Seed fingerprint — all signals collected from the seed target
// ---------------------------------------------------------------------------

/// All infrastructure signals collected from the seed target.
struct SeedFingerprint {
    cert_serial: Option<Vec<u8>>,
    ssh_key: Option<String>,
    tracking_ids: HashSet<String>,
    internal_ips: HashSet<String>,
    csp_report_uri: Option<String>,
    cors_origins: HashSet<String>,
    favicon_hash: Option<i32>,
    content_hash: Option<String>,
    jarm: Option<String>,
    dns_ips: Option<HashSet<IpAddr>>,
}

impl SeedFingerprint {
    async fn collect(
        client: &gossan_core::reqwest::Client,
        resolver: &hickory_resolver::TokioAsyncResolver,
        seed: &str,
        max_size: usize,
    ) -> Self {
        let (mut tracking_ids, mut internal_ips, mut csp_report_uri, mut cors_origins) =
            (HashSet::new(), HashSet::new(), None, HashSet::new());

        if let Ok((_status, headers, body)) = fetch_http(client, seed, max_size).await {
            tracking_ids = extract_tracking_ids(&body);
            internal_ips = extract_internal_ips(&headers);
            csp_report_uri = extract_csp_report_uri(&headers);
            cors_origins = extract_cors_origins(&headers);
        }

        Self {
            cert_serial: get_cert_serial(seed).await.ok(),
            ssh_key: get_ssh_host_key(seed).await.ok(),
            tracking_ids,
            internal_ips,
            csp_report_uri,
            cors_origins,
            favicon_hash: get_favicon_hash(client, seed, max_size).await.ok(),
            content_hash: get_content_hash(client, seed, max_size).await.ok(),
            jarm: get_jarm_fingerprint(seed).await.ok(),
            dns_ips: get_dns_ips(resolver, seed).await.ok(),
        }
    }

    /// Compare this fingerprint against a candidate and return all matching signals.
    async fn compare(
        &self,
        client: &gossan_core::reqwest::Client,
        resolver: &hickory_resolver::TokioAsyncResolver,
        host: &str,
        max_size: usize,
    ) -> Vec<Signal> {
        let mut signals = Vec::new();

        // --- Tier 0: strong infrastructure signals ---

        // TLS certificate serial
        if let Some(ref seed_cert) = self.cert_serial {
            if !seed_cert.is_empty() {
                if let Ok(t_cert) = get_cert_serial(host).await {
                    if seed_cert == &t_cert {
                        signals.push(Signal {
                            name: "TLS Certificate Serial",
                            weight: 40,
                            detail: format!("same leaf TLS certificate serial as seed"),
                            matched_value: hex::encode(&t_cert),
                        });
                    }
                }
            }
        }

        // SSH host key
        if let Some(ref seed_ssh) = self.ssh_key {
            if !seed_ssh.is_empty() {
                if let Ok(t_ssh) = get_ssh_host_key(host).await {
                    if seed_ssh == &t_ssh {
                        signals.push(Signal {
                            name: "SSH Host Key",
                            weight: 40,
                            detail: format!("same ssh kex fingerprint as seed"),
                            matched_value: t_ssh,
                        });
                    }
                }
            }
        }

        // --- Fetch candidate HTTP once for multiple signal extractions ---
        let mut t_tracking_ids = HashSet::new();
        let mut t_internal_ips = HashSet::new();
        let mut t_csp_report_uri = None;
        let mut t_cors_origins = HashSet::new();

        if let Ok((_status, headers, body)) = fetch_http(client, host, max_size).await {
            t_tracking_ids = extract_tracking_ids(&body);
            t_internal_ips = extract_internal_ips(&headers);
            t_csp_report_uri = extract_csp_report_uri(&headers);
            t_cors_origins = extract_cors_origins(&headers);
        }

        // --- Tier 1: account-bound signals ---

        // Shared tracking/analytics IDs
        if !self.tracking_ids.is_empty() {
            let shared: Vec<_> = self
                .tracking_ids
                .intersection(&t_tracking_ids)
                .cloned()
                .collect();
            if !shared.is_empty() {
                signals.push(Signal {
                    name: "Shared Tracking ID",
                    weight: 30,
                    detail: format!("shared analytics property: {}", shared.join(", ")),
                    matched_value: shared.join(", "),
                });
            }
        }

        // Leaked internal IPs
        if !self.internal_ips.is_empty() {
            let shared: Vec<_> = self
                .internal_ips
                .intersection(&t_internal_ips)
                .cloned()
                .collect();
            if !shared.is_empty() {
                signals.push(Signal {
                    name: "Leaked Internal IP",
                    weight: 35,
                    detail: format!(
                        "same RFC 1918 address leaked in headers: {}",
                        shared.join(", ")
                    ),
                    matched_value: shared.join(", "),
                });
            }
        }

        // CSP report-uri match
        if let (Some(ref seed_uri), Some(ref t_uri)) = (&self.csp_report_uri, &t_csp_report_uri) {
            if seed_uri == t_uri && !seed_uri.is_empty() {
                signals.push(Signal {
                    name: "CSP Report Endpoint",
                    weight: 25,
                    detail: format!("same CSP report-uri: {}", seed_uri),
                    matched_value: seed_uri.clone(),
                });
            }
        }

        // CORS non-public origin match
        if !self.cors_origins.is_empty() {
            let shared: Vec<_> = self
                .cors_origins
                .intersection(&t_cors_origins)
                .cloned()
                .collect();
            if !shared.is_empty() {
                signals.push(Signal {
                    name: "CORS Allowed Origin",
                    weight: 20,
                    detail: format!("same non-public CORS origin: {}", shared.join(", ")),
                    matched_value: shared.join(", "),
                });
            }
        }

        // --- Tier 2: statistical signals (lower weight) ---

        // Favicon hash (with ambient rejection)
        if let Some(seed_fav) = self.favicon_hash {
            if !AMBIENT_FAVICON.contains(&seed_fav) {
                if let Ok(t_fav) = get_favicon_hash(client, host, max_size).await {
                    if seed_fav == t_fav && !AMBIENT_FAVICON.contains(&t_fav) {
                        signals.push(Signal {
                            name: "Favicon Hash",
                            weight: 15,
                            detail: format!("same favicon mmh3: {}", t_fav),
                            matched_value: t_fav.to_string(),
                        });
                    }
                }
            }
        }

        // Content hash
        if let Some(ref seed_con) = self.content_hash {
            if !seed_con.is_empty() {
                if let Ok(t_con) = get_content_hash(client, host, max_size).await {
                    if seed_con == &t_con {
                        signals.push(Signal {
                            name: "Content Hash",
                            weight: 20,
                            detail: format!("identical page content SHA-256"),
                            matched_value: t_con,
                        });
                    }
                }
            }
        }

        // JARM fingerprint (with ambient rejection)
        if let Some(ref seed_jarm) = self.jarm {
            if !AMBIENT_JARM.iter().any(|a| a == seed_jarm) {
                if let Ok(t_jarm) = get_jarm_fingerprint(host).await {
                    if seed_jarm == &t_jarm && !AMBIENT_JARM.iter().any(|a| a == &t_jarm) {
                        signals.push(Signal {
                            name: "JARM TLS Fingerprint",
                            weight: 10,
                            detail: format!(
                                "same JARM (non-CDN): {}",
                                &t_jarm[..16.min(t_jarm.len())]
                            ),
                            matched_value: t_jarm,
                        });
                    }
                }
            }
        }

        // DNS IP (lowest weight — shared hosting is extremely common)
        if let Some(ref seed_dns) = self.dns_ips {
            if !seed_dns.is_empty() {
                if let Ok(t_dns) = get_dns_ips(resolver, host).await {
                    if seed_dns == &t_dns {
                        signals.push(Signal {
                            name: "DNS Resolution IP",
                            weight: 5,
                            detail: format!(
                                "resolves to same IP(s): {}",
                                t_dns
                                    .iter()
                                    .map(|ip| ip.to_string())
                                    .collect::<Vec<_>>()
                                    .join(", ")
                            ),
                            matched_value: t_dns
                                .iter()
                                .map(|ip| ip.to_string())
                                .collect::<Vec<_>>()
                                .join(", "),
                        });
                    }
                }
            }
        }

        signals
    }
}

// ---------------------------------------------------------------------------
// TLS verifier (accept any cert — we only care about the serial, not validity)
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct NoAuthVerifier;

impl rustls::client::danger::ServerCertVerifier for NoAuthVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ED448,
        ]
    }
}

// ---------------------------------------------------------------------------
// Scanner implementation
// ---------------------------------------------------------------------------

/// Conservative campaign mapper — candidate generator for Warpscan and Sear.
///
/// Compares candidate targets against a seed using tiered infrastructure signals.
/// Emits structured findings with full evidence for each correlated candidate.
/// Intentionally a candidate generator, not a verdict engine.
///
/// # Examples
///
/// ```rust,ignore
/// let scanner = ConservativeScanner;
/// let output = scanner.run(input, &config).await?;
/// // output.findings carry signal evidence for downstream consumers
/// ```
pub struct ConservativeScanner;

#[async_trait]
impl Scanner for ConservativeScanner {
    fn name(&self) -> &'static str {
        "conservative"
    }

    fn tags(&self) -> &[&'static str] {
        &["passive", "network", "intel", "horizontal", "conservative"]
    }

    fn accepts(&self, target: &Target) -> bool {
        matches!(target, Target::Domain(_) | Target::Host(_))
    }

    async fn run(&self, input: ScanInput, config: &Config) -> anyhow::Result<()> {
        let client = gossan_core::ScanClient::from_config(config, Arc::clone(&input.resolver))?;
        let resolver = Arc::clone(&input.resolver);
        let seed = &input.seed;

        // Collect all signals from the seed target once.
        let fingerprint =
            SeedFingerprint::collect(&client, &resolver, seed, config.max_response_size).await;

        // Drain the inbound target stream. Conservative campaign
        // matching scores each candidate against the seed fingerprint,
        // so it needs the full input set — collecting up-front is the
        // intended semantics.
        let inbound: Vec<Target> = {
            let mut rx = input.target_rx.lock().await;
            let mut buf = Vec::new();
            while let Ok(t) = rx.try_recv() {
                buf.push(t);
            }
            buf
        };

        for target in &inbound {
            let host_string = match target {
                Target::Domain(d) => d.domain.clone(),
                Target::Host(h) => h.ip.to_string(),
                _ => continue,
            };
            let host = host_string.as_str();

            if host == seed {
                continue;
            }

            let signals = fingerprint
                .compare(&client, &resolver, host, config.max_response_size)
                .await;

            let total_weight: u32 = signals.iter().map(|s| s.weight).sum();

            if total_weight >= EMISSION_THRESHOLD {
                let signal_names: Vec<_> = signals.iter().map(|s| s.name).collect();
                let signal_details: Vec<_> = signals
                    .iter()
                    .map(|s| format!("  [{}] (weight: {}) {}", s.name, s.weight, s.detail))
                    .collect();

                let confidence = (total_weight as f64 / 100.0).min(1.0);

                // emit_target already pushes to target_tx (which is no
                // longer Optional in the streaming refactor). The
                // explicit `if let Some(ref tx)` send below was a
                // double-emit relic from the earlier API.
                input.emit_target(target.clone());

                let mut builder =
                    secfinding::Finding::builder("conservative", host, Severity::Info)
                        .title(format!(
                            "Campaign candidate: {} signals matched (score: {})",
                            signal_names.len(),
                            total_weight,
                        ))
                        .detail(format!(
                    "Target {} correlates with seed {} via {} independent infrastructure signals \
                     (cumulative weight: {}/{}):\n{}",
                    host, seed, signals.len(), total_weight, EMISSION_THRESHOLD,
                    signal_details.join("\n"),
                ))
                        .confidence(confidence)
                        .tag("conservative")
                        .tag("campaign-candidate")
                        .kind(secfinding::FindingKind::InfoDisclosure);

                for signal in &signals {
                    builder =
                        builder.matched_value(format!("{}={}", signal.name, signal.matched_value));
                }

                // Attach structured signal evidence as JSON
                let signal_json = serde_json::json!({
                    "seed": seed,
                    "candidate": host,
                    "total_weight": total_weight,
                    "threshold": EMISSION_THRESHOLD,
                    "signals": signals.iter().map(|s| serde_json::json!({
                        "name": s.name,
                        "weight": s.weight,
                        "detail": s.detail,
                        "matched_value": s.matched_value,
                    })).collect::<Vec<_>>(),
                });
                builder = builder.evidence(Evidence::Raw(signal_json.to_string().into()));

                if let Some(finding) = builder.build_or_log() {
                    input.emit(finding);
                }
            }
        }

        Ok(())
    }
}
