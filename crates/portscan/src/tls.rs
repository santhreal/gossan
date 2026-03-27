//! TLS certificate inspection for exposed HTTPS/TLS ports.
//! Extracts: Subject, Issuer, SANs, expiry date.
//! Emits findings for: expired certs, certs expiring soon, self-signed certs.
//! SANs are returned as additional domain targets for pipeline enrichment.

use std::fmt;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error, SignatureScheme};
use tokio_rustls::TlsConnector;
use x509_cert::der::Decode;
use x509_cert::Certificate;

/// Information extracted from a TLS certificate.
///
/// Contains parsed certificate fields including subject, issuer,
/// Subject Alternative Names (SANs), and expiry information.
///
/// # Example
///
/// ```rust
/// use gossan_portscan::tls::TlsCertInfo;
///
/// let info = TlsCertInfo {
///     subject: "CN=example.com".into(),
///     issuer: "CN=Let's Encrypt Authority X3".into(),
///     sans: vec!["example.com".into(), "www.example.com".into()],
///     not_after_unix: 1893456000, // Unix timestamp
///     is_self_signed: false,
/// };
///
/// println!("Certificate for: {}", info.subject);
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct TlsCertInfo {
    /// Certificate subject (e.g., "CN=example.com, O=Organization")
    pub subject: String,
    /// Certificate issuer (e.g., "CN=Let's Encrypt Authority X3")
    pub issuer: String,
    /// Subject Alternative Names (DNS names) from the certificate
    pub sans: Vec<String>,
    /// Unix timestamp of certificate expiry.
    pub not_after_unix: i64,
    /// Whether the certificate is self-signed (subject == issuer)
    pub is_self_signed: bool,
}

impl fmt::Display for TlsCertInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TlsCertInfo(subject: {}, issuer: {}, sans: {:?}, expires: {}, self-signed: {})",
            self.subject, self.issuer, self.sans, self.not_after_unix, self.is_self_signed
        )
    }
}

/// Accepts any server certificate — we're doing recon, not verification.
#[derive(Debug)]
struct AcceptAll;

impl ServerCertVerifier for AcceptAll {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _msg: &[u8],
        _cert: &CertificateDer<'_>,
        _sig: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _msg: &[u8],
        _cert: &CertificateDer<'_>,
        _sig: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA1,
            SignatureScheme::ECDSA_SHA1_Legacy,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
        ]
    }
}

/// Probes a TLS server and extracts certificate information.
///
/// Connects to the specified address and performs a TLS handshake to
/// retrieve certificate details. Uses a permissive certificate verifier
/// that accepts any certificate (for reconnaissance, not verification).
///
/// # Arguments
///
/// * `addr` - Hostname or IP address to connect to
/// * `port` - TCP port number
/// * `timeout` - Connection and handshake timeout
/// * `proxy` - Optional proxy URL (e.g., "socks5://127.0.0.1:1080")
///
/// # Returns
///
/// Returns `Some(TlsCertInfo)` if the TLS handshake succeeds and the
/// certificate can be parsed. Returns `None` on connection failure,
/// timeout, or parsing error.
///
/// # Example
///
/// ```rust,no_run
/// use std::time::Duration;
/// use gossan_portscan::tls::probe_tls;
///
/// async fn example() {
///     if let Some(info) = probe_tls("example.com", 443, Duration::from_secs(10), None).await {
///         println!("Certificate subject: {}", info.subject);
///         println!("Is self-signed: {}", info.is_self_signed);
///     }
/// }
/// ```
pub async fn probe_tls(
    addr: &str,
    port: u16,
    timeout: Duration,
    proxy: Option<&str>,
) -> Option<TlsCertInfo> {
    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAll))
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(config));

    let stream = tokio::time::timeout(timeout, gossan_core::net::connect_tcp(addr, port, proxy))
        .await
        .ok()?
        .ok()?;

    let server_name = ServerName::try_from(addr.to_string()).ok()?;
    let tls_stream = tokio::time::timeout(timeout, connector.connect(server_name, stream))
        .await
        .ok()?
        .ok()?;

    let (_, server_conn) = tls_stream.get_ref();
    let certs = server_conn.peer_certificates()?;
    let der = certs.first()?;
    parse_cert(der)
}

fn parse_cert(der: &CertificateDer<'_>) -> Option<TlsCertInfo> {
    let cert = Certificate::from_der(der.as_ref()).ok()?;
    let tbs = &cert.tbs_certificate;

    let subject = tbs.subject.to_string();
    let issuer = tbs.issuer.to_string();
    let is_self_signed = subject == issuer;

    // Convert expiry to Unix timestamp
    let not_after_unix = {
        let st = tbs.validity.not_after.to_system_time();
        st.duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    };

    // Extract DNS SANs from Subject Alternative Name extension
    let mut sans: Vec<String> = Vec::new();
    if let Some(exts) = &tbs.extensions {
        use x509_cert::ext::pkix::name::GeneralName;
        use x509_cert::ext::pkix::SubjectAltName;

        for ext in exts.iter() {
            // OID 2.5.29.17 = SubjectAltName
            if ext.extn_id.to_string() == "2.5.29.17" {
                if let Ok(san) = SubjectAltName::from_der(ext.extn_value.as_bytes()) {
                    for name in &san.0 {
                        if let GeneralName::DnsName(dns) = name {
                            let s = dns.as_str().trim_start_matches("*.").to_string();
                            if !s.is_empty() {
                                sans.push(s);
                            }
                        }
                    }
                }
            }
        }
    }

    // Fallback: extract CN from subject if no SANs
    if sans.is_empty() {
        if let Some(cn) = extract_cn(&subject) {
            sans.push(cn);
        }
    }

    Some(TlsCertInfo {
        subject,
        issuer,
        sans,
        not_after_unix,
        is_self_signed,
    })
}

/// Extract CN value from an RDN string like "CN=example.com, O=Acme"
fn extract_cn(rdnseq: &str) -> Option<String> {
    for part in rdnseq.split(',') {
        let part = part.trim();
        if let Some(val) = part.strip_prefix("CN=") {
            return Some(val.trim().to_string());
        }
    }
    None
}

/// Result of legacy TLS protocol version probing.
///
/// Indicates whether a server accepts deprecated TLS 1.0 or 1.1 connections.
/// Both protocols have known vulnerabilities (BEAST, POODLE) and were
/// deprecated by RFC 8996.
///
/// # Example
///
/// ```rust
/// use gossan_portscan::tls::LegacyTlsResult;
///
/// let result = LegacyTlsResult {
///     supports_tls10: false,
///     supports_tls11: false,
/// };
///
/// if result.supports_tls10 {
///     println!("Warning: TLS 1.0 is supported (vulnerable to BEAST/POODLE)");
/// }
/// ```
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LegacyTlsResult {
    /// Whether TLS 1.0 is supported (deprecated, vulnerable to BEAST/POODLE)
    pub supports_tls10: bool,
    /// Whether TLS 1.1 is supported (deprecated by RFC 8996)
    pub supports_tls11: bool,
}

impl fmt::Display for LegacyTlsResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.supports_tls10 || self.supports_tls11 {
            write!(
                f,
                "LegacyTlsResult(TLS 1.0: {}, TLS 1.1: {})",
                if self.supports_tls10 {
                    "VULNERABLE"
                } else {
                    "no"
                },
                if self.supports_tls11 {
                    "deprecated"
                } else {
                    "no"
                }
            )
        } else {
            write!(f, "LegacyTlsResult(no legacy protocols)")
        }
    }
}

/// Probe whether a TLS server accepts legacy protocol versions (1.0 / 1.1).
///
/// Strategy: send a minimal ClientHello with the target version field set.
/// If the server responds with a ServerHello (byte 0x16, byte 1 = 0x03),
/// the version was accepted. A fatal alert or connection reset means rejected.
///
/// We use raw TCP so we're not constrained by rustls's minimum version policy.
///
/// TLS 1.0 and 1.1 are deprecated due to vulnerabilities:
/// - BEAST (CVE-2011-3389): TLS 1.0 CBC mode weakness
/// - POODLE (CVE-2014-3566): SSL 3.0/TLS 1.0 padding oracle
///
/// Both protocols were formally deprecated by RFC 8996 in March 2021.
///
/// # Arguments
///
/// * `addr` - Hostname or IP address to connect to
/// * `port` - TCP port number
/// * `timeout` - Connection timeout
/// * `proxy` - Optional proxy URL
///
/// # Returns
///
/// Returns a `LegacyTlsResult` indicating which deprecated protocols are supported.
///
/// # Example
///
/// ```rust,no_run
/// use std::time::Duration;
/// use gossan_portscan::tls::probe_legacy;
///
/// async fn example() {
///     let result = probe_legacy("example.com", 443, Duration::from_secs(10), None).await;
///     if result.supports_tls10 {
///         println!("Warning: Server supports vulnerable TLS 1.0");
///     }
/// }
/// ```
pub async fn probe_legacy(
    addr: &str,
    port: u16,
    timeout: Duration,
    proxy: Option<&str>,
) -> LegacyTlsResult {
    let tls10 = probe_raw_version(addr, port, timeout, [0x03, 0x01], proxy).await;
    let tls11 = probe_raw_version(addr, port, timeout, [0x03, 0x02], proxy).await;
    LegacyTlsResult {
        supports_tls10: tls10,
        supports_tls11: tls11,
    }
}

/// Send a minimal TLS ClientHello with the given version bytes [major, minor]
/// and return true if the server responds with a ServerHello (not an alert).
async fn probe_raw_version(
    addr: &str,
    port: u16,
    timeout: Duration,
    version: [u8; 2],
    proxy: Option<&str>,
) -> bool {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let Ok(Ok(mut stream)) =
        tokio::time::timeout(timeout, gossan_core::net::connect_tcp(addr, port, proxy)).await
    else {
        return false;
    };

    // Minimal TLS ClientHello for the requested version.
    // Record layer:  0x16 = handshake, version = target, length = 41 bytes
    // Handshake:     0x01 = ClientHello, length = 37
    // ClientHello:   version = target, 32-byte random, session_id = 0
    //                cipher_suites length = 2, one suite (TLS_RSA_WITH_AES_128_CBC_SHA = 0x002F)
    //                compression_methods = 1 byte null
    let hello: Vec<u8> = {
        let mut h = Vec::with_capacity(49);
        // TLS record header
        h.push(0x16); // content type: handshake
        h.extend_from_slice(&version); // record version
        h.extend_from_slice(&[0x00, 0x29]); // length = 41

        // Handshake header
        h.push(0x01); // HandshakeType: ClientHello
        h.extend_from_slice(&[0x00, 0x00, 0x25]); // length = 37

        // ClientHello body
        h.extend_from_slice(&version); // client_version
                                       // 32-byte random (deterministic probe bytes)
        h.extend_from_slice(&[
            0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
            0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1A, 0x1B, 0x1C,
        ]);
        h.push(0x00); // session_id length = 0
        h.extend_from_slice(&[0x00, 0x02]); // cipher_suites length = 2
        h.extend_from_slice(&[0x00, 0x2F]); // TLS_RSA_WITH_AES_128_CBC_SHA
        h.push(0x01); // compression_methods length = 1
        h.push(0x00); // null compression
        h
    };

    if tokio::time::timeout(timeout, stream.write_all(&hello))
        .await
        .ok()
        .is_none()
    {
        return false;
    }

    // Read first 5 bytes of the response (TLS record header)
    let mut header = [0u8; 5];
    let Ok(Ok(_)) =
        tokio::time::timeout(Duration::from_secs(3), stream.read_exact(&mut header)).await
    else {
        return false;
    };

    // ServerHello: record type 0x16 (handshake), major 0x03
    // Alert:       record type 0x15 — means rejected
    header[0] == 0x16 && header[1] == 0x03
}

/// Calculates days until certificate expiry.
///
/// # Arguments
///
/// * `not_after_unix` - Unix timestamp of certificate expiration
///
/// # Returns
///
/// Returns positive days until expiry, or negative days if already expired.
///
/// # Example
///
/// ```rust
/// use gossan_portscan::tls::days_until_expiry;
/// use std::time::{SystemTime, UNIX_EPOCH};
///
/// // Calculate days until a future certificate expires
/// let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
/// let future = now + (30 * 86400); // 30 days from now
/// assert_eq!(days_until_expiry(future), 30);
///
/// // Calculate days since a past certificate expired
/// let past = now - (7 * 86400); // 7 days ago
/// assert_eq!(days_until_expiry(past), -7);
/// ```
pub fn days_until_expiry(not_after_unix: i64) -> i64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    (not_after_unix - now) / 86_400
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_cn_returns_common_name() {
        assert_eq!(
            extract_cn("CN=example.com, O=Acme"),
            Some("example.com".into())
        );
    }

    #[test]
    fn extract_cn_ignores_non_cn_attributes() {
        assert_eq!(extract_cn("O=Acme, OU=Security"), None);
    }

    #[test]
    fn days_until_expiry_is_positive_for_future_dates() {
        let future = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
            + 3 * 86_400;
        let days = days_until_expiry(future);
        assert!((2..=3).contains(&days));
    }

    #[test]
    fn days_until_expiry_is_negative_for_past_dates() {
        let past = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
            - 2 * 86_400;
        assert!(days_until_expiry(past) <= -1);
    }

    #[test]
    fn accept_all_reports_supported_verify_schemes() {
        let schemes = AcceptAll.supported_verify_schemes();
        assert!(schemes.contains(&SignatureScheme::RSA_PSS_SHA256));
        assert!(schemes.contains(&SignatureScheme::ECDSA_NISTP256_SHA256));
        assert!(schemes.contains(&SignatureScheme::ED25519));
    }
}
