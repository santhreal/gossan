//! TCP connect scanner with banner grabbing and TLS cert inspection.
//! Probes common ports, reads first bytes to identify service version.
//! On TLS ports: extracts cert SANs, expiry, and self-signed status.
//! Emits findings for high-risk exposed services (Docker, k8s, Redis, etc.)
//!
//! # Configuration
//!
//! Port lists and risky service definitions are loaded from TOML files:
//! - `rules/top_ports.toml` - Port list definitions (default, top_100, top_1000)
//! - `rules/risky_services.toml` - High-risk service definitions
//!
//! Users can extend these by placing custom `*.toml` files in a `rules/` directory.
//! See the `rules` module documentation for details.

pub mod cve;
pub mod jarm;
pub mod rules;
pub mod tls;
pub mod top_ports;

use std::fmt;

use async_trait::async_trait;
use futures::StreamExt;
use gossan_core::{
    Config, DiscoverySource, DomainTarget, HostTarget, PortMode, Protocol, ScanInput, ScanOutput,
    Scanner, ServiceTarget, Target,
};
use secfinding::{Evidence, Finding, FindingBuilder, Severity};
use std::time::Duration;
use tokio::io::AsyncReadExt;

/// TCP port scanner with banner grabbing, TLS inspection, and CVE correlation.
///
/// Scans common ports and identifies:
/// - High-risk exposed services (Docker, Redis, MongoDB, etc.)
/// - Service versions from banners (SSH, FTP, SMTP, HTTP, etc.)
/// - TLS certificate issues (expiry, self-signed)
/// - Legacy TLS protocol support (TLS 1.0/1.1)
/// - JARM TLS fingerprints for C2/malware detection
/// - CVE correlation from service banners
///
/// # Example
///
/// ```rust,no_run
/// use gossan_portscan::PortScanner;
/// use gossan_core::{Scanner, ScanInput, Config};
///
/// async fn example() -> anyhow::Result<()> {
///     let scanner = PortScanner::new();
///     // Use with gossan_core scanner pipeline...
///     Ok(())
/// }
/// ```
pub struct PortScanner;

impl Default for PortScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl PortScanner {
    /// Creates a new port scanner instance.
    ///
    /// The scanner is stateless and can be reused across multiple scans.
    ///
    /// # Example
    ///
    /// ```rust
    /// use gossan_portscan::PortScanner;
    ///
    /// let scanner = PortScanner::new();
    /// ```
    pub fn new() -> Self {
        Self
    }
}

impl fmt::Display for PortScanner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PortScanner({})", self.name())
    }
}

/// Creates a finding builder pre-configured for portscan findings.
///
/// # Arguments
///
/// * `target` - The target that generated this finding
/// * `severity` - Severity level of the finding
/// * `title` - Short title describing the finding
/// * `detail` - Detailed explanation with remediation guidance
///
/// # Example
///
/// ```rust
/// use gossan_portscan::finding_builder;
/// use gossan_core::{Target, DomainTarget, DiscoverySource};
/// use secfinding::Severity;
///
/// let target = Target::Domain(DomainTarget {
///     domain: "example.com".into(),
///     source: DiscoverySource::Seed,
/// });
/// let finding = finding_builder(
///     &target,
///     Severity::High,
///     "Test finding",
///     "This is a test finding for demonstration"
/// );
/// ```
pub fn finding_builder(
    target: &Target,
    severity: Severity,
    title: impl Into<String>,
    detail: impl Into<String>,
) -> FindingBuilder {
    Finding::builder("portscan", target.domain().unwrap_or("?"), severity)
        .title(title)
        .detail(detail)
}

#[async_trait]
impl Scanner for PortScanner {
    fn name(&self) -> &'static str {
        "portscan"
    }
    fn tags(&self) -> &[&'static str] {
        &["active", "network"]
    }
    fn accepts(&self, target: &Target) -> bool {
        matches!(target, Target::Domain(_) | Target::Host(_))
    }

    async fn run(&self, input: ScanInput, config: &Config) -> anyhow::Result<ScanOutput> {
        let mut out = ScanOutput::empty();
        let timeout = config.timeout();

        let custom_buf: Vec<u16>;
        let active_ports: &[u16] = match &config.port_mode {
            PortMode::Default => rules::default_ports(),
            PortMode::Top100 => rules::top_100(),
            PortMode::Top1000 => rules::top_1000(),
            PortMode::Full => {
                custom_buf = (1u16..=65535).collect();
                &custom_buf
            }
            PortMode::Custom(ports) => {
                custom_buf = ports.clone();
                &custom_buf
            }
        };

        let pairs: Vec<(String, Option<String>, u16)> = input
            .targets
            .iter()
            .filter(|t| self.accepts(t))
            .flat_map(|t| {
                let (addr, domain) = match t {
                    Target::Domain(d) => (d.domain.clone(), Some(d.domain.clone())),
                    Target::Host(h) => (h.ip.to_string(), h.domain.clone()),
                    _ => unreachable!(),
                };
                active_ports
                    .iter()
                    .map(move |&p| (addr.clone(), domain.clone(), p))
            })
            .collect();

        let results: Vec<Option<(ServiceTarget, Vec<Finding>, Vec<Target>)>> = futures::stream::iter(pairs)
            .map(|(addr, domain, port)| {
                let proxy_opt = config.proxy.clone();
                async move {
                    probe_port(&addr, domain, port, timeout, proxy_opt.as_deref()).await
                }
            })
            .buffer_unordered(config.concurrency)
            .collect()
            .await;

        for item in results.into_iter().flatten() {
            let (svc, findings, extra_targets) = item;
            tracing::debug!(host = ?svc.host.ip, port = svc.port, "open port");
            out.findings.extend(findings);
            out.targets.push(Target::Service(svc));
            out.targets.extend(extra_targets);
        }

        tracing::info!(open = out.targets.len(), "port scan complete");
        Ok(out)
    }
}

async fn probe_port(
    addr: &str,
    domain: Option<String>,
    port: u16,
    timeout: Duration,
    proxy: Option<&str>,
) -> Option<(ServiceTarget, Vec<Finding>, Vec<Target>)> {
    let stream = tokio::time::timeout(timeout, gossan_core::net::connect_tcp(addr, port, proxy))
        .await
        .ok()?
        .ok()?;

    let ip = stream.peer_addr().ok()?.ip();
    let banner = grab_banner(stream, timeout).await;

    let tls = port == 443 || port == 8443 || port == 465 || port == 993 || port == 636;

    let svc = ServiceTarget {
        host: HostTarget {
            ip,
            domain: domain.clone(),
        },
        port,
        protocol: Protocol::Tcp,
        banner: banner.clone(),
        tls,
    };

    let mut findings: Vec<Finding> = Vec::new();
    let mut extra_targets: Vec<Target> = Vec::new();

    // Emit finding for high-risk port exposure
    if let Some(r) = rules::risky_services().iter().find(|r| r.port == port) {
        let target = Target::Service(svc.clone());
        let mut f = finding_builder(&target, r.severity, r.name.clone(), r.detail.clone())
            .tag("exposure")
            .tag("network");
        if let Some(b) = &banner {
            f = f.evidence(Evidence::Banner { raw: b.clone() });
        }
        findings.push(f.build().expect("finding builder: required fields are set"));
    }

    // Banner identification: richer finding for SSH/FTP/SMTP/HTTP/Redis/MongoDB/Telnet.
    // Only replace an existing risky finding if the banner-based finding is at least
    // as severe — prevents an Info-level HTTP Server header from silently discarding
    // a Critical Docker/Kubernetes/Ethereum finding on the same port.
    if let Some(ref b) = banner {
        if let Some(id_finding) = identify_banner(b, &svc, port) {
            let existing_max = findings.iter().map(|f| f.severity).max();
            if existing_max.is_none_or(|max| id_finding.severity >= max) {
                findings.clear();
                findings.push(id_finding);
            } else {
                // Keep the existing higher-severity risky finding; add banner as supplemental
                findings.push(id_finding);
            }
        }
    }

    // TLS cert inspection: extract SANs, check expiry, detect self-signed
    if tls {
        if let Some(cert) = tls::probe_tls(addr, port, timeout, proxy).await {
            let days = tls::days_until_expiry(cert.not_after_unix);
            let target = Target::Service(svc.clone());

            if days < 0 {
                findings.push(
                    finding_builder(&target, Severity::Critical,
                        format!("TLS certificate expired {} days ago", -days),
                        format!("Certificate for port {} expired. Browsers will show security warnings; service may be partially broken.", port))
                    .tag("tls").tag("cert").tag("expired")
                    .build().expect("finding builder: required fields are set"),
                );
            } else if days <= 14 {
                findings.push(
                    finding_builder(&target, Severity::High,
                        format!("TLS certificate expires in {} days", days),
                        format!("Certificate for port {} expires very soon. Immediate renewal required.", port))
                    .tag("tls").tag("cert").tag("expiry")
                    .build().expect("finding builder: required fields are set"),
                );
            } else if days <= 30 {
                findings.push(
                    finding_builder(
                        &target,
                        Severity::Medium,
                        format!("TLS certificate expires in {} days", days),
                        format!("Certificate for port {} expiring within 30 days.", port),
                    )
                    .tag("tls")
                    .tag("cert")
                    .tag("expiry")
                    .build()
                    .expect("finding builder: required fields are set"),
                );
            }

            if cert.is_self_signed {
                findings.push(
                    finding_builder(&target, Severity::Medium,
                        "Self-signed TLS certificate",
                        format!("Port {} uses a self-signed certificate — clients cannot verify authenticity. Possible MITM target.", port))
                    .tag("tls").tag("cert").tag("self-signed")
                    .build().expect("finding builder: required fields are set"),
                );
            }

            // Add SANs as new Domain targets for the rest of the pipeline
            let parent_domain = domain.as_deref().unwrap_or(addr);
            for san in &cert.sans {
                // Only surface SANs that look like subdomains of what we're scanning
                if san != parent_domain
                    && (san.ends_with(&format!(".{}", parent_domain))
                        || parent_domain.ends_with(&format!(".{}", san)))
                {
                    extra_targets.push(Target::Domain(DomainTarget {
                        domain: san.clone(),
                        source: DiscoverySource::CertificateTransparency,
                    }));
                }
            }

            tracing::debug!(port, subject = %cert.subject, issuer = %cert.issuer, sans = ?cert.sans, "TLS cert inspected");
        }

        // Legacy TLS protocol detection — TLS 1.0 (BEAST/POODLE) and TLS 1.1 (deprecated RFC 8996)
        {
            let legacy = tls::probe_legacy(addr, port, timeout, proxy).await;
            let target = Target::Service(svc.clone());
            if legacy.supports_tls10 {
                findings.push(
                    finding_builder(&target, Severity::High,
                        format!("TLS 1.0 supported on port {} — BEAST/POODLE vulnerable", port),
                        format!("Port {} accepts TLS 1.0 connections. TLS 1.0 has known protocol-level \
                                 vulnerabilities (BEAST, POODLE) and was deprecated by RFC 8996. \
                                 Modern clients still negotiate 1.0 as fallback — disable it.", port))
                    .tag("tls").tag("legacy-tls").tag("protocol")
                    .build().expect("finding builder: required fields are set")
                );
            }
            if legacy.supports_tls11 {
                findings.push(
                    finding_builder(&target, Severity::Medium,
                        format!("TLS 1.1 supported on port {} — deprecated (RFC 8996)", port),
                        format!("Port {} accepts TLS 1.1 connections. TLS 1.1 was deprecated alongside \
                                 TLS 1.0 in RFC 8996 (March 2021). Configure the server to require \
                                 TLS 1.2 or higher.", port))
                    .tag("tls").tag("legacy-tls").tag("protocol")
                    .build().expect("finding builder: required fields are set")
                );
            }
        }

        // JARM TLS fingerprint — identifies C2 frameworks, specific server software
        if let Some(fp) = jarm::fingerprint(addr, port, timeout, proxy).await {
            let target = Target::Service(svc.clone());
            let known_tag = jarm::identify(&fp);
            let (severity, title, detail) = if let Some(name) = known_tag {
                (Severity::Critical,
                 format!("JARM fingerprint matches {}", name),
                 format!("TLS fingerprint {} matches known C2/malware framework: {}. Verify — this host may be part of a threat actor's infrastructure.", fp, name))
            } else {
                (
                    Severity::Info,
                    "JARM TLS fingerprint".to_string(),
                    format!("JARM fingerprint: {}  (Shodan: ssl.jarm:{})", fp, fp),
                )
            };
            findings.push(
                finding_builder(&target, severity, title, detail)
                    .tag("jarm")
                    .tag("tls")
                    .tag("fingerprint")
                    .build()
                    .expect("finding builder: required fields are set"),
            );
        }
    }

    // CVE correlation from banner — map service versions to known CVEs
    if let Some(ref b) = banner {
        findings.extend(cve::correlate(b, &svc));
    }

    Some((svc, findings, extra_targets))
}

fn identify_banner(banner: &str, svc: &ServiceTarget, port: u16) -> Option<Finding> {
    let b = banner.to_lowercase();

    // SSH version disclosure
    if b.starts_with("ssh-") || banner.starts_with("SSH-") {
        // e.g. "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
        let version = banner.lines().next().unwrap_or(banner).trim();
        let severity = if version.contains("OpenSSH_7")
            || version.contains("OpenSSH_6")
            || version.contains("OpenSSH_5")
            || version.contains("OpenSSH_4")
        {
            Severity::High
        } else {
            Severity::Info
        };
        return Some(
            finding_builder(
                &Target::Service(svc.clone()),
                severity,
                format!("SSH version disclosed: {}", version),
                "SSH banner reveals server version. Old versions may have known CVEs.",
            )
            .evidence(Evidence::Banner {
                raw: banner.to_string(),
            })
            .tag("banner")
            .tag("ssh")
            .tag("version-disclosure")
            .build()
            .expect("finding builder: required fields are set"),
        );
    }

    // FTP banner
    if (port == 21 || b.contains("ftp")) && (b.starts_with("220") || b.starts_with("230")) {
        let version = banner.lines().next().unwrap_or(banner).trim();
        return Some(
            finding_builder(
                &Target::Service(svc.clone()),
                Severity::Info,
                format!("FTP banner: {}", version),
                "FTP banner may disclose server software and version.",
            )
            .evidence(Evidence::Banner {
                raw: banner.to_string(),
            })
            .tag("banner")
            .tag("ftp")
            .tag("version-disclosure")
            .build()
            .expect("finding builder: required fields are set"),
        );
    }

    // SMTP banner
    if (port == 25 || port == 465 || port == 587) && b.starts_with("220") {
        {
            let version = banner.lines().next().unwrap_or(banner).trim();
            return Some(
                finding_builder(
                    &Target::Service(svc.clone()),
                    Severity::Info,
                    format!("SMTP banner: {}", version),
                    "SMTP banner may disclose mail server software and version.",
                )
                .evidence(Evidence::Banner {
                    raw: banner.to_string(),
                })
                .tag("banner")
                .tag("smtp")
                .tag("version-disclosure")
                .build()
                .expect("finding builder: required fields are set"),
            );
        }
    }

    // HTTP Server header (from raw banner — sometimes visible on plain HTTP)
    if b.starts_with("http/") {
        // Pick out Server: header if present
        let server_line = banner
            .lines()
            .find(|l| l.to_lowercase().starts_with("server:"))
            .unwrap_or("");
        if !server_line.is_empty() {
            return Some(
                finding_builder(
                    &Target::Service(svc.clone()),
                    Severity::Info,
                    format!("HTTP server header: {}", server_line.trim()),
                    "HTTP Server header discloses software and version.",
                )
                .evidence(Evidence::Banner {
                    raw: banner.to_string(),
                })
                .tag("banner")
                .tag("http")
                .tag("version-disclosure")
                .build()
                .expect("finding builder: required fields are set"),
            );
        }
    }

    // Redis inline — usually responds with "-NOAUTH" or "+PONG" or version in INFO
    if port == 6379 && (b.starts_with("+") || b.starts_with("-")) {
        return Some(
            finding_builder(&Target::Service(svc.clone()), Severity::Critical,
                "Redis responds without authentication",
                "Redis accepted connection and responded — likely unauthenticated. Full data access and potential RCE via cron/SSH key write.")
            .evidence(Evidence::Banner { raw: banner.to_string() })
            .tag("banner").tag("redis").tag("no-auth")
            .build().expect("finding builder: required fields are set"),
        );
    }

    // MongoDB — responds with binary, but printable excerpt may contain "MongoDB"
    if port == 27017 && (banner.contains("MongoDB") || banner.contains("ismaster")) {
        return Some(
            finding_builder(
                &Target::Service(svc.clone()),
                Severity::Critical,
                "MongoDB responds — likely unauthenticated",
                "MongoDB accepted connection. May allow unauthenticated full database access.",
            )
            .evidence(Evidence::Banner {
                raw: banner.to_string(),
            })
            .tag("banner")
            .tag("mongodb")
            .tag("no-auth")
            .build()
            .expect("finding builder: required fields are set"),
        );
    }

    // Telnet — any response means it's live
    if port == 23 {
        return Some(
            finding_builder(&Target::Service(svc.clone()), Severity::Critical,
                "Telnet service responds",
                "Telnet is active and responding. All traffic is plaintext — immediate credential interception risk.")
            .evidence(Evidence::Banner { raw: banner.to_string() })
            .tag("banner").tag("telnet").tag("plaintext")
            .build().expect("finding builder: required fields are set"),
        );
    }

    None
}

/// Attempts to grab a service banner from an open TCP connection.
///
/// Reads up to 512 bytes from the stream with an 800ms timeout.
/// Non-printable characters are replaced with '.' for safe display.
///
/// # Arguments
///
/// * `stream` - Connected TCP stream to read from
/// * `timeout` - Maximum duration to wait for data (currently uses 800ms internally)
///
/// # Returns
///
/// Returns `Some(String)` with the sanitized banner if successful,
/// or `None` if the read times out, fails, or returns empty data.
///
/// # Example
///
/// ```rust,no_run
/// use std::time::Duration;
/// use tokio::net::TcpStream;
/// use gossan_portscan::grab_banner;
///
/// async fn example() {
///     if let Ok(stream) = TcpStream::connect("example.com:80").await {
///         if let Some(banner) = grab_banner(stream, Duration::from_secs(5)).await {
///             println!("Banner: {}", banner);
///         }
///     }
/// }
/// ```
pub async fn grab_banner(mut stream: tokio::net::TcpStream, _timeout: Duration) -> Option<String> {
    let mut buf = vec![0u8; 512];
    let n = match tokio::time::timeout(Duration::from_millis(800), stream.read(&mut buf)).await {
        Ok(Ok(n)) => n,
        Ok(Err(e)) => {
            tracing::debug!(error = %e, "failed to read banner from stream");
            return None;
        }
        Err(_) => {
            tracing::debug!("banner grab timed out after 800ms");
            return None;
        }
    };

    if n == 0 {
        tracing::debug!("banner read returned 0 bytes - connection closed immediately");
        return None;
    }

    let s: String = buf[..n]
        .iter()
        .map(|&b| {
            if (0x20..0x7f).contains(&b) {
                b as char
            } else {
                '.'
            }
        })
        .collect::<String>()
        .trim()
        .to_string();

    if s.is_empty() {
        tracing::debug!("banner contained only non-printable characters");
        None
    } else {
        Some(s)
    }
}
#[cfg(test)]
mod tests;
