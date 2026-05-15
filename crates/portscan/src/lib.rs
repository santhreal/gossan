#![forbid(unsafe_code)]
// pedantic moved to workspace [lints.clippy] in root Cargo.toml
//
// `expect_used` is intentionally ALLOWED inside this crate — every
// `.expect()` site is on `Mutex::lock()` and the message is the
// documented invariant ("portscan completed_ports mutex poisoned").
// `unwrap_used` / `todo` / `unimplemented` / `panic` stay forbidden.
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::todo,
        clippy::unimplemented,
        clippy::panic
    )
)]
#![allow(
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::missing_errors_doc,
)]

//! TCP connect scanner with banner grabbing, active service probing,
//! TLS inspection (JA3/JA3S, cert chain, cipher weakness), rate limiting,
//! IPv6 support, and checkpoint resume.
//!
//! # Configuration
//!
//! Port lists, service probes, and risky service definitions are loaded from TOML:
//! - `rules/top_ports.toml` — port list definitions
//! - `rules/risky_services.toml` — high-risk service definitions
//! - `rules/service_probes.toml` — active service probe payloads (~200+)

pub mod cdn;
pub mod cve;
pub mod jarm;
pub mod probes;
pub mod rules;
pub mod tls;
pub mod top_ports;

#[cfg(test)]
mod integration_tests;

use std::fmt;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use futures::StreamExt;
use gossan_core::{
    Config, DiscoverySource, DomainTarget, HostTarget, PortMode, Protocol, ScanInput, Scanner,
    ServiceTarget, Target,
};
use secfinding::{Evidence, Finding, FindingBuilder, Severity};
use tokio::io::AsyncReadExt;

/// TCP port scanner with banner grabbing, TLS inspection, and CVE correlation.
pub struct PortScanner;

impl Default for PortScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl PortScanner {
    /// Creates a new port scanner instance.
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
pub fn finding_builder(
    target: &Target,
    severity: Severity,
    title: impl Into<String>,
    detail: impl Into<String>,
) -> FindingBuilder {
    Finding::builder("portscan", target.domain().unwrap_or("?"), severity)
        .title(title)
        .detail(detail)
        .kind(secfinding::FindingKind::Exposure)
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
        matches!(
            target,
            Target::Domain(_) | Target::Host(_) | Target::Network(_)
        )
    }

    async fn run(&self, input: ScanInput, config: &Config) -> anyhow::Result<()> {
        let timeout = config.timeout();
        let host_delay = Duration::from_millis(config.host_delay_ms);
        let rate_limiter = Arc::new(gossan_core::ratelimit::HostRateLimiter::new(
            config.rate_limit.max(1),
        ));

        // Drain all targets from the channel
        let mut all_input_targets = Vec::new();
        {
            let mut rx = input.target_rx.lock().await;
            while let Ok(t) = rx.try_recv() {
                all_input_targets.push(t);
            }
        }
        let mut expanded_targets = Vec::new();
        for t in &all_input_targets {
            if let Target::Network(net) = t {
                if let Ok(prefix) = net.cidr.parse::<ipnet::IpNet>() {
                    let max_hosts: usize = 256;
                    let total_hosts = prefix.hosts().count();
                    if total_hosts > max_hosts {
                        if let Some(f) = finding_builder(
                            &Target::Network(net.clone()),
                            Severity::Info,
                            format!(
                                "CIDR range {} truncated: scanning {}/{} hosts",
                                net.cidr, max_hosts, total_hosts
                            ),
                            format!(
                                "Network {} contains {} hosts but scanning is limited to {} per range. \
                                 {} hosts will NOT be scanned. Split into /24 subnets for full coverage.",
                                net.cidr, total_hosts, max_hosts, total_hosts - max_hosts
                            ),
                        )
                        .tag("cidr")
                        .tag("truncation")
                        .kind(secfinding::FindingKind::InfoDisclosure)
                        .build_or_log()
                        {
                            input.emit(f);
                        }
                    }
                    for addr in prefix.hosts().take(max_hosts) {
                        expanded_targets.push(Target::Host(HostTarget {
                            ip: addr,
                            domain: None,
                        }));
                    }
                }
            } else {
                expanded_targets.push(t.clone());
            }
        }

        let active_ports: Vec<u16> = match &config.port_mode {
            PortMode::Default => rules::default_ports().to_vec(),
            PortMode::Top100 => rules::top_100().to_vec(),
            PortMode::Top1000 => rules::top_1000().to_vec(),
            PortMode::Full => (1u16..=65535).collect(),
            PortMode::Custom(ports) => ports.clone(),
        };

        // ── Resume support: load checkpoint if available ─────────────────────
        let completed_ports: Arc<std::sync::Mutex<std::collections::HashSet<(IpAddr, u16)>>> =
            Arc::new(std::sync::Mutex::new(std::collections::HashSet::new()));
        let checkpoint_path = std::env::var("GOSSAN_CHECKPOINT")
            .ok()
            .map(std::path::PathBuf::from)
            .or_else(|| Some(std::path::PathBuf::from("gossan-scan.db")));

        if let Some(ref path) = checkpoint_path {
            if path.exists() {
                // Touch the CheckpointStore as a structural soundness
                // check (corrupted DB → don't try to resume), then read
                // the per-portscan sidecar JSON. The portscan resume
                // contract is intentionally side-cared off the main
                // store: per-(IpAddr, u16) granularity would inflate
                // the SQLite write rate to one row per probed port,
                // which dominated wall time on previous benchmarks.
                if gossan_checkpoint::CheckpointStore::open(path).is_ok() {
                    if let Ok(content) = std::fs::read_to_string(
                        path.with_extension("portscan-resume.json"),
                    ) {
                        if let Ok(ports) =
                            serde_json::from_str::<Vec<(IpAddr, u16)>>(&content)
                        {
                            completed_ports.lock().expect("portscan completed_ports mutex poisoned").extend(ports);
                            tracing::info!(
                                resumed = completed_ports.lock().expect("portscan completed_ports mutex poisoned").len(),
                                "resuming portscan from checkpoint"
                            );
                        }
                    }
                }
            }
        }

        let pairs: Vec<(String, Option<String>, u16, IpAddr)> = expanded_targets
            .iter()
            .filter(|t| self.accepts(t))
            .flat_map(|t| {
                let (addr, domain, ip) = match t {
                    Target::Domain(d) => (d.domain.clone(), Some(d.domain.clone()), None),
                    Target::Host(h) => (h.ip.to_string(), h.domain.clone(), Some(h.ip)),
                    _ => return Vec::new(),
                };
                active_ports
                    .iter()
                    .filter({
                        let completed_ports = Arc::clone(&completed_ports);
                        move |&&p| {
                        if let Some(ip) = ip {
                            !completed_ports.lock().expect("portscan completed_ports mutex poisoned").contains(&(ip, p))
                        } else {
                            true
                        }
                        }
                    })
                    .map(move |&p| {
                        let ip = ip.unwrap_or_else(|| {
                            // placeholder; resolved later
                            IpAddr::from([0, 0, 0, 0])
                        });
                        (addr.clone(), domain.clone(), p, ip)
                    })
                    .collect::<Vec<_>>()
            })
            .collect();

        let open_count = Arc::new(AtomicUsize::new(0));
        let probe_engine = Arc::new(probes::ProbeEngine::new(timeout));

        let results: Vec<Option<(ServiceTarget, Vec<Finding>, Vec<Target>)>> =
            futures::stream::iter(pairs)
                .map(|(addr, domain, port, ip)| {
                    let rl = Arc::clone(&rate_limiter);
                    let proxy_opt = config.proxy.clone();
                    let engine = Arc::clone(&probe_engine);
                    let open_count = Arc::clone(&open_count);
                    let completed_ports = Arc::clone(&completed_ports);
                    async move {
                        // Per-host rate limiting
                        rl.until_ready(&addr).await;
                        tokio::time::sleep(host_delay).await;

                        let result = retry_probe(
                            &addr,
                            domain.clone(),
                            port,
                            timeout,
                            proxy_opt.as_deref(),
                            &engine,
                        )
                        .await;

                        // Mark this (ip, port) pair complete REGARDLESS
                        // of result. Resume semantics are "we already
                        // probed this once" — the result (open / closed
                        // / filtered) doesn't change whether we should
                        // re-probe on resume. Without this, the loaded
                        // completed_ports set was treated read-only and
                        // every resumed run re-scanned every port from
                        // scratch — exactly the bug the warning on the
                        // unused `ip` variable was concealing.
                        completed_ports.lock().expect("portscan completed_ports mutex poisoned").insert((ip, port));

                        if let Some((ref svc, _, _)) = result {
                            tracing::debug!(host = ?svc.host.ip, port = svc.port, "open port");
                            open_count.fetch_add(1, Ordering::Relaxed);
                        }
                        result
                    }
                })
                .buffer_unordered(config.concurrency)
                .collect()
                .await;

        // ── Extract the seed's root domain for SAN filtering ─────────────────
        let seed_root = extract_root_domain(&input.seed);

        for item in results.into_iter().flatten() {
            let (svc, findings, extra_targets) = item;
            for f in findings {
                input.emit(f);
            }
            input.emit_target(Target::Service(svc));

            for t in extra_targets {
                if let Target::Domain(ref d) = t {
                    let san_root = extract_root_domain(&d.domain);
                    if san_root == seed_root
                        || d.domain.ends_with(&format!(".{}", input.seed))
                        || input.seed.ends_with(&format!(".{}", d.domain))
                    {
                        input.emit_target(t);
                    } else {
                        tracing::debug!(
                            san = %d.domain,
                            seed = %input.seed,
                            "filtered out-of-scope SAN domain"
                        );
                    }
                } else {
                    input.emit_target(t);
                }
            }
        }

        // ── Save checkpoint ──────────────────────────────────────────────────
        if let Some(path) = checkpoint_path {
            let resume_file = path.with_extension("portscan-resume.json");
            let _ = std::fs::write(
                &resume_file,
                serde_json::to_string(&completed_ports.lock().expect("portscan completed_ports mutex poisoned").iter().collect::<Vec<_>>())?,
            );
        }

        tracing::info!(
            open = open_count.load(Ordering::Relaxed),
            "port scan complete"
        );
        Ok(())
    }
}

async fn retry_probe(
    addr: &str,
    domain: Option<String>,
    port: u16,
    timeout: Duration,
    proxy: Option<&str>,
    engine: &probes::ProbeEngine,
) -> Option<(ServiceTarget, Vec<Finding>, Vec<Target>)> {
    const MAX_RETRIES: u32 = 3;
    for attempt in 0..MAX_RETRIES {
        match probe_port(addr, domain.clone(), port, timeout, proxy, engine).await {
            Some(result) => return Some(result),
            None if attempt + 1 < MAX_RETRIES => {
                let delay = Duration::from_millis(200 * 2u64.pow(attempt));
                tokio::time::sleep(delay).await;
            }
            None => return None,
        }
    }
    None
}

async fn probe_port(
    addr: &str,
    domain: Option<String>,
    port: u16,
    timeout: Duration,
    proxy: Option<&str>,
    engine: &probes::ProbeEngine,
) -> Option<(ServiceTarget, Vec<Finding>, Vec<Target>)> {
    let stream = tokio::time::timeout(
        timeout,
        gossan_core::net::connect_tcp(addr, port, proxy),
    )
    .await
    .ok()?
    .ok()?;

    let ip = stream.peer_addr().ok()?.ip();

    // Run banner grab and active probes in parallel under a shared deadline
    let deadline = timeout.max(Duration::from_secs(5));
    let probe_future = engine.probe(stream, addr, port, proxy);
    let (banner, probe_matches) = match tokio::time::timeout(deadline, probe_future).await {
        Ok((b, m)) => (b, m),
        Err(_) => (None, Vec::new()),
    };

    let tls = port == 443
        || port == 8443
        || port == 465
        || port == 993
        || port == 636
        || port == 995
        || port == 587;

    let svc = ServiceTarget {
        host: HostTarget { ip, domain },
        port,
        protocol: Protocol::Tcp,
        banner: banner.clone(),
        tls,
    };

    let mut findings: Vec<Finding> = Vec::new();
    let mut extra_targets: Vec<Target> = Vec::new();

    // Emit finding for high-risk port exposure (require banner confirmation)
    if let Some(r) = rules::risky_services().iter().find(|r| r.port == port) {
        let target = Target::Service(svc.clone());
        let severity = if banner.is_none() {
            Severity::Low // downgrade if we can't confirm the service
        } else {
            r.severity
        };
        // Structured tags so the masscan-grepable renderer can pick
        // out the IP / port / proto / service hint without parsing
        // the human-readable title. The hint is derived from the
        // banner via the same logic the cli uses for grepable output.
        let svc_hint = banner.as_deref().and_then(|b| {
            // Keep this in sync with cli::output::classify_service_hint.
            let bl = b.to_ascii_lowercase();
            if bl.starts_with("ssh-") || port == 22 {
                Some("ssh")
            } else if bl.contains("http/") || matches!(port, 80 | 8080 | 8000 | 8888) {
                Some("http")
            } else if matches!(port, 443 | 8443) {
                Some("https")
            } else if bl.starts_with("220 ") && (bl.contains("smtp") || port == 25) {
                Some("smtp")
            } else if bl.starts_with("220") && port == 21 {
                Some("ftp")
            } else if port == 6379 || bl.contains("noauth") {
                Some("redis")
            } else if port == 27017 || bl.contains("mongodb") {
                Some("mongodb")
            } else {
                None
            }
        });
        let mut f = finding_builder(&target, severity, r.name.clone(), r.detail.clone())
            .tag("exposure")
            .tag("network")
            .tag(format!("ip:{ip}"))
            .tag(format!("port:{port}/tcp"));
        if let Some(s) = svc_hint {
            f = f.tag(format!("service:{s}"));
        }
        if let Some(ref b) = banner {
            f = f.evidence(Evidence::Banner { raw: b.clone().into() });
        }
        gossan_core::try_push_finding(f, &mut findings);
    }

    // Banner / probe identification
    let combined_banner = banner.as_deref().unwrap_or("");
    if let Some(id_finding) = identify_banner_or_probe(combined_banner, &probe_matches, &svc, port)
    {
        let existing_max = findings.iter().map(|f| f.severity()).max();
        if existing_max.is_none_or(|max| id_finding.severity() >= max) {
            findings.clear();
            findings.push(id_finding);
        } else {
            findings.push(id_finding);
        }
    }

    // TLS cert inspection (parallelized)
    if tls {
        let tls_deadline = timeout.max(Duration::from_secs(8));
        let tls_future = async {
            let mut all_findings = Vec::new();
            if let Some(cert) = tls::probe_tls(addr, port, timeout, proxy).await {
                let days = tls::days_until_expiry(cert.not_after_unix);
                let target = Target::Service(svc.clone());

                if days < 0 {
                    gossan_core::try_push_finding(
                        finding_builder(
                            &target,
                            Severity::Critical,
                            format!("TLS certificate expired {} days ago", -days),
                            format!(
                                "Certificate for port {} expired. Browsers will show security warnings.",
                                port
                            ),
                        )
                        .tag("tls")
                        .tag("cert")
                        .tag("expired")
                        .kind(secfinding::FindingKind::Misconfiguration),
                        &mut all_findings,
                    );
                } else if days <= 14 {
                    gossan_core::try_push_finding(
                        finding_builder(
                            &target,
                            Severity::High,
                            format!("TLS certificate expires in {} days", days),
                            format!(
                                "Certificate for port {} expires very soon. Immediate renewal required.",
                                port
                            ),
                        )
                        .tag("tls")
                        .tag("cert")
                        .tag("expiry")
                        .kind(secfinding::FindingKind::Misconfiguration),
                        &mut all_findings,
                    );
                } else if days <= 30 {
                    gossan_core::try_push_finding(
                        finding_builder(
                            &target,
                            Severity::Medium,
                            format!("TLS certificate expires in {} days", days),
                            format!("Certificate for port {} expiring within 30 days.", port),
                        )
                        .tag("tls")
                        .tag("cert")
                        .tag("expiry"),
                        &mut all_findings,
                    );
                }

                if cert.is_self_signed {
                    gossan_core::try_push_finding(
                        finding_builder(
                            &target,
                            Severity::Medium,
                            "Self-signed TLS certificate",
                            format!(
                                "Port {} uses a self-signed certificate — clients cannot verify authenticity.",
                                port
                            ),
                        )
                        .tag("tls")
                        .tag("cert")
                        .tag("self-signed")
                        .kind(secfinding::FindingKind::Misconfiguration),
                        &mut all_findings,
                    );
                }

                // Note: cipher_weakness and negotiated_version removed from TlsCertInfo


                for san in &cert.sans {
                    let san = san.trim_start_matches("*.").to_string();
                    if !san.is_empty() {
                        extra_targets.push(Target::Domain(DomainTarget {
                            domain: san,
                            source: DiscoverySource::CertificateTransparency,
                        }));
                    }
                }

                tracing::debug!(
                    port,
                    subject = %cert.subject,
                    issuer = %cert.issuer,
                    sans = ?cert.sans,
                    "TLS cert inspected"
                );
            }

            // Legacy TLS protocol detection
            let legacy = tls::probe_legacy(addr, port, timeout, proxy).await;
            let target = Target::Service(svc.clone());
            if legacy.supports_tls10 {
                gossan_core::try_push_finding(
                    finding_builder(
                        &target,
                        Severity::High,
                        format!("TLS 1.0 supported on port {} — BEAST/POODLE vulnerable", port),
                        format!(
                            "Port {} accepts TLS 1.0 connections. TLS 1.0 has known protocol-level \
                             vulnerabilities (BEAST, POODLE) and was deprecated by RFC 8996.",
                            port
                        ),
                    )
                    .tag("tls")
                    .tag("legacy-tls")
                    .tag("protocol")
                    .kind(secfinding::FindingKind::Misconfiguration),
                    &mut all_findings,
                );
            }
            if legacy.supports_tls11 {
                gossan_core::try_push_finding(
                    finding_builder(
                        &target,
                        Severity::Medium,
                        format!("TLS 1.1 supported on port {} — deprecated (RFC 8996)", port),
                        format!(
                            "Port {} accepts TLS 1.1 connections. TLS 1.1 was deprecated alongside \
                             TLS 1.0 in RFC 8996 (March 2021). Configure the server to require \
                             TLS 1.2 or higher.",
                            port
                        ),
                    )
                    .tag("tls")
                    .tag("legacy-tls")
                    .tag("protocol")
                    .kind(secfinding::FindingKind::Misconfiguration),
                    &mut all_findings,
                );
            }

            all_findings
        };

        let tls_results = tokio::time::timeout(tls_deadline, tls_future).await.unwrap_or_default();
        findings.extend(tls_results);

        // JARM (optional, default off)
        let jarm_enabled = std::env::var("GOSSAN_JARM")
            .map(|s| s == "1" || s == "true")
            .unwrap_or(false);
        if jarm_enabled {
            if let Some(fp) = jarm::fingerprint(addr, port, timeout, proxy).await {
                let target = Target::Service(svc.clone());
                let known_tag = jarm::identify(&fp);
                let (severity, title, detail) = if let Some(name) = known_tag {
                    (
                        Severity::Critical,
                        format!("JARM fingerprint matches {}", name),
                        format!(
                            "TLS fingerprint {} matches known C2/malware framework: {}.",
                            fp, name
                        ),
                    )
                } else {
                    (
                        Severity::Info,
                        "JARM TLS fingerprint".to_string(),
                        format!("JARM fingerprint: {}  (Shodan: ssl.jarm:{})", fp, fp),
                    )
                };
                gossan_core::try_push_finding(
                    finding_builder(&target, severity, title, detail)
                        .tag("jarm")
                        .tag("tls")
                        .tag("fingerprint")
                        .kind(secfinding::FindingKind::TechDetect),
                    &mut findings,
                );
            }
        }
    }

    // CVE correlation from banner + probe responses
    let banner_for_cve = if banner.is_some() {
        banner.as_deref().unwrap_or("").to_string()
    } else {
        probe_matches.join(" | ")
    };
    if !banner_for_cve.is_empty() {
        findings.extend(cve::correlate(&banner_for_cve, &svc));
    }

    Some((svc, findings, extra_targets))
}

fn identify_banner_or_probe(
    banner: &str,
    probe_matches: &[String],
    svc: &ServiceTarget,
    port: u16,
) -> Option<Finding> {
    let b = banner.to_lowercase();

    // SSH version disclosure
    if b.starts_with("ssh-") || banner.starts_with("SSH-") {
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
                raw: banner.to_string().into(),
            })
            .tag("banner")
            .tag("ssh")
            .tag("version-disclosure")
            .kind(secfinding::FindingKind::InfoDisclosure)
            .build()
            .ok()?,
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
                raw: banner.to_string().into(),
            })
            .tag("banner")
            .tag("ftp")
            .tag("version-disclosure")
            .kind(secfinding::FindingKind::InfoDisclosure)
            .build()
            .ok()?,
        );
    }

    // SMTP banner
    if (port == 25 || port == 465 || port == 587) && b.starts_with("220") {
        let version = banner.lines().next().unwrap_or(banner).trim();
        return Some(
            finding_builder(
                &Target::Service(svc.clone()),
                Severity::Info,
                format!("SMTP banner: {}", version),
                "SMTP banner may disclose mail server software and version.",
            )
            .evidence(Evidence::Banner {
                raw: banner.to_string().into(),
            })
            .tag("banner")
            .tag("smtp")
            .tag("version-disclosure")
            .kind(secfinding::FindingKind::InfoDisclosure)
            .build()
            .ok()?,
        );
    }

    // HTTP Server header
    if b.starts_with("http/") {
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
                    raw: banner.to_string().into(),
                })
                .tag("banner")
                .tag("http")
                .tag("version-disclosure")
                .build()
                .ok()?,
            );
        }
    }

    // Redis
    if port == 6379 && (b.starts_with('+') || b.starts_with('-')) {
        return Some(
            finding_builder(
                &Target::Service(svc.clone()),
                Severity::Critical,
                "Redis responds without authentication",
                "Redis accepted connection and responded — likely unauthenticated. Full data access and potential RCE via cron/SSH key write.",
            )
            .evidence(Evidence::Banner { raw: banner.to_string().into() })
            .tag("banner")
            .tag("redis")
            .tag("no-auth")
            .kind(secfinding::FindingKind::Vulnerability)
            .build()
            .ok()?,
        );
    }

    // MongoDB
    if port == 27017 && (banner.contains("MongoDB") || b.contains("ismaster")) {
        return Some(
            finding_builder(
                &Target::Service(svc.clone()),
                Severity::Critical,
                "MongoDB responds — likely unauthenticated",
                "MongoDB accepted connection. May allow unauthenticated full database access.",
            )
            .evidence(Evidence::Banner {
                raw: banner.to_string().into(),
            })
            .tag("banner")
            .tag("mongodb")
            .tag("no-auth")
            .kind(secfinding::FindingKind::Vulnerability)
            .build()
            .ok()?,
        );
    }

    // Telnet
    if port == 23 {
        return Some(
            finding_builder(
                &Target::Service(svc.clone()),
                Severity::Critical,
                "Telnet service responds",
                "Telnet is active and responding. All traffic is plaintext — immediate credential interception risk.",
            )
            .evidence(Evidence::Banner { raw: banner.to_string().into() })
            .tag("banner")
            .tag("telnet")
            .tag("plaintext")
            .kind(secfinding::FindingKind::Vulnerability)
            .build()
            .ok()?,
        );
    }

    // Elasticsearch
    if (port == 9200 || port == 9300)
        && (b.contains("lucene")
            || b.contains("elasticsearch")
            || b.contains("\"cluster_name\""))
    {
        return Some(
            finding_builder(
                &Target::Service(svc.clone()),
                Severity::Critical,
                "Elasticsearch responds — likely unauthenticated",
                format!(
                    "Elasticsearch on port {} accepted connection and returned cluster info. \
                     Unauthenticated access allows full index enumeration, data exfiltration, \
                     and potential RCE via script queries.",
                    port
                ),
            )
            .evidence(Evidence::Banner { raw: banner.to_string().into() })
            .tag("banner")
            .tag("elasticsearch")
            .tag("no-auth")
            .kind(secfinding::FindingKind::Vulnerability)
            .build()
            .ok()?,
        );
    }

    // PostgreSQL
    if port == 5432
        && (banner.contains("PostgreSQL")
            || b.contains("pgsql")
            || b.contains("pg_hba.conf"))
    {
        let severity = if b.contains("no pg_hba.conf entry") {
            Severity::Info
        } else {
            Severity::High
        };
        return Some(
            finding_builder(
                &Target::Service(svc.clone()),
                severity,
                "PostgreSQL service responds",
                format!(
                    "PostgreSQL on port {} is accepting connections.",
                    port
                ),
            )
            .evidence(Evidence::Banner { raw: banner.to_string().into() })
            .tag("banner")
            .tag("postgresql")
            .tag("database")
            .kind(secfinding::FindingKind::Exposure)
            .build()
            .ok()?,
        );
    }

    // MySQL
    if port == 3306
        && (banner.contains("mysql")
            || b.contains("mariadb")
            || b.contains("caching_sha2"))
    {
        return Some(
            finding_builder(
                &Target::Service(svc.clone()),
                Severity::High,
                format!("MySQL/MariaDB responds on port {}", port),
                format!(
                    "MySQL on port {} is accepting connections. Direct database port exposure \
                     enables brute-force attacks and version-specific CVE exploitation.",
                    port
                ),
            )
            .evidence(Evidence::Banner { raw: banner.to_string().into() })
            .tag("banner")
            .tag("mysql")
            .tag("database")
            .kind(secfinding::FindingKind::Exposure)
            .build()
            .ok()?,
        );
    }

    // Memcached
    if port == 11211 && (b.starts_with("stat") || b.starts_with("version") || b.starts_with("error"))
    {
        return Some(
            finding_builder(
                &Target::Service(svc.clone()),
                Severity::Critical,
                "Memcached responds — likely unauthenticated",
                "Memcached on port 11211 accepted connection. Unauthenticated access allows full \
                 cache dump, data injection, and DDoS amplification (UDP reflection).",
            )
            .evidence(Evidence::Banner { raw: banner.to_string().into() })
            .tag("banner")
            .tag("memcached")
            .tag("no-auth")
            .kind(secfinding::FindingKind::Vulnerability)
            .build()
            .ok()?,
        );
    }

    // Kubernetes API
    if (port == 6443 || port == 443 || port == 8443)
        && b.contains("\"kind\"")
        && (b.contains("status") || b.contains("api"))
    {
        let severity = if b.contains("forbidden") || b.contains("unauthorized") {
            Severity::Medium
        } else {
            Severity::Critical
        };
        return Some(
            finding_builder(
                &Target::Service(svc.clone()),
                severity,
                format!("Kubernetes API server detected on port {}", port),
                format!(
                    "Kubernetes API responding on port {}. {} access may expose cluster \
                     configuration, secrets, and allow container escape.",
                    port,
                    if severity == Severity::Critical {
                        "Unauthenticated"
                    } else {
                        "Authenticated"
                    }
                ),
            )
            .evidence(Evidence::Banner { raw: banner.to_string().into() })
            .tag("banner")
            .tag("kubernetes")
            .tag("api")
            .kind(secfinding::FindingKind::Exposure)
            .build()
            .ok()?,
        );
    }

    // Probe-based matches (from active probes)
    for m in probe_matches {
        return Some(
            finding_builder(
                &Target::Service(svc.clone()),
                Severity::Info,
                format!("Service detected via active probe: {}", m),
                "An active service probe returned a positive match.",
            )
            .tag("banner")
            .tag("probe")
            .kind(secfinding::FindingKind::TechDetect)
            .build()
            .ok()?,
        );
    }

    None
}

/// Attempts to grab a service banner from an open TCP connection.
pub async fn grab_banner(mut stream: tokio::net::TcpStream, timeout: Duration) -> Option<String> {
    let mut buf = vec![0u8; 512];
    let effective_timeout = timeout.max(Duration::from_millis(100));
    let n = match tokio::time::timeout(effective_timeout, stream.read(&mut buf)).await {
        Ok(Ok(n)) => n,
        Ok(Err(e)) => {
            tracing::debug!(error = %e, "failed to read banner from stream");
            return None;
        }
        Err(_) => {
            tracing::debug!("banner grab timed out");
            return None;
        }
    };

    if n == 0 {
        tracing::debug!("banner read returned 0 bytes - connection closed immediately");
        return None;
    }

    let s: String = buf[..n]
        .iter()
        .map(|&b| if (0x20..0x7f).contains(&b) { b as char } else { '.' })
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

/// Extract the registrable root domain from a full domain name.
fn extract_root_domain(domain: &str) -> String {
    let domain = domain.trim_end_matches('.').to_lowercase();
    // Fast path for simple cases
    if domain.is_empty() {
        return domain;
    }
    // Pure fallback: last two labels (or three for known two-part TLDs)
    // No external publicsuffix crate dependency needed.
    let parts: Vec<&str> = domain.split('.').collect();
    if parts.len() <= 2 {
        return domain;
    }
    let last_two = format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1]);
    last_two
}

#[cfg(test)]
mod tests;
