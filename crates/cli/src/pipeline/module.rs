use gossan_core::WebAssetTarget;
// Pipeline orchestration — streaming, concurrent stages, correlation, checkpoint.
//
// Stage graph:
//
//   Subdomain ──┐
//               ├─ PortScan ──┐
//               │             ├─ TechStack ──┐
//               │             └─ DNS         ├─ JS
//               │                            ├─ Hidden
//               └─────────────────────────── ┘
//   Cloud (runs on all discovered web assets + seed)
//   Correlation (post-scan, runs on full finding set)
//
// Subdomain discovery streams targets via an unbounded channel so that port
// scanning begins as soon as the first subdomain resolves, without waiting
// for all sources to finish.
use std::sync::Arc;

use gossan_core::net::build_resolver;
use gossan_core::{Config, ScanInput, Scanner, Target};
use secfinding::{Finding, Severity};

use super::helpers::{apply_kind_filter, apply_min_severity, dedup, seed_target};

#[cfg(feature = "checkpoint")]
use gossan_checkpoint::CheckpointStore;
#[cfg(feature = "cloud")]
use gossan_cloud::CloudScanner;
#[cfg(feature = "crawl")]
use gossan_crawl::CrawlScanner;
#[cfg(feature = "dns")]
use gossan_dns::DnsScanner;
#[cfg(feature = "engine")]
use gossan_engine::EngineScanner;
#[cfg(feature = "headless")]
use gossan_headless::HeadlessScanner;
#[cfg(feature = "hidden")]
use gossan_hidden::HiddenScanner;
#[cfg(feature = "js")]
use gossan_js::JsScanner;
#[cfg(feature = "portscan")]
use gossan_portscan::PortScanner;
#[cfg(feature = "subdomain")]
use gossan_subdomain::SubdomainScanner;
#[cfg(feature = "techstack")]
use gossan_techstack::TechStackScanner;

// ── Checkpoint helpers ────────────────────────────────────────────────────────

#[cfg(feature = "checkpoint")]
#[allow(dead_code)]
struct Checkpointer {
    store: CheckpointStore,
    scan_id: uuid::Uuid,
}

#[cfg(feature = "checkpoint")]
impl Checkpointer {
    #[allow(dead_code)]
    fn save(&self, stage: &str, targets: &[Target], findings: &[Finding]) {
        if let Err(e) = self
            .store
            .save_stage(self.scan_id, stage, targets, findings)
        {
            tracing::warn!(stage, err = %e, "checkpoint save failed");
        }
    }
}

// ── Full pipeline ─────────────────────────────────────────────────────────────
pub async fn run_module(seed: &str, module: &str, config: Config) -> anyhow::Result<Vec<Finding>> {
    let resolver = Arc::new(build_resolver(&config)?);
    let (in_tx, in_rx) = tokio::sync::mpsc::unbounded_channel();
    let (out_tx, mut out_rx) = tokio::sync::mpsc::unbounded_channel();
    let (live_tx, mut live_rx) = tokio::sync::mpsc::unbounded_channel();

    // Seed the target channel
    let _ = in_tx.send(seed_target(seed));
    drop(in_tx);

    let input = ScanInput {
        seed: seed.to_string(),
        target_rx: tokio::sync::Mutex::new(in_rx),
        live_tx,
        target_tx: out_tx,
        resolver,
    };

    let _ = dispatch_module(module, input, &config).await?;

    let mut findings = Vec::new();
    while let Some(finding) = live_rx.recv().await {
        findings.push(finding);
    }

    let mut out_targets = Vec::new();
    while let Some(t) = out_rx.recv().await {
        out_targets.push(t);
    }

    // For subdomain/portscan/techstack standalone, convert discovered targets to
    // Info findings so the output formatter can display them.
    match module {
        "subdomain" => {
            for target in &out_targets {
                let Target::Domain(d) = target else { continue };
                let source_label = format!("{:?}", d.source)
                    .to_lowercase()
                    .replace("discoverysource::", "");
                gossan_core::try_push_finding(
                    Finding::builder("subdomain", target.domain().unwrap_or("?"), Severity::Info)
                        .title(format!("Subdomain: {}", d.domain))
                        .detail(format!("Discovered via {}", source_label))
                        .kind(secfinding::FindingKind::Exposure)
                        .tag("discovery"),
                    &mut findings,
                );
            }
        }
        "portscan" => {
            for target in &out_targets {
                let Target::Service(s) = target else { continue };
                let scheme = if s.tls { "https" } else { "http" };
                gossan_core::try_push_finding(
                    Finding::builder("portscan", target.domain().unwrap_or("?"), Severity::Info)
                        // Protocol is a small `non_exhaustive` enum
                        // (Tcp | Udp) without an as_str(); use Debug
                        // + lowercase to render `tcp`/`udp`.
                        .title(format!(
                            "Open Port: {}/{}",
                            s.port,
                            format!("{:?}", s.protocol).to_lowercase()
                        ))
                        .detail(format!(
                            "Found open service directly addressing {}",
                            s.host.ip
                        ))
                        .tag(scheme)
                        .kind(secfinding::FindingKind::Exposure),
                    &mut findings,
                );
            }
        }
        "techstack" => {
            for target in &out_targets {
                let Target::Web(w) = target else { continue };
                if w.tech.is_empty() {
                    continue;
                }
                let tech_list = w
                    .tech
                    .iter()
                    .map(|t| t.name.clone())
                    .collect::<Vec<_>>()
                    .join(", ");
                gossan_core::try_push_finding(
                    Finding::builder("techstack", w.url.clone(), Severity::Info)
                        .title(format!("Tech Stack: {}", tech_list))
                        .detail(format!(
                            "Fingerprinted {} distinct technologies",
                            w.tech.len()
                        ))
                        .kind(secfinding::FindingKind::Exposure),
                    &mut findings,
                );
            }
        }
        _ => {}
    }

    // `severity` field is private on the secfinding `Finding` type;
    // use the public `severity()` accessor.
    findings.sort_by(|a, b| b.severity().cmp(&a.severity()));
    findings = dedup(findings);
    findings = apply_min_severity(findings, config.min_severity);
    findings = apply_kind_filter(findings, &config.include_kind, &config.exclude_kind);
    Ok(findings)
}

fn targets_from_stdin() -> Vec<String> {
    scantarget::TargetList::from_stdin()
        .unwrap_or_default()
        .into_iter()
        .map(|t| t.to_string())
        .collect()
}

pub fn resolve_targets(target: String) -> Vec<String> {
    if target == "-" {
        targets_from_stdin()
    } else {
        vec![target]
    }
}

pub async fn exec_module(target: String, module_name: &str, config: Config) -> anyhow::Result<()> {
    let output_config = config.output.clone();
    let targets = resolve_targets(target);
    let mut all = Vec::new();
    for seed in targets {
        all.extend(run_module(&seed, module_name, config.clone()).await?);
    }
    crate::output::print_findings(&all, &output_config);
    Ok(())
}

/// Build synthetic `Target::Service` targets for a domain — used by `techstack`
/// standalone mode, which requires Service targets with web ports.
fn make_service_targets(domain: &str) -> Vec<Target> {
    use gossan_core::{HostTarget, Protocol, ServiceTarget};
    use std::net::{IpAddr, Ipv4Addr};
    let ip = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
    vec![
        Target::Service(ServiceTarget {
            host: HostTarget {
                ip,
                domain: Some(domain.to_string()),
            },
            port: 443,
            protocol: Protocol::Tcp,
            banner: None,
            tls: true,
        }),
        Target::Service(ServiceTarget {
            host: HostTarget {
                ip,
                domain: Some(domain.to_string()),
            },
            port: 80,
            protocol: Protocol::Tcp,
            banner: None,
            tls: false,
        }),
    ]
}

/// Build synthetic `Target::Web` targets for a domain — used by `js` and `hidden`
/// standalone mode, which require  inputs.
fn make_web_targets(domain: &str) -> Vec<Target> {
    use gossan_core::{HostTarget, Protocol, ServiceTarget};
    use std::net::{IpAddr, Ipv4Addr};
    let ip = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
    let mut targets = Vec::new();
    for (port, tls) in [(443u16, true), (80u16, false)] {
        let svc = ServiceTarget {
            host: HostTarget {
                ip,
                domain: Some(domain.to_string()),
            },
            port,
            protocol: Protocol::Tcp,
            banner: None,
            tls,
        };
        if let Some(url) = svc.base_url() {
            targets.push(Target::Web(Box::new(WebAssetTarget {
                url,
                service: svc,
                tech: vec![],
                status: 0,
                title: None,
                favicon_hash: None,
                body_hash: None,
                forms: vec![],
                params: vec![],
            })));
        }
    }
    targets
}

async fn dispatch_module(module: &str, input: ScanInput, config: &Config) -> anyhow::Result<()> {
    let seed = input.seed.clone();
    // Helper for the standalone-module case where the user invoked
    // e.g. `gossan scan --modules hidden example.com` directly. Those
    // scanners need pre-derived Service / Web targets (port 80/443
    // pseudo-services) instead of raw Domain seeds — when they ran
    // inside the full pipeline upstream stages produced those for
    // them, but standalone has to synthesize them here.
    //
    // The pre-streaming API let us mutate `input.targets = vec![…]`;
    // the streaming refactor turned that field into a channel
    // receiver. We rebuild the ScanInput so the target_rx is freshly
    // pre-loaded with the synthetic targets — equivalent semantics,
    // matches the new contract.
    let rebuild_with = |targets: Vec<Target>, prev: ScanInput| -> ScanInput {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<Target>();
        for t in targets {
            let _ = tx.send(t);
        }
        drop(tx);
        ScanInput {
            seed: prev.seed,
            target_rx: tokio::sync::Mutex::new(rx),
            live_tx: prev.live_tx,
            target_tx: prev.target_tx,
            resolver: prev.resolver,
        }
    };
    match module {
        #[cfg(feature = "subdomain")]
        "subdomain" => SubdomainScanner.run(input, config).await,
        #[cfg(feature = "portscan")]
        "portscan" => PortScanner.run(input, config).await,
        #[cfg(feature = "techstack")]
        "techstack" => {
            let input = rebuild_with(make_service_targets(&seed), input);
            TechStackScanner.run(input, config).await
        }
        #[cfg(feature = "dns")]
        "dns" => DnsScanner.run(input, config).await,
        #[cfg(feature = "js")]
        "js" => {
            let input = rebuild_with(make_web_targets(&seed), input);
            JsScanner.run(input, config).await
        }
        #[cfg(feature = "hidden")]
        "hidden" => {
            let input = rebuild_with(make_web_targets(&seed), input);
            HiddenScanner.run(input, config).await
        }
        #[cfg(feature = "cloud")]
        "cloud" => CloudScanner.run(input, config).await,
        #[cfg(feature = "headless")]
        "headless" => {
            let input = rebuild_with(make_web_targets(&seed), input);
            HeadlessScanner.run(input, config).await
        }
        #[cfg(feature = "crawl")]
        "crawl" => {
            let input = rebuild_with(make_web_targets(&seed), input);
            CrawlScanner.run(input, config).await
        }
        #[cfg(feature = "horizontal")]
        "horizontal" => {
            if config.conservative {
                gossan_horizontal::conservative::ConservativeScanner
                    .run(input, config)
                    .await
            } else {
                gossan_horizontal::HorizontalScanner
                    .run(input, config)
                    .await
            }
        }
        #[cfg(feature = "scm")]
        "scm" => gossan_scm::ScmScanner.run(input, config).await,
        #[cfg(feature = "intel")]
        "intel" => {
            let scanner = gossan_intel::IntelScanner::new("santh_intel.db")?;
            scanner.run(input, config).await
        }
        #[cfg(feature = "engine")]
        "engine" => gossan_engine::EngineScanner::new().run(input, config).await,
        other => anyhow::bail!("unknown or uncompiled module: {}", other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipeline::helpers::dedup_web_assets;
    use gossan_core::Target;
    use secfinding::{Evidence, Finding, Severity};
    use url::Url;

    fn finding(title: &str, severity: Severity) -> Finding {
        Finding::builder("test", "example.com", severity)
            .title(title.to_string())
            .detail("detail".to_string())
            .build()
            .expect("finding builder: required fields are set")
    }

    #[test]
    fn dedup_keeps_first() {
        let a = finding("SQL injection", Severity::High);
        let b = finding("SQL injection", Severity::High);
        let c = finding("XSS", Severity::Medium);
        let r = dedup(vec![a, b, c]);
        assert_eq!(r.len(), 2);
    }

    #[test]
    fn dedup_case_insensitive() {
        let a = finding("SQL Injection", Severity::High);
        let b = finding("sql injection", Severity::High);
        assert_eq!(dedup(vec![a, b]).len(), 1);
    }

    #[test]
    fn dedup_keeps_findings_with_distinct_evidence_scope() {
        let a = Finding::builder("test", "example.com", Severity::High)
            .title("SQL injection")
            .detail("param id")
            .evidence(Evidence::Raw("GET /?id=1".into()))
            .build()
            .expect("finding builder: required fields are set");
        let b = Finding::builder("test", "example.com", Severity::High)
            .title("SQL injection")
            .detail("param user_id")
            .evidence(Evidence::Raw("GET /?user_id=1".into()))
            .build()
            .expect("finding builder: required fields are set");

        assert_eq!(dedup(vec![a, b]).len(), 2);
    }

    #[test]
    fn min_severity_filters() {
        let findings = vec![
            finding("info", Severity::Info),
            finding("high", Severity::High),
            finding("critical", Severity::Critical),
        ];
        let r = apply_min_severity(findings, Some(Severity::High));
        assert_eq!(r.len(), 2);
    }

    #[test]
    fn make_service_targets_produces_port_80_and_443() {
        let targets = make_service_targets("example.com");
        assert_eq!(targets.len(), 2);
        let ports: Vec<u16> = targets
            .iter()
            .filter_map(|t| {
                if let Target::Service(s) = t {
                    Some(s.port)
                } else {
                    None
                }
            })
            .collect();
        assert!(ports.contains(&443), "should include port 443");
        assert!(ports.contains(&80), "should include port 80");
        // Both should carry the correct domain
        for t in &targets {
            if let Target::Service(s) = t {
                assert_eq!(s.host.domain.as_deref(), Some("example.com"));
            }
        }
    }

    #[test]
    fn dedup_web_assets_keeps_distinct_hostnames() {
        use gossan_core::{HostTarget, Protocol, ServiceTarget};
        use std::net::{IpAddr, Ipv4Addr};

        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10));
        let service = ServiceTarget {
            host: HostTarget {
                ip,
                domain: Some("a.example.com".into()),
            },
            port: 443,
            protocol: Protocol::Tcp,
            banner: None,
            tls: true,
        };
        let first = Target::Web(Box::new(WebAssetTarget {
            url: Url::parse("https://a.example.com").unwrap(),
            service: service.clone(),
            tech: vec![],
            status: 200,
            title: None,
            favicon_hash: None,
            body_hash: Some("same".into()),
            forms: vec![],
            params: vec![],
        }));
        let second = Target::Web(Box::new(WebAssetTarget {
            url: Url::parse("https://b.example.com").unwrap(),
            service: ServiceTarget {
                host: HostTarget {
                    ip,
                    domain: Some("b.example.com".into()),
                },
                ..service
            },
            tech: vec![],
            status: 200,
            title: None,
            favicon_hash: None,
            body_hash: Some("same".into()),
            forms: vec![],
            params: vec![],
        }));

        assert_eq!(dedup_web_assets(vec![first, second]).len(), 1);
    }

    #[test]
    fn make_web_targets_produces_http_and_https() {
        let targets = make_web_targets("example.com");
        assert_eq!(targets.len(), 2);
        let schemes: Vec<&str> = targets
            .iter()
            .filter_map(|t| {
                if let Target::Web(w) = t {
                    Some(w.url.scheme())
                } else {
                    None
                }
            })
            .collect();
        assert!(schemes.contains(&"https"), "should include https target");
        assert!(schemes.contains(&"http"), "should include http target");
        // URLs should point at the correct host
        for t in &targets {
            if let Target::Web(w) = t {
                assert_eq!(w.url.host_str(), Some("example.com"));
            }
        }
    }
}
