//! Pipeline orchestration — streaming, concurrent stages, correlation, checkpoint.
//!
//! Stage graph:
//!
//!   Subdomain ──┐
//!               ├─ PortScan ──┐
//!               │             ├─ TechStack ──┐
//!               │             └─ DNS         ├─ JS
//!               │                            ├─ Hidden
//!               └─────────────────────────── ┘
//!   Cloud (runs on all discovered web assets + seed)
//!   Correlation (post-scan, runs on full finding set)
//!
//! Subdomain discovery streams targets via an unbounded channel so that port
//! scanning begins as soon as the first subdomain resolves, without waiting
//! for all sources to finish.
use std::collections::HashSet;
use std::time::Duration;

use gossan_core::{Config, DiscoverySource, DomainTarget, ScanInput, Scanner, Target};
use secfinding::{Finding, Severity};

#[cfg(feature = "checkpoint")]
use gossan_checkpoint::CheckpointStore;
#[cfg(feature = "cloud")]
use gossan_cloud::CloudScanner;
#[cfg(feature = "correlation")]
use gossan_correlation::CorrelationEngine;
#[cfg(feature = "crawl")]
use gossan_crawl::CrawlScanner;
#[cfg(feature = "dns")]
use gossan_dns::DnsScanner;
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
#[cfg(feature = "synscan")]
use gossan_synscan::SynScanner;
#[cfg(feature = "techstack")]
use gossan_techstack::TechStackScanner;

use indicatif::{MultiProgress, ProgressBar, ProgressStyle};

// ── Helpers ──────────────────────────────────────────────────────────────────

fn seed_target(seed: &str) -> Target {
    Target::Domain(DomainTarget {
        domain: seed
            .trim_start_matches("http://")
            .trim_start_matches("https://")
            .trim_end_matches('/')
            .split('/')
            .next()
            .unwrap_or(seed)
            .to_string(),
        source: DiscoverySource::Seed,
    })
}

fn spinner(mp: &MultiProgress, msg: &str) -> ProgressBar {
    let pb = mp.add(ProgressBar::new_spinner());
    pb.set_style(
        ProgressStyle::with_template("{spinner:.cyan} {msg}")
            .expect("valid spinner template")
            .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏", " "]),
    );
    pb.enable_steady_tick(Duration::from_millis(80));
    pb.set_message(msg.to_string());
    pb
}

fn finish(pb: &ProgressBar, msg: &str) {
    pb.set_style(
        ProgressStyle::with_template("  \x1b[32m✓\x1b[0m {msg}").expect("valid finish template"),
    );
    pb.finish_with_message(msg.to_string());
}

fn dedup(mut findings: Vec<Finding>) -> Vec<Finding> {
    let mut seen = HashSet::new();
    findings.retain(|f| {
        seen.insert(format!(
            "{}|{}|{}",
            f.scanner,
            f.target.as_str(),
            f.title.to_lowercase()
        ))
    });
    findings
}

fn apply_min_severity(findings: Vec<Finding>, min: Option<Severity>) -> Vec<Finding> {
    match min {
        None => findings,
        Some(min) => findings.into_iter().filter(|f| f.severity >= min).collect(),
    }
}

/// Deduplicate structurally identical web assets to prevent scanning the same CDN edge 50 times
fn dedup_web_assets(targets: Vec<Target>) -> Vec<Target> {
    let mut seen = HashSet::new();
    targets
        .into_iter()
        .filter(|t| {
            if let Target::Web(w) = t {
                // Unique signature: IP + Port + Status + BodyHash
                let ip = w.service.host.ip;
                let port = w.service.port;
                let hash = w.body_hash.as_deref().unwrap_or("nohash");
                let key = format!("{}:{}-{}-{}", ip, port, w.status, hash);
                seen.insert(key)
            } else {
                true
            }
        })
        .collect()
}

fn broadcast(tx: &tokio::sync::mpsc::UnboundedSender<Finding>, findings: &[Finding]) {
    for f in findings {
        let _ = tx.send(f.clone());
    }
}

// ── Checkpoint helpers ────────────────────────────────────────────────────────

#[cfg(feature = "checkpoint")]
struct Checkpointer {
    store: CheckpointStore,
    scan_id: uuid::Uuid,
}

#[cfg(feature = "checkpoint")]
impl Checkpointer {
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

#[allow(unused_variables)]
pub async fn run_full(
    seed: &str,
    config: Config,
    checkpoint_path: Option<&str>,
    resume_id: Option<&str>,
) -> anyhow::Result<Vec<Finding>> {
    let mp = MultiProgress::new();
    {
        let h = mp.add(ProgressBar::new_spinner());
        h.set_style(ProgressStyle::with_template("\n  \x1b[1m{msg}\x1b[0m").expect("ok"));
        h.finish_with_message(format!("gossan · {}", seed));
    }

    // ── Checkpoint init ───────────────────────────────────────────────────
    #[cfg(feature = "checkpoint")]
    let checkpointer: Option<Checkpointer> = match checkpoint_path {
        Some(path) => {
            let store = CheckpointStore::open(path)?;
            let scan_id = if let Some(rid) = resume_id {
                uuid::Uuid::parse_str(rid)?
            } else {
                let config_json = serde_json::to_string(&config).unwrap_or_default();
                let id = store.new_scan(seed, &config_json)?;
                tracing::info!(scan_id = %id, "checkpoint created — use --resume {} to continue if interrupted", id);
                id
            };
            Some(Checkpointer { store, scan_id })
        }
        None => None,
    };

    // ── Restore checkpoint ────────────────────────────────────────────────
    #[cfg(feature = "checkpoint")]
    let checkpoint_record = if let (Some(cp), Some(rid)) = (&checkpointer, resume_id) {
        let id = uuid::Uuid::parse_str(rid)?;
        Some(cp.store.load(id)?)
    } else {
        None
    };
    #[cfg(not(feature = "checkpoint"))]
    let checkpoint_record: Option<()> = None;

    macro_rules! restored {
        ($stage:expr) => {{
            #[cfg(feature = "checkpoint")]
            {
                checkpoint_record.as_ref().and_then(|r| r.stage($stage))
            }
            #[cfg(not(feature = "checkpoint"))]
            {
                None::<()>
            }
        }};
    }

    /// Abstracted Stage Runner macro ensuring absolute consistency across the ecosystem pipeline.
    macro_rules! run_standard_stage {
        ($id:expr, $desc:expr, $scanner:expr, $input_targets:expr, $fmt:expr, $all_f:ident, $all_t:ident, $tx:ident) => {{
            if let Some(_r) = restored!($id) {
                #[cfg(feature = "checkpoint")]
                {
                    tracing::info!("{}: restored from checkpoint ({} targets)", $id, _r.targets.len());
                    $all_f.extend(_r.findings.clone());
                    $all_t.extend(_r.targets.clone());
                }
            } else {
                let pb = spinner(&mp, $desc);
                let out = $scanner.run(
                    ScanInput {
                        seed: seed.to_string(),
                        targets: $input_targets,
                        live_tx: Some($tx.clone()),
                        target_tx: None,
                    },
                    &config,
                ).await?;
                let (t_len, f_len) = (out.targets.len(), out.findings.len());
                broadcast(&$tx, &out.findings);
                #[cfg(feature = "checkpoint")]
                if let Some(cp) = &checkpointer {
                    cp.save($id, &out.targets, &out.findings);
                }
                $all_f.extend(out.findings);
                $all_t.extend(out.targets);
                finish(&pb, &$fmt(t_len, f_len));
            }
        }};
    }

    // ── Live Critical/High stream ─────────────────────────────────────────
    let (live_tx, mut live_rx) = tokio::sync::mpsc::unbounded_channel::<Finding>();
    let mp_live = mp.clone();
    tokio::spawn(async move {
        while let Some(f) = live_rx.recv().await {
            if f.severity >= Severity::High {
                let label = match f.severity {
                    Severity::Critical => "\x1b[31;1m[CRIT]\x1b[0m",
                    _ => "\x1b[31m[HIGH]\x1b[0m",
                };
                let _ = mp_live.println(format!(
                    "  {} \x1b[1m{}\x1b[0m  \x1b[90m[{}]\x1b[0m",
                    label, f.title, f.target
                ));
            }
        }
    });

    let mut all_findings: Vec<Finding> = Vec::new();
    let mut all_targets: Vec<Target> = vec![seed_target(seed)];

    // ── Stage 1: Subdomain (streaming) ───────────────────────────────────
    #[cfg(feature = "subdomain")]
    if config.modules.subdomain {
        run_standard_stage!(
            "subdomain",
            "subdomain  · CT · CertSpotter · Wayback · HackerTarget · RapidDNS · OTX · Urlscan · CommonCrawl · bruteforce",
            SubdomainScanner,
            all_targets.clone(),
            |t, _| format!("subdomain  → {t} host{}", if t == 1 { "" } else { "s" }),
            all_findings,
            all_targets,
            live_tx
        );
    }

    // ── Stage 2: Port scan ────────────────────────────────────────────────
    #[cfg(feature = "portscan")]
    if config.modules.portscan {
        let t = all_targets.iter().filter(|t| matches!(t, Target::Domain(_) | Target::Host(_))).count();
        run_standard_stage!(
            "portscan",
            &format!("portscan   · {t} host{}", if t == 1 { "" } else { "s" }),
            PortScanner,
            all_targets.clone(),
            |svcs, nf| format!("portscan   → {svcs} open port{}  ({nf} finding{})", if svcs == 1 { "" } else { "s" }, if nf == 1 { "" } else { "s" }),
            all_findings,
            all_targets,
            live_tx
        );
    }

    // ── Stage 2.5: SYN scan ────────────────────────────────────────────────
    #[cfg(feature = "synscan")]
    if config.modules.synscan {
        let t = all_targets.iter().filter(|t| matches!(t, Target::Domain(_) | Target::Host(_))).count();
        run_standard_stage!(
            "synscan",
            &format!("synscan    · {t} host{}", if t == 1 { "" } else { "s" }),
            SynScanner,
            all_targets.clone(),
            |svcs, nf| format!("synscan    → {svcs} open port{}  ({nf} finding{})", if svcs == 1 { "" } else { "s" }, if nf == 1 { "" } else { "s" }),
            all_findings,
            all_targets,
            live_tx
        );
    }

    // ── Stage 3: TechStack + DNS (concurrent) ────────────────────────────
    let run_tech = cfg!(feature = "techstack") && config.modules.techstack;
    let run_dns = cfg!(feature = "dns") && config.modules.dns;

    let pb_tech = if run_tech {
        Some(spinner(
            &mp,
            "techstack  · fingerprinting + security headers",
        ))
    } else {
        None
    };
    let pb_dns = if run_dns {
        Some(spinner(
            &mp,
            "dns        · SPF / DMARC / DKIM / CAA / takeover",
        ))
    } else {
        None
    };

    let targets_for_tech = all_targets.clone();
    let targets_for_dns = all_targets.clone();
    let seed_s = seed.to_string();
    let config_c = config.clone();
    let live_tx_c = live_tx.clone();

    let (tech_out, dns_out) = tokio::join!(
        async {
            #[cfg(feature = "techstack")]
            if config_c.modules.techstack {
                if let Some(_r) = restored!("techstack") {
                    #[cfg(feature = "checkpoint")]
                    {
                        tracing::info!("techstack: restored from checkpoint");
                        return Ok(gossan_core::ScanOutput {
                            targets: _r.targets.clone(),
                            findings: _r.findings.clone(),
                        });
                    }
                }
                return TechStackScanner
                    .run(
                        ScanInput {
                            seed: seed_s.clone(),
                            targets: targets_for_tech,
                            live_tx: Some(live_tx_c.clone()),
                            target_tx: None,
                        },
                        &config_c,
                    )
                    .await;
            }
            Ok(gossan_core::ScanOutput::empty())
        },
        async {
            #[cfg(feature = "dns")]
            if config.modules.dns {
                if let Some(_r) = restored!("dns") {
                    #[cfg(feature = "checkpoint")]
                    {
                        tracing::info!("dns: restored from checkpoint");
                        return Ok(gossan_core::ScanOutput {
                            targets: _r.targets.clone(),
                            findings: _r.findings.clone(),
                        });
                    }
                }
                return DnsScanner
                    .run(
                        ScanInput {
                            seed: seed.to_string(),
                            targets: targets_for_dns,
                            live_tx: Some(live_tx.clone()),
                            target_tx: None,
                        },
                        &config,
                    )
                    .await;
            }
            Ok::<gossan_core::ScanOutput, anyhow::Error>(gossan_core::ScanOutput::empty())
        },
    );
    let tech_out = tech_out?;
    let dns_out = dns_out?;

    if let Some(pb) = &pb_tech {
        finish(
            pb,
            &format!(
                "techstack  → {} web asset{}  ({} finding{})",
                tech_out.targets.len(),
                if tech_out.targets.len() == 1 { "" } else { "s" },
                tech_out.findings.len(),
                if tech_out.findings.len() == 1 {
                    ""
                } else {
                    "s"
                }
            ),
        );
    }
    if let Some(pb) = &pb_dns {
        finish(
            pb,
            &format!(
                "dns        → {} finding{}",
                dns_out.findings.len(),
                if dns_out.findings.len() == 1 { "" } else { "s" }
            ),
        );
    }

    broadcast(&live_tx, &tech_out.findings);
    broadcast(&live_tx, &dns_out.findings);
    #[cfg(feature = "checkpoint")]
    if let Some(cp) = &checkpointer {
        cp.save("techstack", &tech_out.targets, &tech_out.findings);
        cp.save("dns", &dns_out.targets, &dns_out.findings);
    }
    all_findings.extend(tech_out.findings);
    all_findings.extend(dns_out.findings);
    let raw_web_targets: Vec<Target> = tech_out.targets;
    let web_targets = dedup_web_assets(raw_web_targets.clone());

    if web_targets.len() < raw_web_targets.len() {
        tracing::info!(
            "deduplicated {} identical web assets into {} unique structural roots",
            raw_web_targets.len(),
            web_targets.len()
        );
    }

    all_targets.extend(web_targets.clone());

    // ── Stage 4: JS + Hidden (concurrent, on web assets) ─────────────────
    let run_js = cfg!(feature = "js") && config.modules.js;
    let run_hidden = cfg!(feature = "hidden") && config.modules.hidden;

    let pb_js = if run_js {
        Some(spinner(&mp, "js         · endpoints + secrets"))
    } else {
        None
    };
    let pb_hidden = if run_hidden {
        Some(spinner(&mp, "hidden     · 50+ paths"))
    } else {
        None
    };

    let (js_out, hidden_out) = tokio::join!(
        async {
            #[cfg(feature = "js")]
            if config.modules.js {
                if let Some(_r) = restored!("js") {
                    #[cfg(feature = "checkpoint")]
                    {
                        tracing::info!("js: restored from checkpoint");
                        return Ok(gossan_core::ScanOutput {
                            targets: _r.targets.clone(),
                            findings: _r.findings.clone(),
                        });
                    }
                }
                return JsScanner
                    .run(
                        ScanInput {
                            seed: seed.to_string(),
                            targets: web_targets.clone(),
                            live_tx: Some(live_tx.clone()),
                            target_tx: None,
                        },
                        &config,
                    )
                    .await;
            }
            Ok::<gossan_core::ScanOutput, anyhow::Error>(gossan_core::ScanOutput::empty())
        },
        async {
            #[cfg(feature = "hidden")]
            if config.modules.hidden {
                if let Some(_r) = restored!("hidden") {
                    #[cfg(feature = "checkpoint")]
                    {
                        tracing::info!("hidden: restored from checkpoint");
                        return Ok(gossan_core::ScanOutput {
                            targets: _r.targets.clone(),
                            findings: _r.findings.clone(),
                        });
                    }
                }
                return HiddenScanner
                    .run(
                        ScanInput {
                            seed: seed.to_string(),
                            targets: web_targets.clone(),
                            live_tx: Some(live_tx.clone()),
                            target_tx: None,
                        },
                        &config,
                    )
                    .await;
            }
            Ok::<gossan_core::ScanOutput, anyhow::Error>(gossan_core::ScanOutput::empty())
        },
    );
    let js_out = js_out?;
    let hidden_out = hidden_out?;

    if let Some(pb) = &pb_js {
        finish(
            pb,
            &format!(
                "js         → {} finding{}",
                js_out.findings.len(),
                if js_out.findings.len() == 1 { "" } else { "s" }
            ),
        );
    }
    if let Some(pb) = &pb_hidden {
        finish(
            pb,
            &format!(
                "hidden     → {} finding{}",
                hidden_out.findings.len(),
                if hidden_out.findings.len() == 1 {
                    ""
                } else {
                    "s"
                }
            ),
        );
    }
    broadcast(&live_tx, &js_out.findings);
    broadcast(&live_tx, &hidden_out.findings);
    #[cfg(feature = "checkpoint")]
    if let Some(cp) = &checkpointer {
        cp.save("js", &js_out.targets, &js_out.findings);
        cp.save("hidden", &hidden_out.targets, &hidden_out.findings);
    }
    all_findings.extend(js_out.findings);
    all_findings.extend(hidden_out.findings);

    // ── Stage 4.5: Headless (concurrently executing full browser analysis on web assets)
    #[cfg(feature = "headless")]
    if config.modules.headless {
        // Run standard stage requires identical lengths for args, headless only produces findings so we ignore targets
        run_standard_stage!(
            "headless",
            "headless   · dom-rendering and xhr trapping",
            HeadlessScanner,
            web_targets.clone(),
            |_, nf| format!("headless   → {nf} finding{}", if nf == 1 { "" } else { "s" }),
            all_findings,
            all_targets,
            live_tx
        );
    }

    // ── Stage 4.6: Crawl (authenticated crawling, form extraction, param discovery)
    #[cfg(feature = "crawl")]
    if config.modules.crawl {
        run_standard_stage!(
            "crawl",
            "crawl      · forms + params + link following",
            CrawlScanner,
            web_targets.clone(),
            |nt, nf| format!("crawl      → {nt} page{}  ({nf} form{})", if nt == 1 { "" } else { "s" }, if nf == 1 { "" } else { "s" }),
            all_findings,
            all_targets,
            live_tx
        );
    }

    // ── Stage 5: Cloud ────────────────────────────────────────────────────
    #[cfg(feature = "cloud")]
    if config.modules.cloud {
        run_standard_stage!(
            "cloud",
            "cloud      · S3 / GCS / Azure / DO Spaces",
            CloudScanner,
            all_targets.clone(),
            |_, nf| format!("cloud      → {nf} finding{}", if nf == 1 { "" } else { "s" }),
            all_findings,
            all_targets,
            live_tx
        );
    }

    drop(live_tx);

    // ── Correlation engine ────────────────────────────────────────────────
    #[cfg(feature = "correlation")]
    {
        let engine = CorrelationEngine::new();
        let chains = engine.run(&all_findings, &all_targets);
        if !chains.is_empty() {
            let pb = mp.add(ProgressBar::new_spinner());
            pb.set_style(ProgressStyle::with_template("  \x1b[32m✓\x1b[0m {msg}").expect("ok"));
            pb.finish_with_message(format!(
                "correlation → {} attack chain{}",
                chains.len(),
                if chains.len() == 1 { "" } else { "s" }
            ));
        }
        all_findings.extend(chains);
    }

    // ── Finalise ──────────────────────────────────────────────────────────
    all_findings.sort_by(|a, b| b.severity.cmp(&a.severity));
    all_findings = dedup(all_findings);
    all_findings = apply_min_severity(all_findings, config.min_severity);

    let total = mp.add(ProgressBar::new_spinner());
    total.set_style(ProgressStyle::with_template("\n  {msg}").expect("ok"));
    total.finish_with_message(format!(
        "\x1b[1m{} finding{} total\x1b[0m",
        all_findings.len(),
        if all_findings.len() == 1 { "" } else { "s" }
    ));

    Ok(all_findings)
}

// ── Single-module runner ──────────────────────────────────────────────────────

pub async fn run_module(seed: &str, module: &str, config: Config) -> anyhow::Result<Vec<Finding>> {
    let input = ScanInput {
        seed: seed.to_string(),
        targets: vec![seed_target(seed)],
        live_tx: None,
        target_tx: None,
    };
    let out = dispatch_module(module, input, &config).await?;
    let mut findings = out.findings;

    // For subdomain/portscan/techstack standalone, convert discovered targets to
    // Info findings so the output formatter can display them.
    match module {
        "subdomain" => {
            for target in &out.targets {
                let Target::Domain(d) = target else { continue };
                let source_label = format!("{:?}", d.source)
                    .to_lowercase()
                    .replace("discoverysource::", "");
                findings.push(
                    Finding::builder("subdomain", target.domain().unwrap_or("?"), Severity::Info)
                        .title(format!("Subdomain: {}", d.domain))
                        .detail(format!("Discovered via {}", source_label))
                        .tag("subdomain")
                        .tag("discovery")
                        .build()
                        .expect("finding builder: required fields are set"),
                );
            }
        }
        "portscan" => {
            for target in &out.targets {
                let Target::Service(s) = target else { continue };
                let host = s
                    .host
                    .domain
                    .as_deref()
                    .unwrap_or(&s.host.ip.to_string())
                    .to_string();
                let proto = if s.tls { "TLS" } else { "TCP" };
                findings.push(
                    Finding::builder("portscan", target.domain().unwrap_or("?"), Severity::Info)
                        .title(format!("Open port: {}:{} ({})", host, s.port, proto))
                        .detail(s.banner.as_deref().unwrap_or("no banner").to_string())
                        .tag("open-port")
                        .tag("discovery")
                        .build()
                        .expect("finding builder: required fields are set"),
                );
            }
        }
        _ => {}
    }

    findings.sort_by(|a, b| b.severity.cmp(&a.severity));
    findings = dedup(findings);
    findings = apply_min_severity(findings, config.min_severity);
    Ok(findings)
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
/// standalone mode, which require WebAssetTarget inputs.
fn make_web_targets(domain: &str) -> Vec<Target> {
    use gossan_core::{HostTarget, Protocol, ServiceTarget, WebAssetTarget};
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

async fn dispatch_module(
    module: &str,
    input: ScanInput,
    config: &Config,
) -> anyhow::Result<gossan_core::ScanOutput> {
    let seed = input.seed.clone();
    match module {
        #[cfg(feature = "subdomain")]
        "subdomain" => SubdomainScanner.run(input, config).await,
        #[cfg(feature = "portscan")]
        "portscan" => PortScanner.run(input, config).await,
        #[cfg(feature = "techstack")]
        "techstack" => {
            let mut input = input;
            input.targets = make_service_targets(&seed);
            TechStackScanner.run(input, config).await
        }
        #[cfg(feature = "dns")]
        "dns" => DnsScanner.run(input, config).await,
        #[cfg(feature = "js")]
        "js" => {
            let mut input = input;
            input.targets = make_web_targets(&seed);
            JsScanner.run(input, config).await
        }
        #[cfg(feature = "hidden")]
        "hidden" => {
            let mut input = input;
            input.targets = make_web_targets(&seed);
            HiddenScanner.run(input, config).await
        }
        #[cfg(feature = "cloud")]
        "cloud" => CloudScanner.run(input, config).await,
        #[cfg(feature = "synscan")]
        "synscan" => SynScanner.run(input, config).await,
        #[cfg(feature = "headless")]
        "headless" => {
            let mut input = input;
            input.targets = make_web_targets(&seed);
            HeadlessScanner.run(input, config).await
        }
        #[cfg(feature = "crawl")]
        "crawl" => {
            let mut input = input;
            input.targets = make_web_targets(&seed);
            CrawlScanner.run(input, config).await
        }
        other => anyhow::bail!("unknown or uncompiled module: {}", other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gossan_core::{DiscoverySource, DomainTarget, Target};
    use secfinding::{Finding, Severity};

    fn finding(title: &str, severity: Severity) -> Finding {
        let _ = Target::Domain(DomainTarget {
            domain: "example.com".into(),
            source: DiscoverySource::Seed,
        });
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
