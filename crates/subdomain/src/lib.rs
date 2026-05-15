#![forbid(unsafe_code)]
// pedantic moved to workspace [lints.clippy] in root Cargo.toml
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::todo,
        clippy::unimplemented,
        clippy::panic
    )
)]
#![allow(
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::missing_errors_doc
)]

//! Subdomain discovery — 80+ concurrent sources + DNS bruteforce + permutation engine.
//!
//! Sources (no API key): crt.sh, CertSpotter, Wayback Machine, HackerTarget,
//!                        RapidDNS, AlienVault OTX, Urlscan.io, CommonCrawl, DNSdumpster,
//!                        Anubis, BufferOver, Robtex, DNSRepo, and 30+ more.
//! Sources (API key):   VirusTotal, SecurityTrails, Shodan, Censys, BinaryEdge,
//!                        FullHunt, GitHub, Chaos, Bevigil, FOFA, Hunter.io, Netlas,
//!                        ZoomEye, C99, Quake, ThreatBook, IntelX, LeakIX, WhoisXML,
//!                        and 15+ more.
//!
//! Every confirmed target is emitted via `input.emit_target()` immediately
//! so the port scanner can start while subdomain discovery is still running.

pub mod dedup;
pub mod sources;
pub mod wildcard;

mod bruteforce;
mod permutations;

use std::collections::HashSet;
use std::sync::Arc;

use async_trait::async_trait;
use gossan_core::{Config, ScanInput, Scanner, Target};
use secfinding::{Evidence, Finding, Severity};
use tokio::sync::Mutex;

use crate::dedup::normalize_domain;
use crate::sources::{all_sources, SubdomainSource};
use crate::wildcard::detect_wildcards;

/// Downstream emitter wrapper — cloneable so it can be moved into spawned tasks.
#[derive(Clone)]
struct Emitter {
    live_tx: tokio::sync::mpsc::UnboundedSender<Finding>,
    target_tx: tokio::sync::mpsc::UnboundedSender<Target>,
}

impl Emitter {
    fn emit_target(&self, t: Target) {
        let _ = self.target_tx.send(t);
    }
    fn emit_finding(&self, f: Finding) {
        let _ = self.live_tx.send(f);
    }
}

impl From<&ScanInput> for Emitter {
    fn from(input: &ScanInput) -> Self {
        Self {
            live_tx: input.live_tx.clone(),
            target_tx: input.target_tx.clone(),
        }
    }
}

/// Multi-source subdomain enumeration and brute-force scanner.
pub struct SubdomainScanner;

#[async_trait]
impl Scanner for SubdomainScanner {
    fn name(&self) -> &'static str {
        "subdomain"
    }
    fn tags(&self) -> &[&'static str] {
        &["active", "dns", "discovery"]
    }
    fn accepts(&self, target: &Target) -> bool {
        matches!(target, Target::Domain(_))
    }

    async fn run(&self, input: ScanInput, config: &Config) -> anyhow::Result<()> {
        let client = gossan_core::ScanClient::from_config(config, Arc::clone(&input.resolver))?;
        let sources = Arc::new(all_sources());
        let emitter = Emitter::from(&input);

        // Drain all targets from the channel
        let mut all_targets = Vec::new();
        {
            let mut rx = input.target_rx.lock().await;
            while let Ok(t) = rx.try_recv() {
                all_targets.push(t);
            }
        }

        for target in &all_targets {
            let Target::Domain(d) = target else { continue };
            tracing::info!(domain = %d.domain, sources = sources.len(), "subdomain scan");

            let wildcard_ips = detect_wildcards(&d.domain, &input.resolver, 5).await;
            if !wildcard_ips.is_empty() {
                tracing::warn!(domain = %d.domain, ips = ?wildcard_ips, "wildcard DNS detected");
            }

            let seen = Arc::new(Mutex::new(HashSet::<String>::new()));
            let mut tasks = Vec::new();

            // Spawn all passive sources
            for i in 0..sources.len() {
                let sources = Arc::clone(&sources);
                let domain = d.domain.clone();
                let client = client.clone();
                let config = config.clone();
                let emitter = emitter.clone();
                let seen = Arc::clone(&seen);
                let limiter = sources[i].rate_limit().build_limiter();
                let source_name = sources[i].name();
                let discovery = sources[i].discovery_source();

                tasks.push(tokio::spawn(async move {
                    match sources[i].query(&domain, &config, &client, &limiter).await {
                        Ok(targets) => {
                            for mut t in targets {
                                // Rewrite discovery source to the canonical one for this source
                                if let Target::Domain(ref mut dt) = t {
                                    dt.source = discovery.clone();
                                }
                                if let Some(dom) = t.domain() {
                                    if let Some(norm) = normalize_domain(dom) {
                                        if seen.lock().await.insert(norm) {
                                            emitter.emit_target(t);
                                        }
                                    }
                                }
                            }
                        }
                        Err(err) => {
                            tracing::warn!(source = source_name, domain, err = %err, "subdomain source error");
                            let severity = if config.api_keys.contains_key(source_name) {
                                Severity::High
                            } else {
                                Severity::Medium
                            };
                            if let Some(finding) = Finding::builder("subdomain", &domain, severity)
                                .title(format!("Subdomain source failed: {source_name}"))
                                .detail(format!(
                                    "Passive source {source_name} failed while enumerating {domain}. \
                                     Fix: inspect connectivity, credentials, and upstream throttling. Error: {err}"
                                ))
                                .kind(secfinding::FindingKind::Other)
                                .tag("subdomain")
                                .tag("source-error")
                                .evidence(Evidence::Raw(err.to_string().into()))
                                .build_or_log()
                            {
                                emitter.emit_finding(finding);
                            }
                        }
                    }
                }));
            }

            // Spawn bruteforce with wildcard filtering
            let domain_bf = d.domain.clone();
            let config_bf = config.clone();
            let resolver_bf = Arc::clone(&input.resolver);
            let emitter_bf = emitter.clone();
            let seen_bf = Arc::clone(&seen);
            let wildcard_ips_bf = wildcard_ips.clone();
            tasks.push(tokio::spawn(async move {
                match bruteforce::scan(
                    &domain_bf,
                    &config_bf,
                    Some(emitter_bf.target_tx.clone()),
                    resolver_bf,
                    Some(&wildcard_ips_bf),
                )
                .await
                {
                    Ok(targets) => {
                        for mut t in targets {
                            if let Target::Domain(ref mut dt) = t {
                                dt.source = gossan_core::DiscoverySource::DnsBruteforce;
                            }
                            if let Some(dom) = t.domain() {
                                if let Some(norm) = normalize_domain(dom) {
                                    if seen_bf.lock().await.insert(norm) {
                                        emitter_bf.emit_target(t);
                                    }
                                }
                            }
                        }
                    }
                    Err(err) => {
                        tracing::warn!(source = "bruteforce", domain = domain_bf, err = %err, "bruteforce error");
                    }
                }
            }));

            // Wait for all tasks; failure isolation is automatic because each task is independent.
            for task in tasks {
                let _ = task.await;
            }

            // Collect currently seen domains for permutation input
            let current_seen: Vec<Target> = {
                let locked = seen.lock().await;
                locked
                    .iter()
                    .map(|dom| {
                        Target::Domain(gossan_core::DomainTarget {
                            domain: dom.clone(),
                            source: gossan_core::DiscoverySource::PassiveDns,
                        })
                    })
                    .collect()
            };

            // Permutation expansion with wildcard-aware resolver
            match permutations::expand(
                &current_seen,
                &d.domain,
                config,
                &wildcard_ips,
                &input.resolver,
            )
            .await
            {
                Ok(perms) => {
                    for mut t in perms {
                        if let Target::Domain(ref mut dt) = t {
                            dt.source = gossan_core::DiscoverySource::DnsBruteforce;
                        }
                        if let Some(dom) = t.domain() {
                            if let Some(norm) = normalize_domain(dom) {
                                if seen.lock().await.insert(norm) {
                                    emitter.emit_target(t);
                                }
                            }
                        }
                    }
                }
                Err(e) => tracing::warn!(err = %e, "permutation expansion error"),
            }
        }

        tracing::info!("subdomain scan complete");
        Ok(())
    }
}

/// Returns `true` if `candidate` is a direct subdomain of `domain`.
pub(crate) fn is_subdomain_of(candidate: &str, domain: &str) -> bool {
    let candidate = candidate.trim_end_matches('.');
    let domain = domain.trim_end_matches('.');
    candidate
        .strip_suffix(domain)
        .is_some_and(|prefix| prefix.ends_with('.'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use gossan_core::{DiscoverySource, DomainTarget};

    fn domain_target(domain: &str) -> Target {
        Target::Domain(DomainTarget {
            domain: domain.into(),
            source: DiscoverySource::Seed,
        })
    }

    #[test]
    fn scanner_accepts_only_domain_targets() {
        let scanner = SubdomainScanner;
        assert!(scanner.accepts(&domain_target("example.com")));
        assert!(!scanner.accepts(&Target::Host(gossan_core::HostTarget {
            ip: "127.0.0.1".parse().unwrap(),
            domain: None,
        })));
    }

    #[test]
    fn is_subdomain_of_requires_label_boundary() {
        assert!(is_subdomain_of("api.example.com", "example.com"));
        assert!(!is_subdomain_of("badexample.com", "example.com"));
        assert!(!is_subdomain_of("example.com", "example.com"));
    }
}
