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

//! Subdomain discovery: 80+ concurrent sources + DNS bruteforce + permutation engine.
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

pub mod bruteforce;
mod permutations;

#[cfg(test)]
mod hermetic_dns;
#[cfg(test)]
mod hermetic_tests;

use std::collections::HashSet;
use std::sync::Arc;

use async_trait::async_trait;
use gossan_core::{Config, ScanInput, Scanner, Target};
use secfinding::{Evidence, Finding, Severity};
use tokio::sync::{Mutex, Semaphore};

use crate::dedup::normalize_domain;
use crate::sources::{all_sources, SubdomainSource};
use crate::wildcard::detect_wildcards;

/// Maximum number of passive sources that may query concurrently per domain.
/// This cap prevents thundering-herd DNS bursts and respects per-source rate limits.
const MAX_CONCURRENT_SOURCES: usize = 16;
/// Hard deadline per passive source. Sources that exceed this are
/// cancelled and reported as unhealthy so one dead endpoint cannot
/// hang the entire scan past operator patience.
const SOURCE_TIMEOUT_SECS: u64 = 30;

/// Downstream emitter wrapper (cloneable so it can be moved into spawned tasks).
#[derive(Clone)]
struct Emitter {
    live_tx: tokio::sync::mpsc::Sender<Finding>,
    target_tx: tokio::sync::mpsc::Sender<Target>,
}

impl Emitter {
    async fn emit_target(&self, t: Target) {
        if let Err(e) = self.target_tx.send(t).await {
            tracing::error!(err = %e, "failed to emit target (channel closed)");
        }
    }
    async fn emit_finding(&self, f: Finding) {
        if let Err(e) = self.live_tx.send(f).await {
            tracing::error!(err = %e, "failed to emit finding (channel closed)");
        }
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
        self.run_with_sources(input, config, all_sources()).await
    }
}

impl SubdomainScanner {
    /// Run the scanner with an explicit list of sources (useful for tests).
    pub async fn run_with_sources(
        &self,
        input: ScanInput,
        config: &Config,
        sources: Vec<Box<dyn SubdomainSource>>,
    ) -> anyhow::Result<()> {
        let client = gossan_core::ScanClient::from_config(config, Arc::clone(&input.resolver))?;
        let sources = Arc::new(sources);
        let emitter = Emitter::from(&input);

        // Drain all targets from the channel
        let mut all_targets = Vec::new();
        {
            let mut rx = input.target_rx.lock().await;
            // recv() until the pipeline closes the inbox — try_recv races the
            // sender and drops asynchronously delivered targets.
            while let Some(t) = rx.recv().await {
                all_targets.push(t);
            }
        }

        
        for target in &all_targets {
            let Target::Domain(d) = target else { continue };
            
            tracing::info!(domain = %d.domain, sources = sources.len(), "subdomain scan");

            let wildcard_ips = detect_wildcards(&d.domain, input.resolver.as_ref(), 5).await;
            if !wildcard_ips.is_empty() {
                tracing::warn!(domain = %d.domain, ips = ?wildcard_ips, "wildcard DNS detected");
            }

            let seen = Arc::new(Mutex::new(HashSet::<String>::new()));
            let sem = Arc::new(Semaphore::new(MAX_CONCURRENT_SOURCES));
            let mut tasks = Vec::new();

            // Spawn all passive sources
            for i in 0..sources.len() {
                let sources = Arc::clone(&sources);
                let domain = d.domain.clone();
                let client = client.clone();
                let config = config.clone();
                let emitter = emitter.clone();
                let seen = Arc::clone(&seen);
                let sem = Arc::clone(&sem);
                let resolver = Arc::clone(&input.resolver);
                let wildcard_ips_passive = wildcard_ips.clone();
                let limiter = sources[i].rate_limit().build_limiter();
                let source_name = sources[i].name();
                let discovery = sources[i].discovery_source();

                tasks.push(tokio::spawn(async move {
                    let Ok(_permit) = sem.acquire().await else {
                        return;
                    };
                    let query_result =
                        tokio::time::timeout(
                            std::time::Duration::from_secs(SOURCE_TIMEOUT_SECS),
                            sources[i].query(&domain, &config, &client, &limiter),
                        )
                        .await;
                    match query_result {
                        Ok(Ok(targets)) => {
                            for mut t in targets {
                                // Rewrite discovery source to the canonical one for this source
                                if let Target::Domain(dt) = &mut t {
                                    dt.source = discovery.clone();
                                }
                                if let Some(dom) = t.domain() {
                                    // Drop passive hits that resolve only to zone-wildcard IPs.
                                    if !wildcard_ips_passive.is_empty() {
                                        if let Ok(lookup) = resolver.lookup_ip(dom).await {
                                            if lookup.iter().any(|ip| wildcard_ips_passive.contains(&ip)) {
                                                continue;
                                            }
                                        }
                                    }
                                    if let Some(norm) = normalize_domain(dom) {
                                        if seen.lock().await.insert(norm) {
                                            emitter.emit_target(t).await;
                                        }
                                    }
                                }
                            }
                        }
                        Ok(Err(err)) => {
                            tracing::warn!(source = source_name, domain, err = %err, "subdomain source error");
                            let severity = Severity::Info;
                            if let Some(finding) = Finding::builder("subdomain", &domain, severity)
                                .title(format!("Subdomain source failed: {source_name}"))
                                .detail(format!(
                                    "Passive source {source_name} failed while enumerating {domain}. \
                                     Fix: inspect connectivity, credentials, and upstream throttling. Error: {err}"
                                ))
                                .kind(secfinding::FindingKind::Other)
                                .tag("subdomain")
                                .tag("source-error")
                                .evidence(Evidence::raw(err.to_string()))
                                .build_or_log()
                            {
                                emitter.emit_finding(finding).await;
                            }
                        }
                        Err(_) => {
                            tracing::warn!(
                                source = source_name,
                                domain,
                                timeout_secs = SOURCE_TIMEOUT_SECS,
                                "subdomain source timed out"
                            );
                            let severity = Severity::Info;
                            if let Some(finding) = Finding::builder("subdomain", &domain, severity)
                                .title(format!("Subdomain source timed out: {source_name}"))
                                .detail(format!(
                                    "Passive source {source_name} exceeded the {SOURCE_TIMEOUT_SECS}s deadline \
                                     while enumerating {domain}. The endpoint may be dead or throttled."
                                ))
                                .kind(secfinding::FindingKind::Other)
                                .tag("subdomain")
                                .tag("source-timeout")
                                .evidence(Evidence::raw(format!("timeout after {SOURCE_TIMEOUT_SECS}s")))
                                .build_or_log()
                            {
                                emitter.emit_finding(finding).await;
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
                            if let Target::Domain(dt) = &mut t {
                                dt.source = gossan_core::DiscoverySource::DnsBruteforce;
                            }
                            if let Some(dom) = t.domain() {
                                if let Some(norm) = normalize_domain(dom) {
                                    if seen_bf.lock().await.insert(norm) {
                                        emitter_bf.emit_target(t).await;
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
                input.resolver.as_ref(),
            )
            .await
            {
                Ok(perms) => {
                    for mut t in perms {
                        if let Target::Domain(dt) = &mut t {
                            dt.source = gossan_core::DiscoverySource::DnsBruteforce;
                        }
                        if let Some(dom) = t.domain() {
                            if let Some(norm) = normalize_domain(dom) {
                                if seen.lock().await.insert(norm) {
                                    emitter.emit_target(t).await;
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
        .is_some_and(|prefix| {
            prefix.ends_with('.') && !prefix.contains("..") && prefix != "."
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use gossan_core::{DiscoverySource, DomainTarget};
    use proptest::prelude::*;

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

    #[test]
    fn is_subdomain_of_empty_strings() {
        assert!(!is_subdomain_of("", ""));
    }

    #[test]
    fn is_subdomain_of_trailing_dot() {
        assert!(is_subdomain_of("api.example.com.", "example.com"));
        assert!(is_subdomain_of("api.example.com", "example.com."));
    }

    #[test]
    fn is_subdomain_of_double_dot() {
        assert!(!is_subdomain_of("a..example.com", "example.com"));
    }

    #[test]
    fn is_subdomain_of_partial_match() {
        assert!(!is_subdomain_of("notexample.com", "example.com"));
    }

    /// Adversarial: very long strings with many dots must not panic.
    #[test]
    fn is_subdomain_of_handles_long_strings() {
        let candidate = "a.".repeat(1000) + "example.com";
        let domain = "example.com";
        // Must not panic on pathologically long input.
        let _ = is_subdomain_of(&candidate, domain);
    }

    proptest! {
        /// Property: `is_subdomain_of` never panics.
        #[test]
        fn is_subdomain_of_never_panics(candidate in ".*", domain in ".*") {
            let _ = is_subdomain_of(&candidate, &domain);
        }

        /// Property: a string is never a subdomain of itself (unless empty).
        #[test]
        fn is_subdomain_of_reflexive_false(s in ".{1,256}") {
            prop_assert!(!is_subdomain_of(&s, &s));
        }

        /// Property: empty candidate is never a subdomain.
        #[test]
        fn empty_candidate_is_never_subdomain(domain in ".*") {
            prop_assert!(!is_subdomain_of("", &domain));
        }

        /// Property: `is_subdomain_of` is consistent with manual suffix check
        /// for simple dot-separated ASCII strings.
        #[test]
        fn is_subdomain_of_matches_suffix(
            prefix in "[a-z0-9]{1,20}",
            domain in "[a-z0-9]{1,20}[.][a-z]{2,6}",
        ) {
            let candidate = format!("{}.{}", prefix, domain);
            prop_assert!(is_subdomain_of(&candidate, &domain));
        }
    }
}
