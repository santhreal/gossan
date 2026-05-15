#![forbid(unsafe_code)]
// pedantic moved to workspace [lints.clippy] in root Cargo.toml
//
// `expect_used` is intentionally ALLOWED here because the conservative
// regex literals in `conservative.rs` are infallible (they're compile-
// time string constants known to parse). The `expect("compile-time
// regex literal must compile")` documents that invariant. Other
// correctness lints (unwrap_used, todo, unimplemented, panic) stay
// forbidden in non-test code.
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

//! Horizontal discovery — ASN/BGP prefix mapping and sibling domain correlation.
//!
//! Expands the attack surface beyond a single domain by mapping the
//! organization's network footprint via public BGP and WHOIS data.

use async_trait::async_trait;
use gossan_core::{Config, DiscoverySource, DomainTarget, ScanInput, Scanner, Target, NetworkTarget};
use secfinding::{Finding, Severity};
use std::sync::Arc;
use futures::StreamExt;

pub mod asn;
pub mod ownership;
pub mod conservative;
/// ASN/BGP prefix mapper and sibling domain correlator for attack surface expansion.
pub struct HorizontalScanner;

#[async_trait]
impl Scanner for HorizontalScanner {
    fn name(&self) -> &'static str {
        "horizontal"
    }
    fn tags(&self) -> &[&'static str] {
        &["passive", "network", "intel", "horizontal"]
    }
    fn accepts(&self, target: &Target) -> bool {
        matches!(target, Target::Domain(_) | Target::Host(_) | Target::Network(_))
    }

    async fn run(&self, input: ScanInput, config: &Config) -> anyhow::Result<()> {
        let client = gossan_core::ScanClient::from_config(config, Arc::clone(&input.resolver))?;

        // Drain the inbound stream up-front. The original code held a
        // `targets: Vec<Target>` field on ScanInput; the streaming
        // refactor replaced it with `target_rx: Mutex<UnboundedReceiver>`
        // and horizontal was missed in that pass. The horizontal stage
        // does ASN/PTR/ownership pivots that need to see the full input
        // batch (it can't act incrementally on each new target the way
        // a portscan can), so collecting here matches the stage's
        // semantics — not a performance regression.
        let inbound: Vec<Target> = {
            let mut rx = input.target_rx.lock().await;
            let mut buf = Vec::new();
            while let Ok(t) = rx.try_recv() {
                buf.push(t);
            }
            buf
        };

        for target in &inbound {
            // 1. IP → ASN → BGP Prefixes
            if let Some(ip) = target.ip() {
                if let Ok(prefixes) = asn::get_prefixes_for_ip(&client, &ip.to_string()).await {
                    for prefix in prefixes {
                        let network = Target::Network(NetworkTarget {
                            cidr: prefix.clone(),
                            source: DiscoverySource::AsnLookup,
                        });
                        
                        // Emit to the target stream for recursive
                        // scanning. (The historical
                        // `if let Some(ref tx) = input.target_tx` +
                        // explicit `tx.send` + `emit_target` was
                        // double-emit; `target_tx` is no longer
                        // optional, so `emit_target` alone is correct
                        // and emits exactly once.)
                        input.emit_target(network);
                    }
                }
            }

            // 2. Network → PTR Sweep (Legendary Internal Discovery)
            if let Target::Network(net) = target {
                if let Ok(prefix) = net.cidr.parse::<ipnet::IpNet>() {
                    // Sample the first 16 IPs in the block for PTR records
                    let hosts: Vec<_> = prefix.hosts().take(16).collect();
                    let ptr_results: Vec<Option<String>> = futures::stream::iter(hosts)
                        .map(|ip| {
                            let resolver = Arc::clone(&input.resolver);
                            async move {
                                resolver.reverse_lookup(ip).await.ok().and_then(|r| {
                                    r.iter().next().map(|name| name.to_string().trim_end_matches('.').to_string())
                                })
                            }
                        })
                        .buffer_unordered(config.concurrency)
                        .collect()
                        .await;

                    for name in ptr_results.into_iter().flatten() {
                        let new_domain = Target::Domain(DomainTarget {
                            domain: name.clone(),
                            source: DiscoverySource::Crawl, // Discovered via PTR sweep
                        });
                        input.emit_target(new_domain);
                    }
                }
            }

            // 3. Domain → Organization → Root Domains
            if let Target::Domain(d) = target {
                if let Ok(sibling_domains) = ownership::get_sibling_domains(&client, &d.domain).await {
                    for domain in sibling_domains {
                        let new_domain = Target::Domain(DomainTarget {
                            domain: domain.clone(),
                            source: DiscoverySource::Crawl, // Pivoted from ownership
                        });

                        input.emit_target(new_domain);

                        // Create a finding for the discovery
                        if let Some(finding) = Finding::builder("horizontal", &d.domain, Severity::Info)
                            .title("Horizontal discovery: sibling domain found via ownership correlation".to_string())
                            .detail(format!("Domain {} shares ownership attributes with {}. This reveals a wider attack surface.", domain, d.domain))
                            .tag("horizontal")
                            .tag("ownership-pivot")
                            .kind(secfinding::FindingKind::InfoDisclosure)
                            .build_or_log()
                        {
                            input.emit(finding);
                        }
                    }
                }
            }
        }

        Ok(())
    }
}
