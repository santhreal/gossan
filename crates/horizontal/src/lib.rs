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
    clippy::missing_errors_doc
)]

//! Horizontal discovery: ASN/BGP prefix mapping and sibling domain correlation.
//!
//! Expands the attack surface beyond a single domain by mapping the
//! organization's network footprint via public BGP and WHOIS data.

use async_trait::async_trait;
use futures::StreamExt;
use gossan_core::{
    Config, DiscoverySource, DomainTarget, NetworkTarget, ScanInput, Scanner, Target,
};
use secfinding::{Finding, Severity};
use std::sync::Arc;

/// Maximum bytes for ASN and reverse-IP lookup text responses.
/// These endpoints return compact text; 1 MiB is very generous while
/// preventing unbounded reads from adversarial or malfunctioning APIs.
pub(crate) const MAX_HORIZONTAL_TEXT_BYTES: usize = 1 * 1024 * 1024;

pub mod asn;
pub mod conservative;
pub mod ownership;
pub mod permutation;
pub mod private_ip;
pub mod tld;
pub mod passive_dns;

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
        matches!(
            target,
            Target::Domain(_) | Target::Host(_) | Target::Network(_)
        )
    }

    async fn run(&self, input: ScanInput, config: &Config) -> anyhow::Result<()> {
        let client = gossan_core::ScanClient::from_config(config, Arc::clone(&input.resolver))?;

        // Collect the inbound target stream. The horizontal stage does
        // ASN/PTR/ownership pivots that need to see the full input batch
        // (it can't act incrementally on each new target the way a portscan
        // can), so collecting until the channel closes is the intended batch
        // semantics. Using `recv().await` waits for the sender to close
        // rather than exiting early on an empty buffer like `try_recv`.
        let inbound: Vec<Target> = {
            let mut rx = input.target_rx.lock().await;
            let mut buf = Vec::new();
            while let Some(t) = rx.recv().await {
                buf.push(t);
            }
            buf
        };

        let mut seed_domains: Vec<String> = Vec::new();

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
                        input.emit_target(network).await;
                    }
                }
            }

            // 2. Network → PTR Sweep (Oneshot Internal Discovery)
            if let Target::Network(net) = target {
                if let Ok(prefix) = net.cidr.parse::<ipnet::IpNet>() {
                    // Sample the first 16 IPs in the block for PTR records
                    let hosts: Vec<_> = prefix.hosts().take(16).collect();
                    let ptr_results: Vec<Option<String>> = futures::stream::iter(hosts)
                        .map(|ip| {
                            let resolver = Arc::clone(&input.resolver);
                            async move {
                                match resolver.reverse_lookup(ip).await {
                                    Ok(r) => r.iter().next().map(|name| {
                                        name.to_string().trim_end_matches('.').to_string()
                                    }),
                                    Err(e)
                                        if e.is_nx_domain() || e.is_no_records_found() =>
                                    {
                                        None
                                    }
                                    Err(e) => {
                                        tracing::warn!(
                                            %ip,
                                            error = %e,
                                            "PTR reverse lookup failed; skipping host"
                                        );
                                        None
                                    }
                                }
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
                        input.emit_target(new_domain).await;
                    }
                }
            }

            // 3. Domain → permutations + passive DNS
            if let Target::Domain(d) = target {
                seed_domains.push(d.domain.clone());

                const PREFIXES: &[&str] =
                    &["dev", "staging", "api", "admin", "test", "mail", "vpn"];
                const SUFFIXES: &[&str] = &["-dev", "-staging", "-backup", "-old"];
                for perm in permutation::deduplicate_permutations(
                    &permutation::generate_all_permutations(&d.domain, PREFIXES, SUFFIXES),
                ) {
                    if perm == d.domain {
                        continue;
                    }
                    input.emit_target(Target::Domain(DomainTarget {
                        domain: perm,
                        source: DiscoverySource::DnsBruteforce,
                    })).await;
                }

                if let Ok(records) =
                    passive_dns::query_hostsearch(&client, &d.domain, "https://api.hackertarget.com")
                        .await
                {
                    for domain in passive_dns::extract_unique_domains(&records) {
                        input.emit_target(Target::Domain(DomainTarget {
                            domain,
                            source: DiscoverySource::PassiveDns,
                        })).await;
                    }
                    for ip in private_ip::filter_private_ips(
                        &passive_dns::extract_unique_ips(&records)
                            .into_iter()
                            .collect::<Vec<_>>(),
                    ) {
                        if let Ok(addr) = ip.parse() {
                            input.emit_target(Target::Host(gossan_core::HostTarget {
                                ip: addr,
                                domain: Some(d.domain.clone()),
                            })).await;
                        }
                    }
                }

                // 3c. TLD variations for the same registrable domain.
                const TLDS: &[&str] = &[
                    "com", "net", "org", "io", "co", "info", "biz", "us",
                ];
                for variant in tld::generate_tld_variations(&d.domain, TLDS) {
                    if variant == d.domain {
                        continue;
                    }
                    input.emit_target(Target::Domain(DomainTarget {
                        domain: variant,
                        source: DiscoverySource::DnsBruteforce,
                    })).await;
                }
            }
        }

        // 4. Ownership correlation via WHOIS/RDAP across the inbound domain set.
        // Reverse-IP hosting is intentionally not used (shared-hosting FPs).
        if seed_domains.len() > 1 {
            if let Ok(groups) = ownership::group_siblings_by_ownership(
                &client,
                &seed_domains,
                "https://api.hackertarget.com",
            )
            .await
            {
                for (_key, domains) in groups {
                    for domain in &domains {
                        for sibling in domains.iter().filter(|s| *s != domain) {
                            input.emit_target(Target::Domain(DomainTarget {
                                domain: sibling.clone(),
                                source: DiscoverySource::Crawl,
                            })).await;
                            if let Some(finding) = Finding::builder(
                                "horizontal",
                                domain,
                                Severity::Info,
                            )
                            .title(
                                "Horizontal discovery: sibling domain found via ownership correlation"
                                    .to_string(),
                            )
                            .detail(format!(
                                "Domain {} shares WHOIS/RDAP ownership attributes with {}.",
                                sibling, domain
                            ))
                            .tag("horizontal")
                            .tag("ownership-pivot")
                            .kind(secfinding::FindingKind::InfoDisclosure)
                            .build_or_log()
                            {
                                input.emit(finding).await;
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }
}
