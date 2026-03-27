//! Subdomain discovery — 9 concurrent sources + DNS bruteforce + permutation engine.
//!
//! Sources (no API key):  crt.sh, CertSpotter, Wayback Machine, HackerTarget,
//!                        RapidDNS, AlienVault OTX, Urlscan.io, CommonCrawl
//! Sources (API key):     VirusTotal ($VT_API_KEY), SecurityTrails ($ST_API_KEY)
//!
//! Every confirmed target is emitted via `input.emit_target()` immediately
//! so the port scanner can start while subdomain discovery is still running.

mod alienvault;
mod bruteforce;
mod certspotter;
mod commoncrawl;
mod ct;
mod hackertarget;
mod permutations;
mod rapiddns;
mod securitytrails;
mod urlscan;
mod virustotal;
mod wayback;

use std::collections::HashSet;

use async_trait::async_trait;
use gossan_core::{build_client, Config, ScanInput, ScanOutput, Scanner, Target};
use hickory_resolver::{
    config::{NameServerConfigGroup, ResolverConfig, ResolverOpts},
    TokioAsyncResolver,
};

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

    async fn run(&self, input: ScanInput, config: &Config) -> anyhow::Result<ScanOutput> {
        let mut out = ScanOutput::empty();
        // Build one HTTP client, shared across all passive sources for this domain
        let client = build_client(config, true)?;

        for target in &input.targets {
            let Target::Domain(d) = target else { continue };
            tracing::info!(domain = %d.domain, "subdomain scan — 10 sources");

            let has_wildcard = detect_wildcard(&d.domain, config).await;
            if has_wildcard {
                tracing::warn!(domain = %d.domain, "wildcard DNS — bruteforce disabled");
            }

            // ── All passive sources + bruteforce in parallel ─────────────────
            macro_rules! source {
                ($name:expr, $result:expr) => {
                    match $result {
                        Ok(v)  => v,
                        Err(e) => { tracing::warn!(source = $name, err = %e, "subdomain source error"); vec![] }
                    }
                };
            }

            let (ct, cs, wb, ht, rd, av, us, cc, vt, st, brute) = tokio::join!(
                ct::query(&d.domain, config, &client),
                certspotter::query(&d.domain, config, &client),
                wayback::query(&d.domain, config, &client),
                hackertarget::query(&d.domain, config, &client),
                rapiddns::query(&d.domain, config, &client),
                alienvault::query(&d.domain, config, &client),
                urlscan::query(&d.domain, config, &client),
                commoncrawl::query(&d.domain, config, &client),
                virustotal::query(&d.domain, config, &client),
                securitytrails::query(&d.domain, config, &client),
                async {
                    if has_wildcard {
                        Ok(vec![])
                    } else {
                        bruteforce::scan(&d.domain, config, input.target_tx.clone()).await
                    }
                },
            );

            for t in source!("ct", ct) {
                emit_and_push(&input, &mut out, t);
            }
            for t in source!("certspotter", cs) {
                emit_and_push(&input, &mut out, t);
            }
            for t in source!("wayback", wb) {
                emit_and_push(&input, &mut out, t);
            }
            for t in source!("hackertarget", ht) {
                emit_and_push(&input, &mut out, t);
            }
            for t in source!("rapiddns", rd) {
                emit_and_push(&input, &mut out, t);
            }
            for t in source!("alienvault", av) {
                emit_and_push(&input, &mut out, t);
            }
            for t in source!("urlscan", us) {
                emit_and_push(&input, &mut out, t);
            }
            for t in source!("commoncrawl", cc) {
                emit_and_push(&input, &mut out, t);
            }
            for t in source!("virustotal", vt) {
                emit_and_push(&input, &mut out, t);
            }
            for t in source!("securitytrails", st) {
                emit_and_push(&input, &mut out, t);
            }
            for t in source!("bruteforce", brute) {
                /* bruteforce already emits via target_tx */
                out.targets.push(t);
            }

            // ── Deduplicate before permutation ───────────────────────────────
            let mut seen: HashSet<String> = HashSet::new();
            out.targets.retain(|t| {
                t.domain()
                    .map(|d| seen.insert(d.to_string()))
                    .unwrap_or(true)
            });

            // ── Permutation expansion ─────────────────────────────────────────
            match permutations::expand(&out.targets, &d.domain, config).await {
                Ok(perms) => {
                    for t in perms {
                        emit_and_push(&input, &mut out, t);
                    }
                }
                Err(e) => tracing::warn!(err = %e, "permutation expansion error"),
            }
        }

        // ── Final deduplication ───────────────────────────────────────────────
        let mut seen = HashSet::new();
        out.targets.retain(|t| {
            t.domain()
                .map(|d| seen.insert(d.to_string()))
                .unwrap_or(true)
        });

        tracing::info!(found = out.targets.len(), "subdomain scan complete");
        Ok(out)
    }
}

/// Emit a target via the streaming channel and push to output.
fn emit_and_push(input: &ScanInput, out: &mut ScanOutput, t: Target) {
    input.emit_target(t.clone());
    out.targets.push(t);
}

/// Returns true if the domain has a wildcard DNS record.
async fn detect_wildcard(domain: &str, config: &Config) -> bool {
    let Ok(resolver) = build_resolver(config) else {
        return false;
    };
    let probe = format!("this-label-should-not-exist-gossan-probe.{}", domain);
    resolver.lookup_ip(probe.as_str()).await.is_ok()
}

pub fn build_resolver(config: &Config) -> anyhow::Result<TokioAsyncResolver> {
    let servers = if config.resolvers.is_empty() {
        NameServerConfigGroup::cloudflare()
    } else {
        NameServerConfigGroup::from_ips_clear(&config.resolvers, 53, true)
    };
    let rc = ResolverConfig::from_parts(None, vec![], servers);
    let mut opts = ResolverOpts::default();
    opts.timeout = config.timeout();
    opts.attempts = 1;
    Ok(TokioAsyncResolver::tokio(rc, opts))
}
#[cfg(test)]
mod tests {
    use super::*;
    use gossan_core::{Config, DiscoverySource, DomainTarget, ScanOutput, Scanner};
    use tokio::sync::mpsc;

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
    fn emit_and_push_streams_target_and_adds_to_output() {
        let (target_tx, mut target_rx) = mpsc::unbounded_channel::<Target>();
        let input = ScanInput {
            seed: "example.com".into(),
            targets: vec![],
            live_tx: None,
            target_tx: Some(target_tx),
        };
        let mut out = ScanOutput::empty();
        let target = domain_target("api.example.com");

        emit_and_push(&input, &mut out, target.clone());

        assert_eq!(out.targets.len(), 1);
        assert_eq!(out.targets[0].domain(), Some("api.example.com"));
        assert_eq!(
            target_rx.try_recv().unwrap().domain(),
            Some("api.example.com")
        );
    }

    #[test]
    fn build_resolver_uses_custom_resolvers_when_supplied() {
        let config = Config {
            resolvers: vec!["9.9.9.9".parse().unwrap()],
            ..Config::default()
        };
        assert!(build_resolver(&config).is_ok());
    }

    #[tokio::test]
    async fn test_detect_wildcard() {
        let config = Config::default();
        // example.com should not have a wildcard
        assert!(!detect_wildcard("example.com", &config).await);
    }
}
