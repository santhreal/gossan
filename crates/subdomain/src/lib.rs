//! Subdomain discovery — 9 concurrent sources + DNS bruteforce + permutation engine.
//!
//! Sources (no API key):  crt.sh, CertSpotter, Wayback Machine, HackerTarget,
//!                        RapidDNS, AlienVault OTX, Urlscan.io, CommonCrawl
//! Sources (API key):     VirusTotal ($VT_API_KEY), SecurityTrails ($ST_API_KEY)
//!
//! Every confirmed target is emitted via `input.emit_target()` immediately
//! so the port scanner can start while subdomain discovery is still running.

extern crate self as reqwest;
pub use stealthreq::http::{header, redirect};
pub use stealthreq::http::{Client, Method, Proxy, Request, Response, StatusCode, Url};

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
use gossan_core::{
    build_client, send_with_backoff, Config, HostRateLimiter, ScanInput, ScanOutput, Scanner,
    Target,
};
use hickory_resolver::{
    config::{NameServerConfigGroup, ResolverConfig, ResolverOpts},
    TokioAsyncResolver,
};
use secfinding::{Evidence, Finding, Severity};

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
        let passive_rate_limiter = HostRateLimiter::new(config.rate_limit);

        for target in &input.targets {
            let Target::Domain(d) = target else { continue };
            tracing::info!(domain = %d.domain, "subdomain scan — 10 sources");

            let has_wildcard = detect_wildcard(&d.domain, config).await;
            if has_wildcard {
                tracing::warn!(domain = %d.domain, "wildcard DNS — bruteforce disabled");
            }

            // ── All passive sources + bruteforce in parallel ─────────────────
            let (ct, cs, wb, ht, rd, av, us, cc, vt, st, brute) = tokio::join!(
                ct::query(&d.domain, config, &client, &passive_rate_limiter),
                certspotter::query(&d.domain, config, &client, &passive_rate_limiter),
                wayback::query(&d.domain, config, &client, &passive_rate_limiter),
                hackertarget::query(&d.domain, config, &client, &passive_rate_limiter),
                rapiddns::query(&d.domain, config, &client, &passive_rate_limiter),
                alienvault::query(&d.domain, config, &client, &passive_rate_limiter),
                urlscan::query(&d.domain, config, &client, &passive_rate_limiter),
                commoncrawl::query(&d.domain, config, &client, &passive_rate_limiter),
                virustotal::query(&d.domain, config, &client, &passive_rate_limiter),
                securitytrails::query(&d.domain, config, &client, &passive_rate_limiter),
                async {
                    if has_wildcard {
                        Ok(vec![])
                    } else {
                        bruteforce::scan(&d.domain, config, input.target_tx.clone()).await
                    }
                },
            );

            for t in take_targets("ct", &d.domain, &mut out, &input, ct) {
                emit_and_push(&input, &mut out, t);
            }
            for t in take_targets("certspotter", &d.domain, &mut out, &input, cs) {
                emit_and_push(&input, &mut out, t);
            }
            for t in take_targets("wayback", &d.domain, &mut out, &input, wb) {
                emit_and_push(&input, &mut out, t);
            }
            for t in take_targets("hackertarget", &d.domain, &mut out, &input, ht) {
                emit_and_push(&input, &mut out, t);
            }
            for t in take_targets("rapiddns", &d.domain, &mut out, &input, rd) {
                emit_and_push(&input, &mut out, t);
            }
            for t in take_targets("alienvault", &d.domain, &mut out, &input, av) {
                emit_and_push(&input, &mut out, t);
            }
            for t in take_targets("urlscan", &d.domain, &mut out, &input, us) {
                emit_and_push(&input, &mut out, t);
            }
            for t in take_targets("commoncrawl", &d.domain, &mut out, &input, cc) {
                emit_and_push(&input, &mut out, t);
            }
            for t in take_targets("virustotal", &d.domain, &mut out, &input, vt) {
                emit_and_push(&input, &mut out, t);
            }
            for t in take_targets("securitytrails", &d.domain, &mut out, &input, st) {
                emit_and_push(&input, &mut out, t);
            }
            for t in take_targets("bruteforce", &d.domain, &mut out, &input, brute) {
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

fn take_targets(
    source: &'static str,
    domain: &str,
    out: &mut ScanOutput,
    input: &ScanInput,
    result: anyhow::Result<Vec<Target>>,
) -> Vec<Target> {
    match result {
        Ok(targets) => targets,
        Err(err) => {
            tracing::warn!(source, domain, err = %err, "subdomain source error");
            let finding = Finding::builder("subdomain", domain, Severity::Low)
                .title(format!("Subdomain source failed: {source}"))
                .detail(format!(
                    "Passive source {source} failed while enumerating {domain}. Fix: inspect connectivity, credentials, and upstream throttling. Error: {err}"
                ))
                .tag("subdomain")
                .tag("source-error")
                .evidence(Evidence::Raw(err.to_string()))
                .build()
                .expect("finding builder: required fields are set");
            input.emit(finding.clone());
            out.findings.push(finding);
            Vec::new()
        }
    }
}

pub(crate) fn is_subdomain_of(candidate: &str, domain: &str) -> bool {
    let candidate = candidate.trim_end_matches('.');
    let domain = domain.trim_end_matches('.');
    candidate
        .strip_suffix(domain)
        .is_some_and(|prefix| prefix.ends_with('.'))
}

pub(crate) async fn get_text(
    client: &reqwest::Client,
    url: &str,
    rate_limiter: &HostRateLimiter,
) -> anyhow::Result<String> {
    send_with_backoff(url, Some(rate_limiter), || async {
        Ok::<reqwest::Response, anyhow::Error>(client.get(url).send().await?)
    })
    .await?
    .text()
    .await
    .map_err(Into::into)
}

pub(crate) async fn get_json<T: serde::de::DeserializeOwned>(
    client: &reqwest::Client,
    url: &str,
    rate_limiter: &HostRateLimiter,
) -> anyhow::Result<T> {
    send_with_backoff(url, Some(rate_limiter), || async {
        Ok::<reqwest::Response, anyhow::Error>(client.get(url).send().await?)
    })
    .await?
    .json()
    .await
    .map_err(Into::into)
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

    #[test]
    fn is_subdomain_of_requires_label_boundary() {
        assert!(is_subdomain_of("api.example.com", "example.com"));
        assert!(!is_subdomain_of("badexample.com", "example.com"));
        assert!(!is_subdomain_of("example.com", "example.com"));
    }

    #[tokio::test]
    async fn test_detect_wildcard() {
        let config = Config::default();
        // example.com should not have a wildcard
        assert!(!detect_wildcard("example.com", &config).await);
    }
}
