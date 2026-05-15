//! DNS bruteforce subdomain discovery.

use std::collections::HashSet;
use std::sync::Arc;

use futures::StreamExt;
use gossan_core::{Config, DiscoverySource, DomainTarget, Target};
use tokio::sync::{Mutex, mpsc::UnboundedSender};

const WORDLIST: &str = include_str!("wordlist.txt");

/// DNS bruteforce scan with recursive depth support and wildcard filtering.
pub async fn scan(
    domain: &str,
    config: &Config,
    target_tx: Option<UnboundedSender<Target>>,
    resolver: Arc<hickory_resolver::TokioAsyncResolver>,
    wildcard_ips: Option<&HashSet<std::net::IpAddr>>,
) -> anyhow::Result<Vec<Target>> {
    let target_tx = Arc::new(target_tx);
    let seen = Arc::new(Mutex::new(HashSet::new()));

    let words: Arc<Vec<String>> = Arc::new(
        WORDLIST
            .lines()
            .map(|w| w.trim().to_string())
            .filter(|w| !w.is_empty())
            .collect(),
    );

    recursive_scan(
        domain.to_string(),
        config.clone(),
        resolver,
        target_tx,
        seen,
        words,
        0,
        2,
        wildcard_ips.cloned(),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
fn recursive_scan(
    domain: String,
    config: Config,
    resolver: Arc<hickory_resolver::TokioAsyncResolver>,
    target_tx: Arc<Option<UnboundedSender<Target>>>,
    seen: Arc<Mutex<HashSet<String>>>,
    words: Arc<Vec<String>>,
    depth: usize,
    max_depth: usize,
    wildcard_ips: Option<HashSet<std::net::IpAddr>>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<Vec<Target>>> + Send>> {
    Box::pin(async move {
        if depth >= max_depth {
            return Ok(vec![]);
        }

        {
            let mut s = seen.lock().await;
            if !s.insert(domain.clone()) {
                return Ok(vec![]);
            }
        }

        let discovered: Vec<Target> = futures::stream::iter(words.as_ref().clone())
            .map(|word| {
                let resolver = Arc::clone(&resolver);
                let domain_str = domain.clone();
                let tx = Arc::clone(&target_tx);
                let wildcards = wildcard_ips.clone();
                async move {
                    let candidate = format!("{}.{}", word, domain_str);
                    let Ok(lookup) = resolver.lookup_ip(candidate.as_str()).await else {
                        return None;
                    };

                    // Filter out wildcard matches
                    if let Some(ref w_ips) = wildcards {
                        if lookup.iter().any(|ip| w_ips.contains(&ip)) {
                            return None;
                        }
                    }

                    let t = Target::Domain(DomainTarget {
                        domain: candidate,
                        source: DiscoverySource::DnsBruteforce,
                    });
                    // Emit immediately for streaming pipeline
                    if let Some(tx) = tx.as_ref() {
                        let _ = tx.send(t.clone());
                    }
                    Some(t)
                }
            })
            .buffer_unordered(config.concurrency)
            .filter_map(|x| async move { x })
            .collect()
            .await;

        let mut all_results = discovered.clone();

        // Recurse on interesting subdomains if depth permits
        if depth + 1 < max_depth {
            let mut recursion_tasks = Vec::new();
            for t in &discovered {
                if let Target::Domain(d) = t {
                    let sub_str = d.domain.clone();
                    let labels = [
                        "dev", "api", "staging", "prod", "test", "v1", "v2", "app",
                        "internal", "corp",
                    ];
                    if labels.iter().any(|&l| sub_str.starts_with(l)) {
                        let resolver_inner = Arc::clone(&resolver);
                        let tx_inner = Arc::clone(&target_tx);
                        let seen_inner = Arc::clone(&seen);
                        let config_inner = config.clone();
                        let words_inner = Arc::clone(&words);
                        let wildcard_ips_clone = wildcard_ips.clone();
                        recursion_tasks.push(tokio::spawn(async move {
                            let sub_wildcard =
                                crate::wildcard::detect_wildcards(&sub_str, &resolver_inner, 3)
                                    .await;
                            let merged = wildcard_ips_clone.as_ref().map(|w| {
                                let mut m = w.clone();
                                m.extend(sub_wildcard);
                                m
                            });
                            recursive_scan(
                                sub_str,
                                config_inner,
                                resolver_inner,
                                tx_inner,
                                seen_inner,
                                words_inner,
                                depth + 1,
                                max_depth,
                                merged,
                            )
                            .await
                        }));
                    }
                }
            }

            for task in recursion_tasks {
                if let Ok(Ok(sub_results)) = task.await {
                    all_results.extend(sub_results);
                }
            }
        }

        Ok(all_results)
    })
}
