use std::sync::Arc;

use futures::StreamExt;
use gossan_core::{Config, DiscoverySource, DomainTarget, Target};
use tokio::sync::mpsc::UnboundedSender;

use crate::build_resolver;

const WORDLIST: &str = include_str!("wordlist.txt");

/// DNS bruteforce scan.
///
/// If `target_tx` is provided, every confirmed subdomain is emitted immediately
/// so the port scanner can start processing it while discovery is still running.
pub async fn scan(
    domain: &str,
    config: &Config,
    target_tx: Option<UnboundedSender<Target>>,
) -> anyhow::Result<Vec<Target>> {
    let resolver = Arc::new(build_resolver(config)?);
    let domain = Arc::new(domain.to_string());
    let target_tx = Arc::new(target_tx);

    let words: Vec<String> = WORDLIST
        .lines()
        .map(|w| w.trim().to_string())
        .filter(|w| !w.is_empty())
        .collect();

    let targets: Vec<Target> = futures::stream::iter(words)
        .map(|word| {
            let resolver = Arc::clone(&resolver);
            let domain = Arc::clone(&domain);
            let tx = Arc::clone(&target_tx);
            async move {
                let candidate = format!("{}.{}", word, domain);
                resolver.lookup_ip(candidate.as_str()).await.ok().map(|_| {
                    let t = Target::Domain(DomainTarget {
                        domain: candidate,
                        source: DiscoverySource::DnsBruteforce,
                    });
                    // Emit immediately for streaming pipeline
                    if let Some(tx) = tx.as_ref() {
                        let _ = tx.send(t.clone());
                    }
                    t
                })
            }
        })
        .buffer_unordered(config.concurrency)
        .filter_map(|x| async move { x })
        .collect()
        .await;

    Ok(targets)
}
