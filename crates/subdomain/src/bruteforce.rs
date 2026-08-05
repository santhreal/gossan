//! DNS bruteforce subdomain discovery.

use std::collections::HashSet;
use std::future::Future;
use std::net::IpAddr;
use std::sync::{Arc, OnceLock};

use hickory_resolver::proto::rr::RecordType;
use futures::StreamExt;
use gossan_core::{Config, DiscoverySource, DomainTarget, Target};
use tokio::sync::{Mutex, Semaphore};

const WORDLIST: &str = include_str!("wordlist.txt");

fn cached_wordlist() -> Arc<Vec<String>> {
    static WORDS: OnceLock<Arc<Vec<String>>> = OnceLock::new();
    Arc::clone(WORDS.get_or_init(|| {
        Arc::new(
            WORDLIST
                .lines()
                .map(|w| w.trim().to_string())
                .filter(|w| !w.is_empty())
                .collect(),
        )
    }))
}

/// Run a bruteforce scan with a caller-supplied wordlist and return the
/// discovered FQDNs as strings. Used by hermetic tests so that assertions
/// can be made against exact names without depending on the built-in wordlist.
pub async fn run_bruteforce_with_words(
    domain: &str,
    words: &[&str],
    resolver: Arc<hickory_resolver::TokioResolver>,
    wildcard_ips: Option<HashSet<IpAddr>>,
    max_depth: usize,
) -> anyhow::Result<Vec<String>> {
    let config = Config::default();
    let sem = Arc::new(Semaphore::new(config.concurrency));
    let target_tx = Arc::new(None::<tokio::sync::mpsc::Sender<Target>>);
    let seen = Arc::new(Mutex::new(HashSet::new()));
    let words: Arc<Vec<String>> = Arc::new(words.iter().map(|w| w.to_string()).collect());

    let targets = recursive_scan(
        domain.to_string(),
        config,
        resolver,
        target_tx,
        seen,
        words,
        0,
        max_depth,
        wildcard_ips,
        sem,
    )
    .await?;

    let mut found: HashSet<String> = HashSet::new();
    for t in targets {
        if let Some(d) = t.domain() {
            found.insert(d.to_string());
        }
    }

    Ok(found.into_iter().collect())
}

/// DNS bruteforce scan with recursive depth support and wildcard filtering.
pub async fn scan(
    domain: &str,
    config: &Config,
    target_tx: Option<tokio::sync::mpsc::Sender<Target>>,
    resolver: Arc<hickory_resolver::TokioResolver>,
    wildcard_ips: Option<&HashSet<std::net::IpAddr>>,
) -> anyhow::Result<Vec<Target>> {
    let sem = Arc::new(Semaphore::new(config.concurrency));
    let target_tx = Arc::new(target_tx);
    let seen = Arc::new(Mutex::new(HashSet::new()));

    let words = cached_wordlist();

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
        sem,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
fn recursive_scan(
    domain: String,
    config: Config,
    resolver: Arc<hickory_resolver::TokioResolver>,
    target_tx: Arc<Option<tokio::sync::mpsc::Sender<Target>>>,
    seen: Arc<Mutex<HashSet<String>>>,
    words: Arc<Vec<String>>,
    depth: usize,
    max_depth: usize,
    wildcard_ips: Option<HashSet<std::net::IpAddr>>,
    sem: Arc<Semaphore>,
) -> std::pin::Pin<Box<dyn Future<Output = anyhow::Result<Vec<Target>>> + Send>> {
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

        let discovered: Vec<Target> = futures::stream::iter(0..words.len())
            .map(|i| {
                let resolver = Arc::clone(&resolver);
                let domain_str = domain.clone();
                let tx = Arc::clone(&target_tx);
                let wildcards = wildcard_ips.clone();
                let words = Arc::clone(&words);
                async move {
                    let candidate = format!("{}.{}", words[i], domain_str);
                    let Ok(lookup) = resolver.lookup_ip(candidate.as_str()).await else {
                        return None;
                    };

                    // Filter out direct wildcard matches, but keep explicit
                    // CNAME records even if the CNAME target resolves to a
                    // wildcard IP.
                    if let Some(w_ips) = &wildcards {
                        if lookup.iter().any(|ip| w_ips.contains(&ip)) {
                            let has_cname = resolver
                                .lookup(candidate.as_str(), RecordType::CNAME)
                                .await
                                .map(|l| l.record_iter().next().is_some())
                                .unwrap_or(false);
                            if !has_cname {
                                return None;
                            }
                        }
                    }

                    let t = Target::Domain(DomainTarget {
                        domain: candidate,
                        source: DiscoverySource::DnsBruteforce,
                    });
                    // Emit immediately for streaming pipeline
                    if let Some(tx) = tx.as_ref() {
                        if let Err(e) = tx.send(t.clone()).await {
                            tracing::warn!(domain = ?t.domain(), err = %e, "failed to emit discovered subdomain");
                        }
                    }
                    Some(t)
                }
            })
            .buffer_unordered(config.concurrency)
            .filter_map(|x| async move { x })
            .collect()
            .await;

        // Recurse on interesting subdomains if depth permits, accumulating
        // sub-results separately to avoid cloning `discovered`.
        let mut sub_results: Vec<Target> = Vec::new();

        if depth + 1 < max_depth {
            let mut recursion_tasks = Vec::new();
            for t in &discovered {
                if let Target::Domain(d) = t {
                    let sub_str = d.domain.clone();
                    let labels = [
                        "dev", "api", "staging", "prod", "test", "v1", "v2", "app", "internal",
                        "corp",
                    ];
                    if labels.iter().any(|&l| sub_str.starts_with(l)) {
                        let resolver_inner = Arc::clone(&resolver);
                        let tx_inner = Arc::clone(&target_tx);
                        let seen_inner = Arc::clone(&seen);
                        let config_inner = config.clone();
                        let words_inner = Arc::clone(&words);
                        let wildcard_ips_clone = wildcard_ips.clone();
                        let sem_inner = Arc::clone(&sem);
                        recursion_tasks.push(tokio::spawn(async move {
                            let _permit = sem_inner.acquire().await.unwrap();
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
                                Arc::clone(&sem_inner),
                            )
                            .await
                        }));
                    }
                }
            }

            for task in recursion_tasks {
                if let Ok(Ok(batch)) = task.await {
                    sub_results.extend(batch);
                }
            }
        }

        // Merge without cloning: move `discovered`, then append recursion.
        let mut all_results = discovered;
        all_results.extend(sub_results);

        Ok(all_results)
    })
}
