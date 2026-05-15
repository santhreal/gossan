use gossan_core::{Config, DiscoverySource, DomainTarget, ScanInput, Scanner, Target};
use gossan_subdomain::SubdomainScanner;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::mpsc;

/// Real-world streaming-throughput observation against `google.com`.
///
/// This test fires the live `SubdomainScanner` against the public
/// internet, exercising every API source (CT logs, RapidDNS, Wayback,
/// AlienVault, etc.) plus the bruteforce path. The runtime is bounded
/// only by the slowest source's timeout, so it can take 60+ seconds on
/// CI runners with degraded network paths.
///
/// Marked `#[ignore]` so `cargo test --workspace` skips it by default;
/// run explicitly with `cargo test -p gossan-subdomain -- --ignored` to
/// see the streaming-delay numbers.
#[tokio::test]
#[ignore = "live network scan against google.com — run with --ignored"]
async fn test_streaming_performance() -> anyhow::Result<()> {
    let scanner = SubdomainScanner;
    let config = Config::default();

    let (target_tx, mut target_rx) = mpsc::unbounded_channel::<Target>();
    let (live_tx, _live_rx) = mpsc::unbounded_channel();
    // Seed via the inbound channel — the pre-streaming `targets:
    // Vec<_>` field is gone; `target_rx` carries seeds and pivoted
    // targets uniformly now. Push the seed Domain then drop the tx
    // so the rx hits EOF after consumption.
    let (inbound_tx, inbound_rx) = mpsc::unbounded_channel::<Target>();
    let _ = inbound_tx.send(Target::Domain(DomainTarget {
        domain: "google.com".to_string(),
        source: DiscoverySource::Seed,
    }));
    drop(inbound_tx);

    let resolver = Arc::new(hickory_resolver::TokioAsyncResolver::tokio_from_system_conf()?);

    let input = ScanInput {
        seed: "google.com".to_string(),
        target_rx: tokio::sync::Mutex::new(inbound_rx),
        live_tx,
        target_tx,
        resolver,
    };

    println!("Starting subdomain scan for google.com...");
    let start = Instant::now();

    let scan_handle = tokio::spawn(async move { scanner.run(input, &config).await });

    let mut count = 0;
    let mut first_target_time = None;

    while let Some(_t) = target_rx.recv().await {
        count += 1;
        if first_target_time.is_none() {
            first_target_time = Some(start.elapsed());
            println!("First target received after {:?}", start.elapsed());
        }
    }

    scan_handle.await??;
    let duration = start.elapsed();

    println!("Scan finished in {:?}", duration);
    println!("Total targets emitted: {}", count);

    if let Some(ft) = first_target_time {
        println!("Streaming delay: {:?} (Total: {:?})", ft, duration);
        if ft > std::time::Duration::from_secs(2) && duration > ft {
            println!("Confirmed: Streaming is blocked by slowest source.");
        }
    }

    Ok(())
}
