use gossan_core::{Config, DiscoverySource, DomainTarget, ScanInput, Scanner, Target};
use gossan_subdomain::SubdomainScanner;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::mpsc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let scanner = SubdomainScanner;
    let config = Config::default();

    let (target_tx, mut target_rx) = mpsc::unbounded_channel::<Target>();
    let (live_tx, _live_rx) = mpsc::unbounded_channel();
    // Pre-load the inbound channel with the seed Domain target. The
    // pre-streaming `targets: vec![…]` field on ScanInput is gone;
    // seed targets now flow in via the same `target_rx` channel that
    // pipeline-stage targets do. Drop `inbound_tx` so the rx hits EOF
    // once the seed is consumed.
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
    let first_target_time = Arc::new(tokio::sync::Mutex::new(None));
    let ftt = Arc::clone(&first_target_time);

    while let Some(_t) = target_rx.recv().await {
        count += 1;
        let mut ftt_lock = ftt.lock().await;
        if ftt_lock.is_none() {
            *ftt_lock = Some(start.elapsed());
            println!("First target received after {:?}", start.elapsed());
        }
    }

    scan_handle.await??;
    let duration = start.elapsed();

    println!("Scan finished in {:?}", duration);
    println!("Total targets emitted: {}", count);

    if let Some(ft) = *first_target_time.lock().await {
        if ft > duration / 2 && duration.as_secs() > 1 {
            println!(
                "WARNING: First target took more than 50% of total time. Streaming is likely broken."
            );
        }
    }

    Ok(())
}
