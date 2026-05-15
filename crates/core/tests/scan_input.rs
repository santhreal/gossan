//! ScanInput streaming tests.
//!
//! Asserts the streaming contract: drop semantics, large bursts, channel
//! exhaustion, and Arc<TokioAsyncResolver> sharing.

use gossan_core::scanner::ScanInput;
use gossan_core::target::{DiscoverySource, DomainTarget, Target};
use gossan_core::{Finding, Severity};
use hickory_resolver::TokioAsyncResolver;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

fn finding() -> Finding {
    Finding::builder("scan-input-test", "example.com", Severity::Info)
        .title("t")
        .detail("d")
        .build()
        .unwrap()
}

fn build_input() -> (
    ScanInput,
    mpsc::UnboundedSender<Target>,
    mpsc::UnboundedReceiver<Finding>,
    mpsc::UnboundedReceiver<Target>,
) {
    let (target_tx_in, target_rx_in) = mpsc::unbounded_channel::<Target>();
    let (live_tx, live_rx) = mpsc::unbounded_channel::<Finding>();
    let (target_tx, target_rx) = mpsc::unbounded_channel::<Target>();
    let resolver = Arc::new(TokioAsyncResolver::tokio(
        ResolverConfig::default(),
        ResolverOpts::default(),
    ));
    let input = ScanInput {
        seed: "example.com".into(),
        target_rx: tokio::sync::Mutex::new(target_rx_in),
        live_tx,
        target_tx,
        resolver,
    };
    (input, target_tx_in, live_rx, target_rx)
}

#[tokio::test]
async fn sender_drop_yields_eof_on_target_rx() {
    let (input, target_tx_in, _live_rx, _target_rx) = build_input();
    drop(target_tx_in);
    let mut rx = input.target_rx.lock().await;
    assert!(rx.recv().await.is_none(), "must signal EOF after sender drop");
}

#[tokio::test]
async fn pushes_100k_targets_through_input() {
    const N: usize = 100_000;
    let (input, target_tx_in, _live_rx, _target_rx) = build_input();
    let producer = tokio::spawn(async move {
        for i in 0..N {
            target_tx_in
                .send(Target::Domain(DomainTarget {
                    domain: format!("a{i}.example.com"),
                    source: DiscoverySource::Seed,
                }))
                .unwrap();
        }
    });
    let mut count = 0usize;
    let mut rx = input.target_rx.lock().await;
    while let Some(_t) = rx.recv().await {
        count += 1;
        if count == N {
            break;
        }
    }
    drop(rx);
    producer.await.unwrap();
    assert_eq!(count, N);
}

#[tokio::test]
async fn emit_does_not_panic_after_live_rx_drop() {
    let (input, _target_tx_in, live_rx, _target_rx) = build_input();
    drop(live_rx);
    // unbounded channel send returns Err when receiver dropped; the helper swallows it
    input.emit(finding());
    input.emit(finding());
}

#[tokio::test]
async fn emit_target_does_not_panic_after_target_rx_drop() {
    let (input, _target_tx_in, _live_rx, target_rx) = build_input();
    drop(target_rx);
    input.emit_target(Target::Domain(DomainTarget {
        domain: "x.example.com".into(),
        source: DiscoverySource::Seed,
    }));
}

#[tokio::test]
async fn resolver_arc_clones_safely_across_tasks() {
    let (input, _tx, _live_rx, _target_rx) = build_input();
    let resolver = Arc::clone(&input.resolver);
    let handles: Vec<_> = (0..16)
        .map(|_| {
            let r = Arc::clone(&resolver);
            tokio::spawn(async move {
                let _ = tokio::time::timeout(
                    Duration::from_millis(1),
                    r.lookup_ip("localhost"),
                )
                .await;
                Arc::strong_count(&r)
            })
        })
        .collect();
    for h in handles {
        h.await.unwrap();
    }
    // Original Arc + the resolver field still alive.
    assert!(Arc::strong_count(&resolver) >= 2);
}

#[tokio::test]
async fn live_tx_buffers_unbounded_emits_without_blocking() {
    let (input, _tx, mut live_rx, _target_rx) = build_input();
    for _ in 0..10_000 {
        input.emit(finding());
    }
    let mut received = 0usize;
    while live_rx.try_recv().is_ok() {
        received += 1;
    }
    assert_eq!(received, 10_000);
}
