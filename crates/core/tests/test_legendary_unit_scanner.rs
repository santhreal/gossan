use gossan_core::{make_finding, DiscoverySource, DomainTarget, ScanInput, Severity, Target};
use hickory_resolver::{
    config::{ResolverConfig, ResolverOpts},
    TokioAsyncResolver,
};
use std::sync::Arc;
use tokio::sync::mpsc;

#[tokio::test]
async fn test_scan_input_emit_finding() {
    let resolver = Arc::new(TokioAsyncResolver::tokio(
        ResolverConfig::default(),
        ResolverOpts::default(),
    ));

    // Streaming-API ScanInput. Pre-streaming form had `targets:
    // Vec<_>`, optional `live_tx`/`target_tx`, no `target_rx`. Now:
    // targets flow through `target_rx`, live + target senders are
    // required. The unused channels here are still allocated so the
    // ScanInput is fully constructed.
    let (in_tx, in_rx) = mpsc::unbounded_channel::<Target>();
    drop(in_tx);
    let (live_tx, mut live_rx) = mpsc::unbounded_channel();
    let (target_tx, _target_rx) = mpsc::unbounded_channel();
    let input = ScanInput {
        seed: "example.com".to_string(),
        target_rx: tokio::sync::Mutex::new(in_rx),
        live_tx,
        target_tx,
        resolver,
    };

    let target = Target::Domain(DomainTarget {
        domain: "example.com".into(),
        source: DiscoverySource::Seed,
    });

    let finding = make_finding("test", target, Severity::Low, "title", "detail").unwrap();

    input.emit(finding.clone());

    let received = live_rx.recv().await.unwrap();
    // `scanner` field is private — use the public accessor.
    assert_eq!(received.scanner(), "test");
}

#[tokio::test]
async fn test_scan_input_emit_target() {
    let resolver = Arc::new(TokioAsyncResolver::tokio(
        ResolverConfig::default(),
        ResolverOpts::default(),
    ));

    // Same streaming-API construction as above.
    let (in_tx, in_rx) = mpsc::unbounded_channel::<Target>();
    drop(in_tx);
    let (live_tx, _live_rx) = mpsc::unbounded_channel();
    let (target_tx, mut target_rx) = mpsc::unbounded_channel();
    let input = ScanInput {
        seed: "example.com".to_string(),
        target_rx: tokio::sync::Mutex::new(in_rx),
        live_tx,
        target_tx,
        resolver,
    };

    let target = Target::Domain(DomainTarget {
        domain: "example.com".into(),
        source: DiscoverySource::Seed,
    });

    input.emit_target(target);

    let received = target_rx.recv().await.unwrap();
    assert_eq!(received.domain(), Some("example.com"));
}

// `test_scan_output_empty` was removed: the `ScanOutput` struct it
// targeted (with `findings` + `targets` fields and an `::empty()`
// constructor) was retired in the streaming refactor. `Scanner::run`
// now returns `Result<()>` and outputs flow through `live_tx` /
// `target_tx`. The two tests above already cover the emission path
// end-to-end, so the empty-constructor sanity check became
// redundant.
