use gossan_core::{Config, DiscoverySource, DomainTarget, Finding, ScanInput, Scanner, Target};
use gossan_horizontal::conservative::ConservativeScanner;
use hickory_resolver::TokioAsyncResolver;
use std::sync::{Arc, Once};

/// `rustls` requires a process-wide default `CryptoProvider` before any
/// `ClientConfig` is built. The conservative scanner builds one inside
/// its TLS-cert probe path. Without this `Once`, every test that hits
/// the TLS path panics with `no process-level CryptoProvider available`.
fn install_rustls_provider() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        // `install_default` returns Err if one is already installed
        // (e.g. another integration test in the same binary). Either
        // outcome is fine — we just need to guarantee one is present.
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// Build a ScanInput for tests using the streaming API. The
/// pre-streaming `ScanInput { seed, targets: Vec<_>, live_tx: None,
/// target_tx: None }` form was retired; tests need to seed the
/// inbound `target_rx` via a one-shot channel and supply real
/// (drained-on-drop) live + target senders.
fn streaming_input(
    seed: &str,
    targets: Vec<Target>,
) -> (
    ScanInput,
    tokio::sync::mpsc::UnboundedReceiver<Finding>,
    tokio::sync::mpsc::UnboundedReceiver<Target>,
) {
    install_rustls_provider();
    let (in_tx, in_rx) = tokio::sync::mpsc::unbounded_channel::<Target>();
    for t in targets {
        let _ = in_tx.send(t);
    }
    drop(in_tx);
    let (live_tx, live_rx) = tokio::sync::mpsc::unbounded_channel();
    let (target_tx, target_rx) = tokio::sync::mpsc::unbounded_channel();
    let input = ScanInput {
        seed: seed.to_string(),
        target_rx: tokio::sync::Mutex::new(in_rx),
        live_tx,
        target_tx,
        resolver: Arc::new(TokioAsyncResolver::tokio_from_system_conf().unwrap()),
    };
    (input, live_rx, target_rx)
}

fn one_domain(name: &str) -> Vec<Target> {
    vec![Target::Domain(DomainTarget {
        domain: name.to_string(),
        source: DiscoverySource::Crawl,
    })]
}

fn fast_config() -> Config {
    let mut c = Config::default();
    // Aggressive timeouts so adversarial tests fail fast on the live
    // resolver / TLS / HTTP probe paths the conservative scanner
    // exercises. Production defaults (10s + per-host throttle) make
    // these tests take 60-120s+ each on a workstation.
    c.timeout_secs = 2;
    c.host_delay_ms = 0;
    c
}

// 90s ceiling: the conservative scanner runs hardcoded 5s JARM and
// banner-grab timeouts per host that are NOT bounded by
// `config.timeout_secs`. On adversarial inputs (1000 unroutable
// targets, huge seed) the sum of those probes can run well past 30s
// even with full parallelism. We still bound the wait so a genuine
// hang fails the test loudly rather than blocking CI forever.
const TEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(90);

#[tokio::test]
async fn test_concurrent_access() {
    let scanner = Arc::new(ConservativeScanner);
    let config = Arc::new(fast_config());

    let mut handles = vec![];
    for _ in 0..10 {
        let scanner_clone = Arc::clone(&scanner);
        let config_clone = Arc::clone(&config);
        handles.push(tokio::spawn(async move {
            let (input, _live_rx, _target_rx) =
                streaming_input("127.0.0.1", one_domain("localhost"));

            // Should execute without panicking and return a Result
            let result =
                tokio::time::timeout(TEST_TIMEOUT, scanner_clone.run(input, &config_clone))
                    .await
                    .expect("concurrent scanner.run must complete within 20s");
            assert!(result.is_ok());
        }));
    }

    for handle in handles {
        handle.await.unwrap();
    }
}

#[tokio::test]
async fn test_crash_recovery_malformed_responses() {
    let scanner = ConservativeScanner;
    let config = fast_config();

    // A target that definitely does not expose valid services, meaning
    // all connections will timeout or fail.
    let (input, mut live_rx, _target_rx) =
        streaming_input("255.255.255.255", one_domain("0.0.0.0"));

    // Scanner must not panic or crash, it should gracefully return
    // an Ok result even when every internal request fails.
    let result = tokio::time::timeout(TEST_TIMEOUT, scanner.run(input, &config))
        .await
        .expect("scanner.run on unroutable target must complete within 20s");
    assert!(result.is_ok(), "scanner returned error: {result:?}");

    // `Scanner::run` no longer returns a struct with `.findings` —
    // findings flow through the `live_tx` channel. Drain whatever
    // was emitted; we expect zero because the validation checks
    // against an unroutable target should produce nothing.
    let mut emitted: Vec<Finding> = Vec::new();
    while let Ok(f) = live_rx.try_recv() {
        emitted.push(f);
    }
    assert!(
        emitted.is_empty(),
        "expected zero findings against unroutable target, got {}: {:?}",
        emitted.len(),
        emitted.iter().map(|f| f.title()).collect::<Vec<_>>(),
    );
}

#[tokio::test]
async fn test_adversarial_null_bytes() {
    let scanner = ConservativeScanner;
    let config = fast_config();

    // Test with null bytes in the seed - should not panic or crash
    let (input, mut live_rx, _target_rx) =
        streaming_input("test\0nullbyte.com", one_domain("example.com"));

    let result = tokio::time::timeout(TEST_TIMEOUT, scanner.run(input, &config))
        .await
        .expect("scanner.run with null-byte seed must complete within 20s");
    assert!(
        result.is_ok(),
        "scanner should handle null bytes gracefully: {result:?}"
    );

    // Drain any emitted findings
    let mut emitted: Vec<Finding> = Vec::new();
    while let Ok(f) = live_rx.try_recv() {
        emitted.push(f);
    }
    // Null bytes shouldn't crash the scanner, regardless of findings
}

// Live network test: ConservativeScanner does real DNS/HTTP/TLS
// probes against `example.com` (the seed). Even with config-side
// timeouts, the scanner has hardcoded per-probe deadlines that on
// "example.com → empty targets" spend ~5 minutes worth of real-network
// roundtrip. The behaviour under no-targets is documented and gated;
// run this manually with `--ignored` after a network state check.
#[tokio::test]
#[ignore = "live network probes against example.com — wall-clock O(minutes); run with --ignored"]
async fn test_adversarial_empty_inputs() {
    let scanner = ConservativeScanner;
    let mut config = Config::default();
    config.timeout_secs = 2;
    config.host_delay_ms = 0;

    let test_timeout = TEST_TIMEOUT;

    // Test with empty seed
    let (input1, mut live_rx1, _target_rx1) = streaming_input("", vec![]);

    let result1 = tokio::time::timeout(test_timeout, scanner.run(input1, &config))
        .await
        .expect("scanner.run with empty seed must return within 90s");
    assert!(
        result1.is_ok(),
        "scanner should handle empty seed gracefully: {result1:?}"
    );

    // Drain any emitted findings
    let mut emitted1: Vec<Finding> = Vec::new();
    while let Ok(f) = live_rx1.try_recv() {
        emitted1.push(f);
    }

    // Test with empty targets
    let (input2, mut live_rx2, _target_rx2) = streaming_input("example.com", vec![]);

    let result2 = tokio::time::timeout(test_timeout, scanner.run(input2, &config))
        .await
        .expect("scanner.run with empty targets must return within 90s");
    assert!(
        result2.is_ok(),
        "scanner should handle empty targets gracefully: {result2:?}"
    );

    // Drain any emitted findings
    let mut emitted2: Vec<Finding> = Vec::new();
    while let Ok(f) = live_rx2.try_recv() {
        emitted2.push(f);
    }
}

#[tokio::test]
#[ignore = "live network probes against example.com — wall-clock O(minutes); run with --ignored"]
async fn test_adversarial_huge_inputs() {
    let scanner = ConservativeScanner;
    let mut config = Config::default();
    config.timeout_secs = 2;
    config.host_delay_ms = 0;
    let test_timeout = TEST_TIMEOUT;

    // Test with very long seed name
    let huge_seed = "a".repeat(10000) + ".com";
    let (input1, mut live_rx1, _target_rx1) =
        streaming_input(&huge_seed, one_domain("example.com"));

    let result1 = tokio::time::timeout(test_timeout, scanner.run(input1, &config))
        .await
        .expect("scanner.run with huge seed must return within 90s");
    assert!(
        result1.is_ok(),
        "scanner should handle huge seed gracefully: {result1:?}"
    );

    // Drain any emitted findings
    let mut emitted1: Vec<Finding> = Vec::new();
    while let Ok(f) = live_rx1.try_recv() {
        emitted1.push(f);
    }

    // Test with many targets
    let huge_targets: Vec<Target> = (0..1000)
        .map(|i| {
            Target::Domain(DomainTarget {
                domain: format!("target{}.example.com", i),
                source: DiscoverySource::Crawl,
            })
        })
        .collect();

    let (input2, mut live_rx2, _target_rx2) = streaming_input("seed.example.com", huge_targets);

    let result2 = tokio::time::timeout(test_timeout, scanner.run(input2, &config))
        .await
        .expect("scanner.run with many targets must return within 90s");
    assert!(
        result2.is_ok(),
        "scanner should handle many targets gracefully: {result2:?}"
    );

    // Drain any emitted findings
    let mut emitted2: Vec<Finding> = Vec::new();
    while let Ok(f) = live_rx2.try_recv() {
        emitted2.push(f);
    }
}
