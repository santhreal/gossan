//! Real-network end-to-end test for the engine.
//!
//! Scans the loopback interface (127.0.0.1) at high rate and reports
//! actual wall-time pps. Unlike the criterion bench (`tx_hot_loop`)
//! which uses a counting stub, this exercises the FULL syscall path:
//! sendmmsg → kernel → loopback → recvmmsg.
//!
//! # Running
//!
//! ```
//! sudo -E env "PATH=$PATH" cargo test -p gossan-engine \
//!     --test realnet_loopback -- --ignored --nocapture
//! ```
//!
//! Requires:
//!   - root (CAP_NET_RAW for sendmmsg backend, falls back to pnet
//!     if non-root)
//!   - Linux kernel that allows raw sockets (most do)
//!
//! Marked `#[ignore]` because:
//!   - It requires sudo (CI without root will be flaky)
//!   - It hits the loopback interface (some sandboxes block this)
//!   - It's a perf test, not a correctness test — the workspace
//!     `cargo test` should not run it by default
//!
//! Headline metric: wall-time pps for a sweep of 65k probes against
//! 127.0.0.1 ports 1..=10. The masscan baseline on the same workload
//! and machine is what we want to beat.

#![cfg(target_os = "linux")]

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Instant;

use gossan_core::{Config, DiscoverySource, HostTarget, PortMode, ScanInput, Scanner, Target};
use tokio::sync::{mpsc, Mutex};

/// Build a minimal `ScanInput` that funnels a single Host target into
/// the scanner. The streaming receiver is pre-loaded with the target;
/// no resolver lookups happen.
fn make_scan_input(target: Target, seed: String) -> ScanInput {
    let (target_tx_loaded, target_rx) = mpsc::unbounded_channel();
    target_tx_loaded.send(target).expect("send target");
    drop(target_tx_loaded);
    let (live_tx, _live_rx) = mpsc::unbounded_channel();
    let (downstream_tx, _downstream_rx) = mpsc::unbounded_channel();
    ScanInput {
        seed,
        target_rx: Mutex::new(target_rx),
        live_tx,
        target_tx: downstream_tx,
        resolver: Arc::new(
            hickory_resolver::AsyncResolver::tokio_from_system_conf().expect("system DNS config"),
        ),
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires root + loopback; run manually with sudo"]
async fn loopback_engine_throughput() {
    let _ = tracing_subscriber::fmt::try_init();

    let target = Target::Host(gossan_core::HostTarget {
        ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        domain: None,
    });

    let _ = HostTarget {
        ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        domain: None,
    };
    let _ = DiscoverySource::Seed;

    // Top-100 ports against a single host = 100 probes. That's tiny;
    // the wall-time number is dominated by the per-batch syscall cost.
    // For a more representative number, repeat the scan N times — the
    // sustained pps is what matters, not single-scan latency.
    const REPEATS: usize = 50;

    let mut config = Config::default();
    config.port_mode = PortMode::Top100;
    config.rate_limit = 0; // unlimited; we're benching ceiling

    let scanner = gossan_engine::EngineScanner::new();
    let start = Instant::now();
    for _ in 0..REPEATS {
        let input = make_scan_input(target.clone(), "127.0.0.1".to_string());
        scanner.run(input, &config).await.expect("scan");
    }
    let elapsed = start.elapsed();
    let total_probes = (REPEATS * 100) as f64;
    let pps = (total_probes / elapsed.as_secs_f64()) as u64;
    eprintln!(
        "loopback_engine_throughput: {REPEATS} runs × 100 ports = {} probes in {:?}; pps = {}",
        REPEATS * 100,
        elapsed,
        pps
    );

    // Sanity bound: even on a bad day we expect > 100k pps on loopback.
    // Lower means something is broken (rate limiter? syscall failure?).
    assert!(
        pps > 100_000,
        "loopback engine pps far below ceiling: {pps}"
    );
}
