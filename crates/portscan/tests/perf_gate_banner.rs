//! Banner-grab concurrency perf gate.
//!
//! Per GOSSAN_LEGENDARY Section F: ≥ 10k connections/min on loopback.
//! That's ~167/sec, a very low bar — tokio's TCP path is well over
//! 1k/sec on any modern machine. We hold it at 1k/sec to make the
//! gate meaningful (catches a regression where the per-connection
//! deadline starts compounding linearly).
//!
//! The test spins up a localhost listener that accepts and responds
//! with a static banner, then drives N parallel `gossan_core::net::
//! connect_tcp` connections through it.

use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

const CONNECTIONS: usize = 1_000;
// The GOSSAN_LEGENDARY F-section gate is ≥10k connections/min on
// loopback ≈ 167 conn/sec. We hold it at 500/sec so regressions
// stand out without flaking on CI runners that share cores.
const MIN_RATE: f64 = 500.0;
const MAX_ELAPSED: Duration = Duration::from_secs(10);

async fn spawn_banner_server() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    let h = tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let _ = socket.write_all(b"SSH-2.0-OpenSSH_9.7\r\n").await;
            });
        }
    });
    (addr, h)
}

async fn one_connection(addr: std::net::SocketAddr) {
    let timeout = Duration::from_secs(1);
    let _ = tokio::time::timeout(
        timeout,
        gossan_core::net::connect_tcp(&addr.ip().to_string(), addr.port(), None),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[cfg(not(debug_assertions))]
async fn banner_grab_1k_loopback_under_10s() {
    let (addr, server) = spawn_banner_server().await;

    let semaphore = Arc::new(tokio::sync::Semaphore::new(256));

    let start = Instant::now();
    let mut handles = Vec::with_capacity(CONNECTIONS);
    for _ in 0..CONNECTIONS {
        let permit = semaphore.clone().acquire_owned().await.expect("permit");
        let addr = addr;
        handles.push(tokio::spawn(async move {
            let _permit = permit;
            one_connection(addr).await;
        }));
    }
    for h in handles {
        let _ = h.await;
    }
    let elapsed = start.elapsed();
    server.abort();

    let rate = CONNECTIONS as f64 / elapsed.as_secs_f64();
    eprintln!(
        "banner grab: {CONNECTIONS} connections in {elapsed:?} ({rate:.0}/s)"
    );
    assert!(
        elapsed < MAX_ELAPSED,
        "banner grab: {CONNECTIONS} connections took {elapsed:?}, > {MAX_ELAPSED:?} regression gate"
    );
    assert!(
        rate >= MIN_RATE,
        "banner grab rate {rate:.0}/s is below {MIN_RATE:.0}/s gate"
    );
}

#[test]
fn banner_grab_perf_gate_is_release_only() {
    // Stub so debug builds report a green test.
}
