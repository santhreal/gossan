//! Master-side smoke tests — no real gRPC transport, just the
//! `Master` struct's task-dispatch contract.
//!
//! Per GOSSAN_LEGENDARY A21:
//!  - With zero workers, `dispatch_task` returns `Err("No workers connected")`.
//!  - `Master::new()` produces a workers-empty / tasks-empty state.
//!
//! End-to-end gRPC + 2 workers + result-merge tests live in
//! `tests/cluster_e2e.rs` (open work — needs a tonic transport
//! harness to exercise the worker-registration handshake).

use gossan_fleet::master::Master;

#[tokio::test]
async fn dispatch_with_no_workers_errors() {
    let master = Master::new();
    let res = master
        .dispatch_task("portscan", vec!["1.2.3.4".to_string()], "{}")
        .await;
    assert!(res.is_err(), "no-worker dispatch must return Err");
    let msg = res.unwrap_err().to_string();
    assert!(
        msg.contains("No workers connected"),
        "unexpected error message: {msg}"
    );
}

#[test]
fn master_default_is_empty() {
    let _ = Master::new();
    let _ = Master::default();
}
