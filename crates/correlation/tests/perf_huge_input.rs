//! Correlation engine perf gate.
//!
//! Per GOSSAN_LEGENDARY A12: 100k findings → chains computed in <500ms.

use gossan_correlation::CorrelationEngine;
use secfinding::{Finding, Severity};
use std::time::{Duration, Instant};

const N: usize = 100_000;
const MAX: Duration = Duration::from_millis(500);

fn synth_findings(n: usize) -> Vec<Finding> {
    (0..n)
        .map(|i| {
            Finding::builder(
                "portscan",
                format!("10.0.{}.{}", (i >> 8) & 0xff, i & 0xff),
                Severity::Info,
            )
            .title(format!("open: {}/tcp", 80 + (i % 1024) as u16))
            .detail("synthetic open port")
            .build()
            .expect("build finding")
        })
        .collect()
}

#[test]
#[cfg(not(debug_assertions))]
fn correlation_runs_under_500ms_on_100k_findings() {
    let engine = CorrelationEngine::new();
    let findings = synth_findings(N);
    let targets = Vec::new();
    let start = Instant::now();
    let _chains = engine.run(&findings, &targets);
    let elapsed = start.elapsed();
    eprintln!("correlation::run on {N} findings: {elapsed:?}");
    assert!(
        elapsed < MAX,
        "correlation::run took {elapsed:?} on {N} findings — exceeded {MAX:?} gate"
    );
}

#[test]
fn correlation_perf_gate_is_release_only() {
    // Stub so debug builds report a green test.
    let engine = CorrelationEngine::new();
    let _ = engine.run(&[], &[]);
}
