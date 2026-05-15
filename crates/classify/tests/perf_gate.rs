//! Perf gate for the classify hot path.
//!
//! Per GOSSAN_LEGENDARY Section F: classify must sustain ≥100k
//! banners/sec on a single thread. This is the wall-clock check —
//! criterion microbench in a separate file gives detailed median/IQR.
//!
//! The test runs in `--release` mode only — debug-build numbers are
//! 10–30× slower and would fail this gate for no good reason. CI
//! invokes this via `cargo test --release -p gossan-classify`.

use gossan_classify::BannerClassifier;

/// Minimum classify throughput on a single thread. Calibrated for a
/// modern x86_64 desktop (5950X / 7950X tier); CI runners that are
/// 2× slower still clear this on release builds.
const MIN_BANNERS_PER_SEC: f64 = 100_000.0;

#[test]
#[cfg(not(debug_assertions))]
fn classify_sustains_100k_banners_per_sec_single_thread() {
    let c = BannerClassifier::new();

    // Real-world banner mix: 80% hits (nginx / apache / ssh),
    // 20% misses (random binary).
    let banners: Vec<&str> = (0..10_000)
        .map(|i| match i % 5 {
            0 => "Server: nginx/1.25.3\r\nContent-Type: text/html",
            1 => "Server: Apache/2.4.52 (Ubuntu)",
            2 => "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",
            3 => "+PONG\r\n",
            _ => "\x00\x01\x02\x03random-noise",
        })
        .collect();

    // Warm-up so first-call JIT / page-fault cost doesn't pollute.
    for b in banners.iter().take(1000) {
        let _ = c.classify(b);
    }

    let start = std::time::Instant::now();
    let mut hit_count = 0usize;
    for b in &banners {
        let hits = c.classify(b);
        hit_count += hits.len();
    }
    let elapsed = start.elapsed();

    let banners_per_sec = banners.len() as f64 / elapsed.as_secs_f64();
    println!(
        "classify: {} banners in {:?} = {:.0} banners/sec ({} total matches)",
        banners.len(),
        elapsed,
        banners_per_sec,
        hit_count
    );
    assert!(
        banners_per_sec >= MIN_BANNERS_PER_SEC,
        "classify throughput {:.0} banners/sec is below the {:.0} banners/sec gate",
        banners_per_sec,
        MIN_BANNERS_PER_SEC
    );
}

#[test]
fn classify_perf_gate_is_release_only() {
    // Stub test so debug builds report something — the real gate runs
    // only when debug_assertions is off (release / opt-level≥1).
    let c = BannerClassifier::new();
    let _ = c.classify("Server: nginx");
}
