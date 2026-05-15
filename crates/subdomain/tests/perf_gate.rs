//! Subdomain dedup throughput gate.
//!
//! Per GOSSAN_LEGENDARY Section F: subdomain enumeration must sustain
//! ≥ 10k domains/min via wordlist. The wordlist arm is bounded by DNS
//! resolution which we can't measure without live network; instead
//! we hold the pre-resolution dedup path (normalize → punycode →
//! HashSet insert) to a high bar so a regression there isn't masked
//! by the slower resolver.

use gossan_subdomain::dedup::dedup_domains;
use std::time::{Duration, Instant};

const CANDIDATE_COUNT: usize = 100_000;
const MIN_RATE: f64 = 1_000_000.0; // domains/sec post-dedup

#[test]
#[cfg(not(debug_assertions))]
fn subdomain_dedup_100k_under_1s() {
    // Mix of duplicates, punycode, mixed case, trailing dots — the
    // shapes the live sources actually emit.
    let mut domains: Vec<String> = Vec::with_capacity(CANDIDATE_COUNT);
    for i in 0..CANDIDATE_COUNT {
        let n = i % 1000;
        match i % 5 {
            0 => domains.push(format!("HOST{n}.example.com")),
            1 => domains.push(format!("host{n}.example.com.")),
            2 => domains.push(format!("host{n}.EXAMPLE.com")),
            3 => domains.push(format!("xn--hst{n}-tla.example.com")),
            _ => domains.push(format!("svc-{n}.example.com")),
        }
    }

    let start = Instant::now();
    let result = dedup_domains(domains.clone());
    let elapsed = start.elapsed();

    let rate = domains.len() as f64 / elapsed.as_secs_f64();
    eprintln!(
        "subdomain dedup: {} candidates in {elapsed:?} → {} unique ({rate:.0}/s)",
        domains.len(),
        result.len()
    );
    assert!(elapsed < Duration::from_secs(1), "dedup took {elapsed:?}");
    assert!(
        rate >= MIN_RATE,
        "subdomain dedup: {rate:.0}/s is below {MIN_RATE:.0}/s regression gate"
    );
}

#[test]
fn subdomain_perf_gate_is_release_only() {
    let _ = dedup_domains(["example.com".to_string()]);
}
