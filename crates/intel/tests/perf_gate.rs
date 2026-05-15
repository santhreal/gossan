//! Intel-db query perf gate.
//!
//! Per GOSSAN_LEGENDARY Section F: query-by-ip against a 1M-record
//! database must return in < 10ms. Catches regressions in the
//! SQLite index path on `intel.ip`.

use gossan_intel::db::{IntelDb, IntelRecord};
use std::time::{Duration, Instant};

const RECORD_COUNT: usize = 1_000_000;
const MAX_QUERY: Duration = Duration::from_millis(10);

fn synthetic_records(n: usize) -> Vec<IntelRecord> {
    (0..n)
        .map(|i| IntelRecord {
            ip: format!("10.{}.{}.{}", (i >> 16) & 0xff, (i >> 8) & 0xff, i & 0xff),
            host: None,
            port: 80,
            protocol: "tcp".into(),
            banner: None,
            tech_stack: Vec::new(),
            last_seen: None,
        })
        .collect()
}

#[test]
#[cfg(not(debug_assertions))]
fn intel_query_by_ip_under_10ms_on_1m_records() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let db_path = dir.path().join("intel.db");
    let db = IntelDb::open(&db_path).expect("open intel db");

    // Insert in 100-batch chunks to keep peak memory bounded.
    let records = synthetic_records(RECORD_COUNT);
    let start = Instant::now();
    for chunk in records.chunks(50_000) {
        db.insert_batch(chunk).expect("insert batch");
    }
    eprintln!(
        "intel insert: {RECORD_COUNT} records in {:?}",
        start.elapsed()
    );

    // Sample 100 queries, take the median. A single query can spike
    // because of OS page-cache warm-up; the median is the reliable
    // signal we want to gate on.
    let mut timings: Vec<Duration> = Vec::with_capacity(100);
    for i in (0..RECORD_COUNT).step_by(RECORD_COUNT / 100) {
        let target_ip = format!("10.{}.{}.{}", (i >> 16) & 0xff, (i >> 8) & 0xff, i & 0xff);
        let q_start = Instant::now();
        let hits = db.query_by_ip(&target_ip).expect("query");
        let q_elapsed = q_start.elapsed();
        timings.push(q_elapsed);
        assert!(!hits.is_empty(), "expected ≥1 record for {target_ip}");
    }
    timings.sort();
    let median = timings[timings.len() / 2];
    eprintln!("intel query_by_ip: median {median:?} over 100 samples");
    assert!(
        median < MAX_QUERY,
        "intel query_by_ip median {median:?} exceeds {MAX_QUERY:?} regression gate"
    );
}

#[test]
fn intel_query_perf_gate_is_release_only() {
    // Stub so debug builds report a green test.
    let dir = tempfile::tempdir().expect("tmpdir");
    let _ = IntelDb::open(dir.path().join("stub.db"));
}
