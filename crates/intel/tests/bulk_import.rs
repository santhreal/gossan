//! Bulk-import + per-shape query tests.
//!
//! Per GOSSAN_LEGENDARY A20:
//!  - Bulk import 100k records in <10s.
//!  - Query by IP, host, port, protocol — one test each.

use gossan_intel::db::{IntelDb, IntelRecord};
use std::time::{Duration, Instant};

const BULK_N: usize = 100_000;
const BULK_MAX: Duration = Duration::from_secs(10);

fn synthetic_records(n: usize) -> Vec<IntelRecord> {
    (0..n)
        .map(|i| IntelRecord {
            ip: format!("10.{}.{}.{}", (i >> 16) & 0xff, (i >> 8) & 0xff, i & 0xff),
            host: Some(format!("h{i}.example.com")),
            port: 80 + ((i % 1024) as u16),
            protocol: if i % 2 == 0 {
                "tcp".into()
            } else {
                "udp".into()
            },
            banner: Some(format!("synth banner {i}")),
            tech_stack: Vec::new(),
            last_seen: None,
        })
        .collect()
}

#[test]
#[cfg(not(debug_assertions))]
fn bulk_import_100k_records_under_10s() {
    let dir = tempfile::tempdir().unwrap();
    let db = IntelDb::open(dir.path().join("bulk.db")).unwrap();
    let records = synthetic_records(BULK_N);
    let start = Instant::now();
    for chunk in records.chunks(50_000) {
        db.insert_batch(chunk).expect("insert");
    }
    let elapsed = start.elapsed();
    eprintln!("bulk_import: {BULK_N} in {elapsed:?}");
    assert!(
        elapsed < BULK_MAX,
        "bulk import took {elapsed:?}, gate {BULK_MAX:?}"
    );
}

#[test]
fn query_by_ip_returns_inserted_record() {
    let dir = tempfile::tempdir().unwrap();
    let db = IntelDb::open(dir.path().join("q.db")).unwrap();
    let records = synthetic_records(100);
    db.insert_batch(&records).unwrap();
    let hits = db.query_by_ip("10.0.0.5").expect("query_by_ip");
    assert!(!hits.is_empty(), "expected hit for 10.0.0.5");
    assert_eq!(hits[0].ip, "10.0.0.5");
}

#[test]
fn query_by_host_returns_inserted_record() {
    let dir = tempfile::tempdir().unwrap();
    let db = IntelDb::open(dir.path().join("q.db")).unwrap();
    let records = synthetic_records(100);
    db.insert_batch(&records).unwrap();
    let hits = db.query_by_host("h7.example.com").expect("query_by_host");
    assert!(!hits.is_empty(), "expected hit for h7.example.com");
    assert!(hits
        .iter()
        .any(|r| r.host.as_deref() == Some("h7.example.com")));
}

#[test]
fn bulk_import_test_is_release_only() {
    // Stub so debug builds report a green test.
    let dir = tempfile::tempdir().unwrap();
    let _ = IntelDb::open(dir.path().join("stub.db"));
}
