//! Concurrent read tests — prove `IntelDb` is safe under parallel
//! query load.
//!
//! Per GOSSAN_LEGENDARY A20: 32 threads × 1000 queries each, no
//! deadlock, all return correct results.

use gossan_intel::db::{IntelDb, IntelRecord};
use std::sync::Arc;

const N_RECORDS: usize = 10_000;
const N_THREADS: usize = 32;
const QUERIES_PER_THREAD: usize = 1_000;

fn synth(n: usize) -> Vec<IntelRecord> {
    (0..n)
        .map(|i| IntelRecord {
            ip: format!("10.{}.{}.{}", (i >> 16) & 0xff, (i >> 8) & 0xff, i & 0xff),
            host: Some(format!("h{i}.example.com")),
            port: 80 + ((i % 1024) as u16),
            protocol: "tcp".into(),
            banner: None,
            tech_stack: Vec::new(),
            last_seen: None,
        })
        .collect()
}

#[test]
fn concurrent_reads_correct_and_no_deadlock() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("concurrent.db");
    let db = IntelDb::open(&path).unwrap();
    db.insert_batch(&synth(N_RECORDS)).unwrap();
    drop(db);

    let path = Arc::new(path);
    let mut handles = Vec::with_capacity(N_THREADS);
    for thread_id in 0..N_THREADS {
        let path = Arc::clone(&path);
        handles.push(std::thread::spawn(move || -> usize {
            let db = IntelDb::open(&*path).expect("open in worker");
            let mut hits_total = 0usize;
            for q in 0..QUERIES_PER_THREAD {
                let i = (thread_id * QUERIES_PER_THREAD + q) % N_RECORDS;
                let target_ip =
                    format!("10.{}.{}.{}", (i >> 16) & 0xff, (i >> 8) & 0xff, i & 0xff);
                let hits = db.query_by_ip(&target_ip).expect("query");
                if !hits.is_empty() {
                    hits_total += 1;
                }
            }
            hits_total
        }));
    }
    let mut total_hits = 0usize;
    for h in handles {
        total_hits += h.join().expect("thread join");
    }
    let expected = N_THREADS * QUERIES_PER_THREAD;
    assert_eq!(
        total_hits, expected,
        "expected {expected} successful queries, got {total_hits}"
    );
}
