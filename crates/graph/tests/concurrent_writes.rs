//! 8 threads × 1000 nodes each must land in the SQLite store without
//! data loss or deadlock.
//!
//! Per GOSSAN_LEGENDARY A18: prove SQLite WAL + busy_timeout=5000 are
//! enough that concurrent writers from gossan-engine + gossan-correlation
//! don't lose or corrupt rows.
//!
//! Each writer thread opens its own `SqliteBackend` against the same
//! file path (Arc<TempDir> keeps the file alive); SQLite WAL handles
//! the rest. We assert the final node count matches the expected
//! 8 * 1000 with a small budget for SQLite-replaced rows on PK collisions
//! (we use unique node IDs so collisions should be zero — assert ==).

use gossan_graph::store::sqlite::SqliteBackend;
use gossan_graph::store::GraphBackend;
use gossan_graph::{schema::NodeType, Node};
use std::sync::Arc;
use tempfile::TempDir;

const THREADS: usize = 8;
const NODES_PER_THREAD: usize = 1000;

#[test]
fn eight_threads_one_thousand_nodes_each_land_intact() {
    let dir = Arc::new(TempDir::new().unwrap());
    let path = dir.path().join("graph.sqlite");

    // Initialize once so the schema exists for the writers.
    {
        let _ = SqliteBackend::open(&path).expect("initial open");
    }

    let mut handles = Vec::with_capacity(THREADS);
    for tid in 0..THREADS {
        let p = path.clone();
        handles.push(std::thread::spawn(move || -> usize {
            let mut backend = match SqliteBackend::open(&p) {
                Ok(b) => b,
                Err(e) => panic!("thread {tid} open: {e}"),
            };
            let mut written = 0;
            // Write in small batches to mirror real engine traffic.
            const BATCH: usize = 50;
            let mut buf = Vec::with_capacity(BATCH);
            for i in 0..NODES_PER_THREAD {
                let id = format!("t{tid}-n{i}");
                let n = Node::new(id, NodeType::Ip, format!("10.{tid}.{}.1", i % 256));
                buf.push(n);
                if buf.len() == BATCH {
                    backend.write_nodes(&buf).expect("write batch");
                    written += buf.len();
                    buf.clear();
                }
            }
            if !buf.is_empty() {
                backend.write_nodes(&buf).expect("write tail");
                written += buf.len();
            }
            written
        }));
    }

    let total: usize = handles.into_iter().map(|h| h.join().unwrap()).sum();
    assert_eq!(total, THREADS * NODES_PER_THREAD);

    // Re-open and count.
    let backend = SqliteBackend::open(&path).expect("reopen");
    let nodes = backend.read_nodes().expect("read");
    assert_eq!(
        nodes.len(),
        THREADS * NODES_PER_THREAD,
        "concurrent writes lost rows: have {}, expected {}",
        nodes.len(),
        THREADS * NODES_PER_THREAD
    );
}
