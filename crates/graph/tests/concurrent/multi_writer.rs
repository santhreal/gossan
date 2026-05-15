#[cfg(feature = "graph")]
#[tokio::test]
async fn test_concurrency_robustness_multi_writer() {
    use gossan_graph::SqliteBackend as GraphStore;
    use gossan_core::{Target, DiscoverySource, DomainTarget};
    use std::path::Path;
    use tokio::task;

    let db_path = "test_concurrent_multi.db";
    if Path::new(db_path).exists() {
        let _ = std::fs::remove_file(db_path);
        let _ = std::fs::remove_file(format!("{}-wal", db_path));
        let _ = std::fs::remove_file(format!("{}-shm", db_path));
    }

    // Initialize DB
    {
        let _ = GraphStore::open(db_path).expect("Failed to open DB");
    }

    let mut handles = vec![];
    for i in 0..10 {
        let path = db_path.to_string();
        handles.push(task::spawn_blocking(move || {
            let mut store = GraphStore::open(&path).expect("Failed to open DB in thread");
            // Simulate some write activity
            for j in 0..50 {
                let target = Target::Domain(DomainTarget {
                    domain: format!("thread-{}-domain-{}.com", i, j),
                    source: DiscoverySource::Seed,
                });
                store.persist_scan(&[target], &[]).expect("Failed to persist");
            }
        }));
    }

    for h in handles {
        h.await.expect("Task failed");
    }

    let _ = std::fs::remove_file(db_path);
    let _ = std::fs::remove_file(format!("{}-wal", db_path));
    let _ = std::fs::remove_file(format!("{}-shm", db_path));
}
