#[cfg(feature = "graph")]
#[tokio::test]
async fn test_locked_database_handling_adversarial() {
    use gossan_core::{DiscoverySource, DomainTarget, Target};
    use gossan_graph::SqliteBackend as GraphStore;
    use rusqlite::Connection;
    use std::path::Path;

    let db_path = "test_locked_adv.db";
    if Path::new(db_path).exists() {
        let _ = std::fs::remove_file(db_path);
        let _ = std::fs::remove_file(format!("{}-wal", db_path));
        let _ = std::fs::remove_file(format!("{}-shm", db_path));
    }

    let mut store = GraphStore::open(db_path).expect("Failed to open DB");

    // Manually lock the database by starting a transaction on a separate connection
    let conn2 = Connection::open(db_path).expect("Failed to open second connection");
    conn2
        .execute("BEGIN EXCLUSIVE TRANSACTION", [])
        .expect("Failed to start exclusive tx");

    // Try to write from the first connection - should respect busy_timeout
    let start = std::time::Instant::now();
    let target = Target::Domain(DomainTarget {
        domain: "locked.com".into(),
        source: DiscoverySource::Seed,
    });

    let res = store.persist_scan(&[target], &[]);
    let duration = start.elapsed();

    assert!(res.is_err(), "Should have failed due to lock");
    assert!(
        duration.as_millis() >= 4000,
        "Should have waited for busy_timeout ({}ms)",
        duration.as_millis()
    );

    drop(conn2);
    let _ = std::fs::remove_file(db_path);
    let _ = std::fs::remove_file(format!("{}-wal", db_path));
    let _ = std::fs::remove_file(format!("{}-shm", db_path));
}
