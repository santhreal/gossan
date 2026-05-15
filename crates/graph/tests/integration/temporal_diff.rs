#[cfg(feature = "graph")]
#[tokio::test]
async fn test_temporal_diffing_integration() {
    use gossan_core::{DiscoverySource, DomainTarget, Target};
    use gossan_graph::SqliteBackend as GraphStore;
    use std::path::Path;

    let db_path = "test_temporal_int.db";
    if Path::new(db_path).exists() {
        let _ = std::fs::remove_file(db_path);
    }

    let mut store = GraphStore::open(db_path).expect("Failed to open DB");

    let t1 = Target::Domain(DomainTarget {
        domain: "seen-once.com".into(),
        source: DiscoverySource::Seed,
    });

    // First scan
    store
        .persist_scan(&[t1.clone()], &[])
        .expect("First scan failed");

    // Sleep to ensure timestamp changes (resolution is 1s)
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    // Second scan with same target + new target
    let t2 = Target::Domain(DomainTarget {
        domain: "new-domain.com".into(),
        source: DiscoverySource::Seed,
    });

    let diff = store
        .compute_diff(
            &[t1.clone(), t2.clone()],
            &[],
            std::time::Duration::from_secs(60),
        )
        .expect("Diff failed");
    assert_eq!(diff.added_targets.len(), 1);
    assert_eq!(
        gossan_graph::target_id(&diff.added_targets[0]),
        "domain:new-domain.com"
    );
    assert_eq!(diff.changed_targets.len(), 0);

    // Test Removal (Past)
    // We can't easily wait hours, so we manually update DB for test
    // GraphStore doesn't expose conn, but we can open a new one
    {
        let conn = rusqlite::Connection::open(db_path).unwrap();
        conn.execute(
            "UPDATE targets SET last_seen = datetime('now', '-2 hours') WHERE id = 'domain:seen-once.com'",
            []
        ).expect("Manual update failed");
    }

    let diff = store
        .compute_diff(&[], &[], std::time::Duration::from_secs(3600))
        .expect("Diff failed");
    assert_eq!(
        diff.removed_targets.len(),
        1,
        "Old last_seen should be considered removed"
    );

    let _ = std::fs::remove_file(db_path);
}
