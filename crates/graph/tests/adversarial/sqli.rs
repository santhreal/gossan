#[cfg(feature = "graph")]
#[test]
fn test_sqli_in_labels_adversarial() {
    use gossan_core::{DiscoverySource, DomainTarget, Target};
    use gossan_graph::SqliteBackend as GraphStore;
    use std::path::Path;

    let db_path = "test_sqli.db";
    if Path::new(db_path).exists() {
        let _ = std::fs::remove_file(db_path);
    }

    let mut store = GraphStore::open(db_path).expect("Failed to open DB");

    // Malicious domain label designed to break SQL queries
    let malicious_domain = "'; DROP TABLE targets; --";
    let t = Target::Domain(DomainTarget {
        domain: malicious_domain.into(),
        source: DiscoverySource::Seed,
    });

    // Should NOT crash and should correctly escape the string
    store
        .persist_scan(&[t], &[])
        .expect("Should handle SQLi in label");

    // Verify table still exists by querying it
    let count: i64 = store
        .conn()
        .query_row("SELECT COUNT(*) FROM targets", [], |row: &rusqlite::Row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(count, 1);

    let _ = std::fs::remove_file(db_path);
}
