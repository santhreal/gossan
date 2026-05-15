use gossan_core::{DiscoverySource, DomainTarget, Target};
// `GraphStore` was renamed to `SqliteBackend` (per-backend graph
// store implementations now live under `store::*`). Use the
// alias-import form so the rest of the test reads identically.
// `GraphError` similarly became `SqliteError`. The free-function
// `target_id` is re-exported at crate root for tests that pin the
// deterministic Target → node-ID mapping (e.g.
// "domain:example.com").
use gossan_graph::{
    store::sqlite::SqliteError as GraphError, target_id, SqliteBackend as GraphStore,
};
use secfinding::{Finding, Severity};
use std::time::Duration;
use tempfile::tempdir;

fn test_target() -> Target {
    Target::Domain(DomainTarget {
        domain: "example.com".into(),
        source: DiscoverySource::Seed,
    })
}

fn test_target2() -> Target {
    Target::Domain(DomainTarget {
        domain: "test.com".into(),
        source: DiscoverySource::Seed,
    })
}

fn test_finding(target: &Target) -> Finding {
    Finding::builder(
        "test_scanner".to_string(),
        target.domain().unwrap_or("unknown").to_string(),
        Severity::High,
    )
    .title("Test finding")
    .detail("This is a test finding")
    .build()
    .unwrap()
}

#[test]
fn test_open_success_and_schema() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("test.db");

    let store = GraphStore::open(&db_path).unwrap();

    // Check if tables exist
    let mut stmt = store
        .conn()
        .prepare("SELECT name FROM sqlite_master WHERE type='table'")
        .unwrap();
    let tables: Vec<String> = stmt
        .query_map([], |row: &rusqlite::Row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();

    assert!(tables.contains(&"targets".to_string()));
    assert!(tables.contains(&"findings".to_string()));
    assert!(tables.contains(&"relationships".to_string()));
}

#[test]
fn test_open_invalid_path() {
    let result = GraphStore::open("/invalid/path/that/does/not/exist/test.db");
    assert!(matches!(result, Err(GraphError::Sqlite(_))));
}

#[test]
fn test_target_id_generation() {
    let t1 = test_target();
    let id1 = target_id(&t1);
    assert_eq!(id1, "domain:example.com");

    let t2 = Target::Domain(DomainTarget {
        domain: "example.com".into(),
        source: DiscoverySource::DnsBruteforce,
    });
    let id2 = target_id(&t2);

    // ID should be stable for the same domain regardless of source
    assert_eq!(id1, id2);
}

#[test]
fn test_persist_scan_and_compute_diff() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("test.db");
    let mut store = GraphStore::open(&db_path).unwrap();

    let t1 = test_target();
    let f1 = test_finding(&t1);

    // Initial persistence
    let persist_res = store.persist_scan(&[t1.clone()], &[f1.clone()]);
    assert!(persist_res.is_ok());

    // Check data in db
    let count: i64 = store
        .conn()
        .query_row("SELECT count(*) FROM targets", [], |row: &rusqlite::Row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(count, 1);

    // Diff against same data
    let diff = store
        .compute_diff(&[t1.clone()], &[f1.clone()], Duration::from_secs(10))
        .unwrap();
    assert!(diff.added_targets.is_empty());
    assert!(diff.changed_targets.is_empty());
    assert!(diff.removed_targets.is_empty());
    assert!(diff.added_findings.is_empty());
    assert!(diff.changed_findings.is_empty());
    assert!(diff.removed_findings.is_empty());

    // Add new target
    let t2 = test_target2();
    let diff2 = store
        .compute_diff(&[t2.clone()], &[], Duration::from_secs(10))
        .unwrap();
    assert_eq!(diff2.added_targets.len(), 1);
    assert_eq!(target_id(&diff2.added_targets[0]), target_id(&t2));

    // Simulate removed target by querying with 0 duration (everything is older than 0 secs ago)
    std::thread::sleep(std::time::Duration::from_millis(100)); // sleep to ensure some time passed
    let diff3 = store
        .compute_diff(&[], &[], Duration::from_secs(0))
        .unwrap();
    assert_eq!(diff3.removed_targets.len(), 1);
    assert_eq!(diff3.removed_findings.len(), 1);
}
