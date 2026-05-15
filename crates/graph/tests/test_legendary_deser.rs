use gossan_core::{DiscoverySource, DomainTarget, Target};
// `GraphStore` was renamed to `SqliteBackend` when the graph store
// gained per-backend implementations (sqlite/json/graphml). The
// public `open` / `persist_scan` / `conn` API is otherwise unchanged.
use gossan_graph::SqliteBackend as GraphStore;
use secfinding::{Finding, Severity};
use tempfile::tempdir;

#[test]
fn test_graph_serialization_deserialization() {
    let dir = tempdir().unwrap();
    let mut store = GraphStore::open(dir.path().join("db.sqlite")).unwrap();
    
    let t = Target::Domain(DomainTarget {
        domain: "deserialize.com".to_string(),
        source: DiscoverySource::Seed,
    });
    
    let f = Finding::builder(
        "deser_scanner".to_string(),
        "deserialize.com".to_string(),
        Severity::High,
    )
    .title("Test deser")
    .detail("Deser detail")
    .build()
    .unwrap();
    
    store.persist_scan(&[t.clone()], &[f.clone()]).unwrap();
    
    let db_path = dir.path().join("db.sqlite");
    let store2 = GraphStore::open(&db_path).unwrap();
    
    // Test that the items deserialized match the original
    let count_targets: i64 = store2.conn().query_row("SELECT count(*) FROM targets", [], |row| row.get(0)).unwrap();
    assert_eq!(count_targets, 1);
    
    let count_findings: i64 = store2.conn().query_row("SELECT count(*) FROM findings", [], |row| row.get(0)).unwrap();
    assert_eq!(count_findings, 1);
    
    let count_rels: i64 = store2.conn().query_row("SELECT count(*) FROM relationships", [], |row| row.get(0)).unwrap();
    assert_eq!(count_rels, 1);
    
    let data: String = store2.conn().query_row("SELECT data FROM targets LIMIT 1", [], |row| row.get(0)).unwrap();
    let deserialized_t: Target = serde_json::from_str(&data).unwrap();
    if let Target::Domain(dt) = deserialized_t {
        assert_eq!(dt.domain, "deserialize.com");
    } else {
        panic!("Wrong target type");
    }
}
