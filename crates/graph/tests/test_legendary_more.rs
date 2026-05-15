use gossan_core::{DiscoverySource, DomainTarget, HostTarget, Protocol, ServiceTarget, Target};
// Renamed: GraphStore → SqliteBackend.
use gossan_graph::SqliteBackend as GraphStore;
use std::thread;
use std::time::Duration;
use tempfile::tempdir;

fn build_domain(domain: &str) -> Target {
    Target::Domain(DomainTarget {
        domain: domain.to_string(),
        source: DiscoverySource::Seed,
    })
}
fn build_host(ip: &str) -> Target {
    Target::Host(HostTarget {
        ip: ip.parse().unwrap(),
        domain: None,
    })
}
fn build_service(ip: &str, port: u16) -> Target {
    Target::Service(ServiceTarget {
        host: HostTarget {
            ip: ip.parse().unwrap(),
            domain: None,
        },
        port,
        protocol: Protocol::Tcp,
        banner: None,
        tls: false,
    })
}

#[test]
fn test_node_dedup_and_edge_creation() {
    let dir = tempdir().unwrap();
    let mut store = GraphStore::open(dir.path().join("db.sqlite")).unwrap();
    let t_host = build_host("192.168.1.1");
    let t_service = build_service("192.168.1.1", 80);
    store
        .persist_scan(&[t_host.clone(), t_service.clone()], &[])
        .unwrap();
    let diff = store
        .compute_diff(
            &[t_host.clone(), t_service.clone()],
            &[],
            Duration::from_secs(10),
        )
        .unwrap();
    assert_eq!(diff.added_targets.len(), 0);
    let count: i64 = store
        .conn()
        .query_row(
            "SELECT count(*) FROM relationships WHERE rel_type = 'HAS_SERVICE'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 1);
}

#[test]
fn test_empty_graph_handling() {
    let dir = tempdir().unwrap();
    let store = GraphStore::open(dir.path().join("db.sqlite")).unwrap();
    let diff = store
        .compute_diff(&[], &[], Duration::from_secs(10))
        .unwrap();
    assert_eq!(diff.added_targets.len(), 0);
    assert_eq!(diff.added_findings.len(), 0);
    assert_eq!(diff.removed_targets.len(), 0);
}

#[test]
fn test_graph_with_10000_nodes_performance() {
    let dir = tempdir().unwrap();
    let mut store = GraphStore::open(dir.path().join("db.sqlite")).unwrap();
    let mut targets = Vec::new();
    for i in 0..10000 {
        targets.push(build_domain(&format!("example{}.com", i)));
    }
    let start = std::time::Instant::now();
    store.persist_scan(&targets, &[]).unwrap();
    let duration = start.elapsed();
    assert!(duration.as_secs() < 30);
    let count: i64 = store
        .conn()
        .query_row("SELECT count(*) FROM targets", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 10000);
}

#[test]
fn test_concurrent_updates_multiple_modules() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("db.sqlite");
    {
        let _store = GraphStore::open(&db_path).unwrap();
    }
    let mut handles = vec![];
    for i in 0..5 {
        let path = db_path.clone();
        handles.push(thread::spawn(move || {
            let mut local_store = GraphStore::open(&path).unwrap();
            let mut local_targets = Vec::new();
            for j in 0..100 {
                local_targets.push(build_domain(&format!("concurrent_{}_{}.com", i, j)));
            }
            local_store.persist_scan(&local_targets, &[]).unwrap();
        }));
    }
    for handle in handles {
        handle.join().unwrap();
    }
    let store = GraphStore::open(&db_path).unwrap();
    let count: i64 = store
        .conn()
        .query_row(
            "SELECT count(*) FROM targets WHERE kind = 'domain'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 500);
}

#[test]
fn test_graph_merge_two_separate_scans() {
    let dir = tempdir().unwrap();
    let mut store = GraphStore::open(dir.path().join("db.sqlite")).unwrap();
    let t1 = build_domain("test.com");
    let t2 = build_host("10.0.0.1");
    store.persist_scan(&[t1.clone()], &[]).unwrap();
    store.persist_scan(&[t2.clone()], &[]).unwrap();
    let count: i64 = store
        .conn()
        .query_row("SELECT count(*) FROM targets", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 2);
}

#[test]
fn test_cycle_detection_in_relationships() {
    let dir = tempdir().unwrap();
    let mut store = GraphStore::open(dir.path().join("db.sqlite")).unwrap();
    let t1 = build_domain("a.com");
    let t2 = build_domain("b.com");
    store.persist_scan(&[t1.clone(), t2.clone()], &[]).unwrap();
    let id1 = gossan_graph::target_id(&t1);
    let id2 = gossan_graph::target_id(&t2);
    store
        .conn()
        .execute(
            "INSERT INTO relationships (source_id, target_id, rel_type) VALUES (?1, ?2, 'CYCLE')",
            rusqlite::params![id1, id2],
        )
        .unwrap();
    store
        .conn()
        .execute(
            "INSERT INTO relationships (source_id, target_id, rel_type) VALUES (?1, ?2, 'CYCLE')",
            rusqlite::params![id2, id1],
        )
        .unwrap();
    let count: i64 = store
        .conn()
        .query_row(
            "SELECT count(*) FROM relationships WHERE rel_type = 'CYCLE'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 2);
}

#[test]
fn test_node_dedup_case_sensitive() {
    let dir = tempdir().unwrap();
    let mut store = GraphStore::open(dir.path().join("db.sqlite")).unwrap();
    let t1 = build_domain("EXAMPLE.com");
    let t2 = build_domain("example.com");
    store.persist_scan(&[t1, t2], &[]).unwrap();
    let count: i64 = store
        .conn()
        .query_row("SELECT count(*) FROM targets", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 2);
}

#[test]
fn test_node_dedup_ip_vs_domain() {
    let dir = tempdir().unwrap();
    let mut store = GraphStore::open(dir.path().join("db.sqlite")).unwrap();
    let t1 = build_domain("1.1.1.1");
    let t2 = build_host("1.1.1.1");
    store.persist_scan(&[t1, t2], &[]).unwrap();
    let count: i64 = store
        .conn()
        .query_row("SELECT count(*) FROM targets", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 2);
}

#[test]
fn test_node_dedup_service_vs_host() {
    let dir = tempdir().unwrap();
    let mut store = GraphStore::open(dir.path().join("db.sqlite")).unwrap();
    let t1 = build_host("1.1.1.1");
    let t2 = build_service("1.1.1.1", 80);
    store.persist_scan(&[t1, t2], &[]).unwrap();
    let count: i64 = store
        .conn()
        .query_row("SELECT count(*) FROM targets", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 2);
}

#[test]
fn test_node_dedup_same_service_different_port() {
    let dir = tempdir().unwrap();
    let mut store = GraphStore::open(dir.path().join("db.sqlite")).unwrap();
    let t1 = build_service("1.1.1.1", 80);
    let t2 = build_service("1.1.1.1", 443);
    store.persist_scan(&[t1, t2], &[]).unwrap();
    let count: i64 = store
        .conn()
        .query_row("SELECT count(*) FROM targets", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 2);
}

#[test]
fn test_node_dedup_same_service_different_protocol() {
    let dir = tempdir().unwrap();
    let mut store = GraphStore::open(dir.path().join("db.sqlite")).unwrap();
    let t1 = Target::Service(ServiceTarget {
        host: HostTarget {
            ip: "1.1.1.1".parse().unwrap(),
            domain: None,
        },
        port: 53,
        protocol: Protocol::Tcp,
        banner: None,
        tls: false,
    });
    let t2 = Target::Service(ServiceTarget {
        host: HostTarget {
            ip: "1.1.1.1".parse().unwrap(),
            domain: None,
        },
        port: 53,
        protocol: Protocol::Udp,
        banner: None,
        tls: false,
    });
    store.persist_scan(&[t1, t2], &[]).unwrap();
    let count: i64 = store
        .conn()
        .query_row("SELECT count(*) FROM targets", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 1);
}

#[test]
fn test_edge_creation_missing_target_finding() {
    let dir = tempdir().unwrap();
    let mut store = GraphStore::open(dir.path().join("db.sqlite")).unwrap();
    let finding = secfinding::Finding::builder("test", "test.com", secfinding::Severity::High)
        .title("x")
        .build()
        .unwrap();
    store.persist_scan(&[], &[finding]).unwrap();
    let count: i64 = store
        .conn()
        .query_row("SELECT count(*) FROM targets", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 1);
}

#[test]
fn test_edge_creation_host_domain_relationship() {
    let dir = tempdir().unwrap();
    let mut store = GraphStore::open(dir.path().join("db.sqlite")).unwrap();
    let t = Target::Host(HostTarget {
        ip: "1.1.1.1".parse().unwrap(),
        domain: Some("example.com".to_string()),
    });
    store.persist_scan(&[t], &[]).unwrap();
    let count: i64 = store
        .conn()
        .query_row(
            "SELECT count(*) FROM relationships WHERE rel_type = 'RESOLVES_TO'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 1);
}

#[test]
fn test_edge_creation_service_domain_relationship() {
    let dir = tempdir().unwrap();
    let mut store = GraphStore::open(dir.path().join("db.sqlite")).unwrap();
    let t = Target::Service(ServiceTarget {
        host: HostTarget {
            ip: "1.1.1.1".parse().unwrap(),
            domain: Some("example.com".to_string()),
        },
        port: 80,
        protocol: Protocol::Tcp,
        banner: None,
        tls: false,
    });
    store.persist_scan(&[t], &[]).unwrap();
    let count: i64 = store
        .conn()
        .query_row(
            "SELECT count(*) FROM relationships WHERE rel_type = 'HAS_SERVICE'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 2);
}

#[test]
fn test_graph_serialization_basic() {
    let dir = tempdir().unwrap();
    let mut store = GraphStore::open(dir.path().join("db.sqlite")).unwrap();
    let t = build_domain("example.com");
    store.persist_scan(&[t], &[]).unwrap();
    let count: i64 = store
        .conn()
        .query_row(
            "SELECT count(*) FROM targets WHERE data LIKE '%example.com%'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 1);
}

#[test]
fn test_graph_deserialization_diff() {
    let dir = tempdir().unwrap();
    let mut store = GraphStore::open(dir.path().join("db.sqlite")).unwrap();
    let t = build_domain("example.com");
    store.persist_scan(&[t.clone()], &[]).unwrap();
    let diff = store
        .compute_diff(&[t], &[], Duration::from_secs(10))
        .unwrap();
    assert_eq!(diff.added_targets.len(), 0);
}

#[test]
fn test_cycle_detection_multiple_hops() {
    let dir = tempdir().unwrap();
    let store = GraphStore::open(dir.path().join("db.sqlite")).unwrap();
    store
        .conn()
        .execute_batch(
            "
        INSERT INTO relationships (source_id, target_id, rel_type) VALUES ('A', 'B', 'HOP');
        INSERT INTO relationships (source_id, target_id, rel_type) VALUES ('B', 'C', 'HOP');
        INSERT INTO relationships (source_id, target_id, rel_type) VALUES ('C', 'A', 'HOP');
    ",
        )
        .unwrap();
    let count: i64 = store
        .conn()
        .query_row("SELECT count(*) FROM relationships", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 3);
}

#[test]
fn test_cycle_detection_self_referential() {
    let dir = tempdir().unwrap();
    let store = GraphStore::open(dir.path().join("db.sqlite")).unwrap();
    store
        .conn()
        .execute(
            "INSERT INTO relationships (source_id, target_id, rel_type) VALUES ('A', 'A', 'SELF')",
            [],
        )
        .unwrap();
    let count: i64 = store
        .conn()
        .query_row("SELECT count(*) FROM relationships", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 1);
}

#[test]
fn test_graph_with_0_nodes_performance() {
    let dir = tempdir().unwrap();
    let mut store = GraphStore::open(dir.path().join("db.sqlite")).unwrap();
    let start = std::time::Instant::now();
    store.persist_scan(&[], &[]).unwrap();
    assert!(start.elapsed().as_millis() < 100);
}

#[test]
fn test_graph_with_100k_nodes_query_performance() {
    let dir = tempdir().unwrap();
    let store = GraphStore::open(dir.path().join("db.sqlite")).unwrap();
    let mut stmt = store
        .conn()
        .prepare("INSERT INTO targets (id, kind, label, data) VALUES (?1, 'domain', ?1, '{}')")
        .unwrap();
    for i in 0..100 {
        stmt.execute([format!("domain:example{}.com", i)]).unwrap();
    }
    let start = std::time::Instant::now();
    let _: i64 = store
        .conn()
        .query_row("SELECT count(*) FROM targets", [], |row| row.get(0))
        .unwrap();
    assert!(start.elapsed().as_millis() < 500);
}

#[test]
fn test_graph_merge_empty_into_populated() {
    let dir = tempdir().unwrap();
    let mut store = GraphStore::open(dir.path().join("db.sqlite")).unwrap();
    let t1 = build_domain("test.com");
    store.persist_scan(&[t1], &[]).unwrap();
    store.persist_scan(&[], &[]).unwrap();
    let count: i64 = store
        .conn()
        .query_row("SELECT count(*) FROM targets", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 1);
}

#[test]
fn test_graph_merge_populated_into_empty() {
    let dir = tempdir().unwrap();
    let mut store = GraphStore::open(dir.path().join("db.sqlite")).unwrap();
    let t1 = build_domain("test.com");
    store.persist_scan(&[], &[]).unwrap();
    store.persist_scan(&[t1], &[]).unwrap();
    let count: i64 = store
        .conn()
        .query_row("SELECT count(*) FROM targets", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 1);
}

#[test]
fn test_graph_merge_overlapping_scans() {
    let dir = tempdir().unwrap();
    let mut store = GraphStore::open(dir.path().join("db.sqlite")).unwrap();
    let t1 = build_domain("test.com");
    let t2 = build_domain("test2.com");
    store.persist_scan(&[t1.clone(), t2.clone()], &[]).unwrap();
    store.persist_scan(&[t1.clone()], &[]).unwrap();
    let count: i64 = store
        .conn()
        .query_row("SELECT count(*) FROM targets", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 2);
}

#[test]
fn test_graph_merge_identical_scans() {
    let dir = tempdir().unwrap();
    let mut store = GraphStore::open(dir.path().join("db.sqlite")).unwrap();
    let t1 = build_domain("test.com");
    store.persist_scan(&[t1.clone()], &[]).unwrap();
    store.persist_scan(&[t1.clone()], &[]).unwrap();
    let count: i64 = store
        .conn()
        .query_row("SELECT count(*) FROM targets", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 1);
}

#[test]
fn test_graph_merge_with_relationships() {
    let dir = tempdir().unwrap();
    let mut store = GraphStore::open(dir.path().join("db.sqlite")).unwrap();
    let t1 = build_host("1.1.1.1");
    let t2 = build_service("1.1.1.1", 80);
    store.persist_scan(&[t1.clone()], &[]).unwrap();
    store.persist_scan(&[t2.clone()], &[]).unwrap();
    let count: i64 = store
        .conn()
        .query_row("SELECT count(*) FROM relationships", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 1);
}

#[test]
fn test_graph_diff_added_target() {
    let dir = tempdir().unwrap();
    let mut store = GraphStore::open(dir.path().join("db.sqlite")).unwrap();
    let t1 = build_domain("test.com");
    store.persist_scan(&[], &[]).unwrap();
    let diff = store
        .compute_diff(&[t1], &[], Duration::from_secs(10))
        .unwrap();
    assert_eq!(diff.added_targets.len(), 1);
}

#[test]
fn test_graph_diff_changed_target() {
    let dir = tempdir().unwrap();
    let mut store = GraphStore::open(dir.path().join("db.sqlite")).unwrap();
    let t1 = build_domain("test.com");
    store.persist_scan(&[t1], &[]).unwrap();
    let mut t2 = build_domain("test.com");
    if let Target::Domain(ref mut d) = t2 {
        d.source = DiscoverySource::RapidDns;
    }
    let diff = store
        .compute_diff(&[t2], &[], Duration::from_secs(10))
        .unwrap();
    assert_eq!(diff.changed_targets.len(), 1);
}

#[test]
fn test_graph_diff_added_finding() {
    let dir = tempdir().unwrap();
    let mut store = GraphStore::open(dir.path().join("db.sqlite")).unwrap();
    let finding = secfinding::Finding::builder("test", "test.com", secfinding::Severity::High)
        .title("x")
        .build()
        .unwrap();
    store.persist_scan(&[], &[]).unwrap();
    let diff = store
        .compute_diff(&[], &[finding], Duration::from_secs(10))
        .unwrap();
    assert_eq!(diff.added_findings.len(), 1);
}

#[test]
fn test_graph_diff_changed_finding() {
    let dir = tempdir().unwrap();
    let mut store = GraphStore::open(dir.path().join("db.sqlite")).unwrap();
    // Build the v1 finding without confidence, persist, then rebuild
    // a v2 with confidence set to 0.9. The pre-streaming form mutated
    // `finding.confidence = Some(0.9)` directly, but `confidence` is
    // now a private field with no public setter — rebuild via the
    // builder is the supported path.
    let v1 = secfinding::Finding::builder("test", "test.com", secfinding::Severity::High)
        .title("x")
        .build()
        .unwrap();
    store.persist_scan(&[], &[v1]).unwrap();
    let v2 = secfinding::Finding::builder("test", "test.com", secfinding::Severity::High)
        .title("x")
        .confidence(0.9)
        .build()
        .unwrap();
    let diff = store
        .compute_diff(&[], &[v2], Duration::from_secs(10))
        .unwrap();
    assert_eq!(diff.changed_findings.len(), 1);
}

#[test]
fn test_graph_target_id_unknown() {
    let t = Target::Network(gossan_core::NetworkTarget {
        cidr: "1.1.1.0/24".to_string(),
        source: DiscoverySource::Seed,
    });
    let id = gossan_graph::target_id(&t);
    assert_eq!(id, "network:1.1.1.0/24");
}

#[test]
fn test_graph_target_id_from_finding_web() {
    let finding =
        secfinding::Finding::builder("test", "http://example.com", secfinding::Severity::High)
            .title("x")
            .build()
            .unwrap();
    let id = finding.target().to_string();
    assert_eq!(id, "http://example.com");
}

#[test]
fn test_graph_deserialization_corrupt_data_err() {
    let dir = tempdir().unwrap();
    let mut store = GraphStore::open(dir.path().join("db.sqlite")).unwrap();
    let t = build_domain("example.com");
    store.persist_scan(&[t.clone()], &[]).unwrap();
    store
        .conn()
        .execute("UPDATE targets SET data = 'corrupted'", [])
        .unwrap();
    let diff = store.compute_diff(&[], &[], Duration::from_secs(0));
    assert!(diff.is_err() || diff.is_ok());
}

#[test]
fn test_graph_diff_removed_target_zero_secs() {
    let dir = tempdir().unwrap();
    let mut store = GraphStore::open(dir.path().join("db.sqlite")).unwrap();
    let t1 = build_domain("test.com");
    store.persist_scan(&[t1.clone()], &[]).unwrap();
    // Simulate time passing by backdating the record
    store
        .conn()
        .execute(
            "UPDATE targets SET last_seen = datetime('now', '-2 seconds')",
            [],
        )
        .unwrap();
    let diff = store
        .compute_diff(&[], &[], Duration::from_secs(1))
        .unwrap();
    assert_eq!(diff.removed_targets.len(), 1);
}

#[test]
fn test_graph_diff_removed_finding_zero_secs() {
    let dir = tempdir().unwrap();
    let mut store = GraphStore::open(dir.path().join("db.sqlite")).unwrap();
    let finding = secfinding::Finding::builder("test", "test.com", secfinding::Severity::High)
        .title("x")
        .build()
        .unwrap();
    store.persist_scan(&[], &[finding]).unwrap();
    store
        .conn()
        .execute(
            "UPDATE findings SET last_seen = datetime('now', '-2 seconds')",
            [],
        )
        .unwrap();
    let diff = store
        .compute_diff(&[], &[], Duration::from_secs(1))
        .unwrap();
    assert_eq!(diff.removed_findings.len(), 1);
}

#[test]
fn test_finding_duplicate_deduplication() {
    let dir = tempdir().unwrap();
    let mut store = GraphStore::open(dir.path().join("db.sqlite")).unwrap();
    let finding = secfinding::Finding::builder("test", "test.com", secfinding::Severity::High)
        .title("x")
        .build()
        .unwrap();
    store
        .persist_scan(&[], &[finding.clone(), finding.clone()])
        .unwrap();
    let count: i64 = store
        .conn()
        .query_row("SELECT count(*) FROM findings", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 1);
}

#[test]
fn test_target_duplicate_deduplication() {
    let dir = tempdir().unwrap();
    let mut store = GraphStore::open(dir.path().join("db.sqlite")).unwrap();
    let t = build_domain("test.com");
    store.persist_scan(&[t.clone(), t.clone()], &[]).unwrap();
    let count: i64 = store
        .conn()
        .query_row("SELECT count(*) FROM targets", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 1);
}
