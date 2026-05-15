use gossan_core::{DiscoverySource, DomainTarget, HostTarget, Target};
// Renamed: GraphStore → SqliteBackend.
use gossan_graph::SqliteBackend as GraphStore;
use secfinding::{Finding, Severity};
use std::time::Duration;
use tempfile::tempdir;
use proptest::prelude::*;

fn arb_target() -> impl Strategy<Value = Target> {
    prop_oneof![
        "[a-z0-9.-]{1,100}".prop_map(|domain| Target::Domain(DomainTarget {
            domain,
            source: DiscoverySource::Seed,
        })),
        "[a-z0-9.-]{1,100}".prop_map(|ip| Target::Host(HostTarget {
            ip: "127.0.0.1".parse().unwrap(),
            domain: Some(ip),
        })),
    ]
}

fn arb_finding() -> impl Strategy<Value = Finding> {
    ("[a-z0-9.-]{1,50}", "[a-zA-Z0-9 ]{1,100}", "[a-zA-Z0-9 ]{1,100}").prop_map(|(target, title, detail)| {
        Finding::builder(
            "proptest_scanner".to_string(),
            target,
            Severity::High,
        )
        .title(title)
        .detail(detail)
        .build()
        .unwrap()
    })
}

proptest! {
    #[test]
    fn property_test_persist_never_panics(
        targets in prop::collection::vec(arb_target(), 0..50),
        findings in prop::collection::vec(arb_finding(), 0..50)
    ) {
        let dir = tempdir().unwrap();
        let mut store = GraphStore::open(dir.path().join("db.sqlite")).unwrap();
        
        let res = store.persist_scan(&targets, &findings);
        prop_assert!(res.is_ok());
    }
    
    #[test]
    fn property_test_diff_never_panics(
        targets in prop::collection::vec(arb_target(), 0..20),
        findings in prop::collection::vec(arb_finding(), 0..20),
        threshold in 0..10000u64
    ) {
        let dir = tempdir().unwrap();
        let mut store = GraphStore::open(dir.path().join("db.sqlite")).unwrap();
        
        // Setup initial state
        store.persist_scan(&targets, &findings).unwrap();
        
        // Compute diff
        let diff = store.compute_diff(&targets, &findings, Duration::from_secs(threshold));
        prop_assert!(diff.is_ok());
        
        let diff_unwrapped = diff.unwrap();
        
        // Invariants: adding same targets again should result in 0 added targets
        prop_assert_eq!(diff_unwrapped.added_targets.len(), 0);
        prop_assert_eq!(diff_unwrapped.added_findings.len(), 0);
    }
    
    #[test]
    fn property_test_target_id_is_deterministic(target in arb_target()) {
        let id1 = gossan_graph::target_id(&target);
        let id2 = gossan_graph::target_id(&target);
        prop_assert_eq!(id1, id2);
    }
}
