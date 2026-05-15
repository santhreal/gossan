use gossan_core::{DiscoverySource, DomainTarget, Target};
use gossan_graph::GraphStore;
use secfinding::{Finding, Severity};
use std::time::Duration;
use tempfile::tempdir;

fn build_target(domain: &str) -> Target {
    Target::Domain(DomainTarget {
        domain: domain.to_string(),
        source: DiscoverySource::Seed,
    })
}

fn build_finding(domain: &str, title: &str, detail: &str) -> Result<Finding, secfinding::FindingBuildError> {
    let safe_title = if title.is_empty() { "empty" } else { title };
    let safe_detail = if detail.is_empty() { "empty" } else { detail };
    
    Finding::builder(
        "adv_scanner".to_string(),
        domain.to_string(),
        Severity::High,
    )
    .title(safe_title)
    .detail(safe_detail)
    .build()
}

// Write some adversarial tests here
#[test]
fn test_node_deduplication() {
    let dir = tempdir().unwrap();
    let mut store = GraphStore::open(dir.path().join("db.sqlite")).unwrap();
    let t = build_target("example.com");
    store.persist_scan(&[t.clone(), t.clone()], &[]).unwrap();
    // Verify single target inserted
    let diff = store.compute_diff(&[t], &[], Duration::from_secs(10)).unwrap();
    assert_eq!(diff.added_targets.len(), 0);
}

