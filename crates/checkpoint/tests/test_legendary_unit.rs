use anyhow::Result;
use gossan_checkpoint::CheckpointStore;
use gossan_core::{DiscoverySource, DomainTarget, Target};
use secfinding::{Finding, Severity};
use uuid::Uuid;

fn make_target(domain: &str) -> Target {
    Target::Domain(DomainTarget {
        domain: domain.into(),
        source: DiscoverySource::Seed,
    })
}

fn make_finding(title: &str) -> Finding {
    Finding::builder("unit_test", "example.com", Severity::Medium)
        .title(title)
        .detail("some detail")
        .build()
        .expect("finding")
}

#[test]
fn test_unit_open_on_disk() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("test.db");

    // First open
    let store = CheckpointStore::open(&path)?;
    let id = store.new_scan("seed.com", "{}")?;
    store.save_stage(id, "dns", &[make_target("api.seed.com")], &[])?;

    // Drop connection
    drop(store);

    // Second open to verify persistence
    let store2 = CheckpointStore::open(&path)?;
    let record = store2.load(id)?;
    assert_eq!(record.seed, "seed.com");
    assert!(record.stage("dns").is_some());
    Ok(())
}

#[test]
fn test_unit_new_scan_returns_valid_uuid() -> Result<()> {
    let store = CheckpointStore::open(":memory:")?;
    let id = store.new_scan("seed1.com", "{}")?;
    let id2 = store.new_scan("seed2.com", "{}")?;
    assert_ne!(id, id2);
    Ok(())
}

#[test]
fn test_unit_save_stage_and_load() -> Result<()> {
    let store = CheckpointStore::open(":memory:")?;
    let id = store.new_scan("seed.com", "{}")?;

    store.save_stage(
        id,
        "stage1",
        &[make_target("sub.seed.com")],
        &[make_finding("Find 1")],
    )?;
    store.save_stage(id, "stage2", &[], &[make_finding("Find 2")])?;

    let record = store.load(id)?;
    assert_eq!(record.stages.len(), 2);

    let s1 = record.stage("stage1").expect("stage1");
    assert_eq!(s1.targets.len(), 1);
    assert_eq!(s1.findings[0].title(), "Find 1");

    let s2 = record.stage("stage2").expect("stage2");
    assert_eq!(s2.findings[0].title(), "Find 2");
    Ok(())
}

#[test]
fn test_unit_list_scans() -> Result<()> {
    let store = CheckpointStore::open(":memory:")?;
    let id1 = store.new_scan("test1.com", "{}")?;
    let id2 = store.new_scan("test2.com", "{}")?;

    let scans = store.list_scans()?;
    assert_eq!(scans.len(), 2);

    // Ordered by DESC created_at so id2 might be first depending on execution speed,
    // but sqlite might save them with the same timestamp if too fast.
    // Let's just check both exist
    let mut found1 = false;
    let mut found2 = false;
    for (id, seed, _) in scans {
        if id == id1 && seed == "test1.com" {
            found1 = true;
        }
        if id == id2 && seed == "test2.com" {
            found2 = true;
        }
    }

    assert!(found1 && found2);
    Ok(())
}

#[test]
fn test_unit_delete_scan() -> Result<()> {
    let store = CheckpointStore::open(":memory:")?;
    let id = store.new_scan("delete.me", "{}")?;
    store.save_stage(id, "stage", &[], &[])?;

    assert_eq!(store.list_scans()?.len(), 1);

    store.delete_scan(id)?;

    assert_eq!(store.list_scans()?.len(), 0);
    assert!(store.load(id).is_err()); // Scan should be gone
    Ok(())
}

#[test]
fn test_unit_load_missing_scan_errors() -> Result<()> {
    let store = CheckpointStore::open(":memory:")?;
    let random_id = Uuid::new_v4();
    let res = store.load(random_id);
    assert!(res.is_err());
    Ok(())
}
