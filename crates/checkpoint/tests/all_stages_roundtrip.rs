//! Save/load roundtrip across every pipeline stage name.
//!
//! Per GOSSAN_LEGENDARY A13: every stage (subdomain / portscan /
//! techstack / dns / js / hidden / cloud / origin / horizontal /
//! crawl / scm / correlation) must round-trip via `save_stage` →
//! `load` with no loss of targets or findings. Plus, a Finding's
//! tag list, evidence, and severity all survive the round-trip.

use gossan_checkpoint::CheckpointStore;
use gossan_core::{DiscoverySource, DomainTarget, Target};
use secfinding::{Evidence, Finding, Severity};

const STAGES: &[&str] = &[
    "subdomain",
    "portscan",
    "techstack",
    "dns",
    "js",
    "hidden",
    "cloud",
    "origin",
    "horizontal",
    "crawl",
    "scm",
    "correlation",
];

fn store() -> CheckpointStore {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ck.db");
    let s = CheckpointStore::open(&path).unwrap();
    // Leak the tempdir so the file outlives the test.
    std::mem::forget(dir);
    s
}

fn target(domain: &str) -> Target {
    Target::Domain(DomainTarget {
        domain: domain.to_string(),
        source: DiscoverySource::Seed,
    })
}

fn rich_finding() -> Finding {
    Finding::builder("portscan", "1.2.3.4", Severity::High)
        .title("open: 22/tcp (OpenSSH)")
        .detail("OpenSSH 8.9 reachable; verify allowlist")
        .tag("port:22/tcp")
        .tag("service:ssh")
        .tag("ip:1.2.3.4")
        .evidence(Evidence::Banner {
            raw: "SSH-2.0-OpenSSH_8.9".into(),
        })
        .build()
        .expect("build")
}

#[test]
fn every_stage_round_trips() {
    let store = store();
    let id = store.new_scan("example.com", "{}").unwrap();
    for stage_name in STAGES {
        let tgt = target(&format!("{stage_name}.example.com"));
        let f = rich_finding();
        store
            .save_stage(id, stage_name, &[tgt.clone()], &[f.clone()])
            .unwrap_or_else(|e| panic!("save_stage({stage_name}): {e}"));

        let loaded = store.load(id).unwrap();
        let stage = loaded
            .stage(stage_name)
            .unwrap_or_else(|| panic!("stage {stage_name} missing after save"));
        assert_eq!(stage.targets.len(), 1, "{stage_name}: target count");
        assert_eq!(stage.findings.len(), 1, "{stage_name}: finding count");
    }
}

#[test]
fn finding_fields_preserved_through_round_trip() {
    let store = store();
    let id = store.new_scan("example.com", "{}").unwrap();
    let original = rich_finding();
    store
        .save_stage(id, "portscan", &[], &[original.clone()])
        .unwrap();
    let loaded = store.load(id).unwrap();
    let stage = loaded.stage("portscan").unwrap();
    assert_eq!(stage.findings.len(), 1);
    let f = &stage.findings[0];
    assert_eq!(f.title(), original.title());
    assert_eq!(f.target(), original.target());
    assert_eq!(f.severity(), original.severity());
    assert_eq!(f.detail(), original.detail());
    let original_tags: Vec<String> = original
        .tags()
        .iter()
        .map(|t| t.as_ref().to_string())
        .collect();
    let loaded_tags: Vec<String> = f.tags().iter().map(|t| t.as_ref().to_string()).collect();
    for t in &original_tags {
        assert!(loaded_tags.contains(t), "tag `{t}` lost in round-trip");
    }
}

#[test]
fn save_stage_is_idempotent_for_every_stage() {
    let store = store();
    let id = store.new_scan("example.com", "{}").unwrap();
    for stage_name in STAGES {
        store.save_stage(id, stage_name, &[], &[]).unwrap();
        store
            .save_stage(id, stage_name, &[target("a.example.com")], &[])
            .unwrap();
        let loaded = store.load(id).unwrap();
        let stage = loaded
            .stage(stage_name)
            .unwrap_or_else(|| panic!("stage {stage_name} missing after idempotent replace"));
        assert_eq!(stage.targets.len(), 1, "{stage_name}: replace, not append");
    }
}
