use anyhow::Result;
use gossan_core::{DiscoverySource, DomainTarget, Target};
use secfinding::{Finding, Severity};
use gossan_checkpoint::CheckpointStore;

fn make_target(domain: &str) -> Target {
    Target::Domain(DomainTarget {
        domain: domain.into(),
        source: DiscoverySource::Seed,
    })
}

fn make_finding(title: &str) -> Finding {
    Finding::builder("adversarial", "example.com", Severity::High)
        .title(title)
        .detail("detail")
        .build()
        .expect("required finding fields")
}


fn in_memory() -> CheckpointStore {
    CheckpointStore::open(":memory:").expect("in-memory store")
}

#[test]
fn test_adversarial_empty_inputs() -> Result<()> {
    let store = in_memory();
    let id = store.new_scan("", "")?;
    store.save_stage(id, "", &[], &[])?;

    let record = store.load(id)?;
    assert_eq!(record.seed, "");
    
    let stage = record.stage("").expect("empty stage should exist");
    assert_eq!(stage.targets.len(), 0);
    assert_eq!(stage.findings.len(), 0);
    Ok(())
}

#[test]
fn test_adversarial_null_bytes() -> Result<()> {
    let store = in_memory();
    
    let seed_with_null = "exa\0mple.com";
    let id = store.new_scan(seed_with_null, "{}")?;

    let target_with_null = make_target("tar\0get.com");
    
    let clean_finding = make_finding("clean-finding-no-null");

    store.save_stage(id, "st\0age", &[target_with_null], &[clean_finding])?;

    let record = store.load(id)?;
    assert_eq!(record.seed, seed_with_null, "seed roundtrip lost null byte");
    let stage = record
        .stage("st\0age")
        .expect("stage name with null byte must roundtrip");

    let Target::Domain(d) = &stage.targets[0] else {
        panic!("unexpected target type");
    };
    assert_eq!(d.domain, "tar\0get.com", "target.domain roundtrip lost null byte");
    assert_eq!(stage.findings[0].title(), "clean-finding-no-null");

    // Boundary: secfinding rejects null bytes in the title at construction.
    // Silent acceptance would let a different caller smuggle nulls into
    // the finding store.
    let err = Finding::builder("adversarial", "example.com", Severity::High)
        .title("fi\0nding")
        .detail("detail")
        .build()
        .expect_err("Finding::builder must reject null bytes in title");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("null"),
        "Finding builder rejection must mention 'null'; got: {msg}"
    );

    Ok(())
}

#[test]
fn test_adversarial_0xff_bytes() -> Result<()> {
    let store = in_memory();
    // Use valid string with weird bytes, Rust strings must be valid UTF-8, so we use string escapes for edge cases or unicode
    // For 0xFF, it's invalid UTF-8, but strings in Rust are always valid UTF-8. We use highest scalar value instead.
    let max_unicode = "\u{10FFFF}\u{10FFFF}";
    let id = store.new_scan(max_unicode, "{}")?;
    store.save_stage(id, max_unicode, &[make_target(max_unicode)], &[make_finding(max_unicode)])?;

    let record = store.load(id)?;
    assert_eq!(record.seed, max_unicode);
    let stage = record.stage(max_unicode).expect("stage with max unicode should exist");
    assert_eq!(stage.findings[0].title(), max_unicode);
    Ok(())
}

#[test]
fn test_adversarial_huge_input() -> Result<()> {
    let store = in_memory();
    // 1MB string for seed/stage values
    let huge_str = "A".repeat(1024 * 1024);
    let id = store.new_scan(&huge_str, "{}")?;
    
    let mut targets = Vec::new();
    for i in 0..10 {
        targets.push(make_target(&format!("{}-{}", huge_str, i)));
    }
    
    // Using a normal finding since secfinding asserts on >1MB titles
    store.save_stage(id, &huge_str, &targets, &[make_finding("normal_title")])?;

    let record = store.load(id)?;
    assert_eq!(record.seed, huge_str);
    let stage = record.stage(&huge_str).expect("huge stage should exist");
    assert_eq!(stage.targets.len(), 10);
    Ok(())
}

#[test]
fn test_adversarial_path_traversal() -> Result<()> {
    let dir = tempfile::tempdir()?;
    // Intentionally try to create a file with a traversal-like name, but inside tempdir.
    // We do NOT write to actual system root.
    let path = dir.path().join(".._.._.._evil.db");
    
    let store = CheckpointStore::open(&path)?;
    let id = store.new_scan("test", "{}")?;
    store.save_stage(id, "test", &[], &[])?;

    assert!(path.exists());
    Ok(())
}

#[test]
fn test_adversarial_sql_injection_homoglyphs() -> Result<()> {
    let store = in_memory();
    // Attempt SQL injection strings that SQLite might misinterpret if not parameterized
    let inject_seed = "'; DROP TABLE scans; --";
    let inject_stage = "'; DROP TABLE stages; --";
    
    let id = store.new_scan(inject_seed, "{}")?;
    store.save_stage(id, inject_stage, &[], &[])?;

    let record = store.load(id)?;
    assert_eq!(record.seed, inject_seed);
    assert!(record.stage(inject_stage).is_some());
    
    // Homoglyphs
    let homoglyph = "еxample.com"; // Cyrillic 'е'
    let id2 = store.new_scan(homoglyph, "{}")?;
    let record2 = store.load(id2)?;
    assert_eq!(record2.seed, homoglyph);
    
    Ok(())
}

#[test]
fn test_adversarial_huge_concurrency_boundaries() -> Result<()> {
    let store = in_memory();
    let id = store.new_scan("seed", "{}")?;
    
    // Save 10,000 stages
    for i in 0..1000 {
        let stage_name = format!("stage-{}", i);
        store.save_stage(id, &stage_name, &[], &[])?;
    }
    
    let record = store.load(id)?;
    assert_eq!(record.stages.len(), 1000);
    Ok(())
}
