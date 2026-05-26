use gossan_core::config::{Config, OutputConfig, OutputFormat};
use gossan_core::target::{Target, DomainTarget, HostTarget, ServiceTarget, WebAssetTarget, NetworkTarget, DiscoverySource, Protocol};
use gossan_core::{ScanInput, Scanner, Finding, Evidence, Severity, make_finding};
use gossan_core::CancellationToken;
use std::sync::Arc;
use tokio::sync::mpsc;
use hickory_resolver::{config::{ResolverConfig, ResolverOpts}, TokioAsyncResolver};
use async_trait::async_trait;
use url::Url;

// ==========================================
// CONFIGURATION VALIDATION TESTS
// ==========================================

#[test]
fn test_config_adversarial_malformed_json_types() {
    // Injecting string instead of numbers in places it expects integer
    let toml_content = r#"
rate_limit = "fast"
timeout_secs = "none"
concurrency = "maximum"
"#;
    let temp_dir = tempfile::tempdir().unwrap();
    let file_path = temp_dir.path().join("gossan_malformed.toml");
    std::fs::write(&file_path, toml_content).unwrap();

    let result = Config::from_toml(&file_path);
    assert!(result.is_err(), "Configuration parser must reject strings where numbers are expected");
}

#[test]
fn test_config_adversarial_deep_nesting() {
    // Nested structs should either reject gracefully or parse without stack overflow
    let mut toml_content = String::from("[modules]\n");
    for i in 0..1000 {
        toml_content.push_str(&format!("level{} = {{ \n", i));
    }
    for _ in 0..1000 {
        toml_content.push_str("}\n");
    }
    let temp_dir = tempfile::tempdir().unwrap();
    let file_path = temp_dir.path().join("gossan_nested.toml");
    std::fs::write(&file_path, toml_content).unwrap();

    // TOML parser should hit a nesting limit or error cleanly, NOT panic
    let result = Config::from_toml(&file_path);
    assert!(result.is_err(), "Configuration parser should error gracefully on deep nesting");
}

#[test]
fn test_config_adversarial_null_bytes() {
    let toml_content = "rate_limit = 100\nuser_agent = \"gossan\0test\"\n";
    let temp_dir = tempfile::tempdir().unwrap();
    let file_path = temp_dir.path().join("gossan_null.toml");
    std::fs::write(&file_path, toml_content).unwrap();

    let result = Config::from_toml(&file_path);
    // TOML parsers might accept null bytes in strings. If it does, we verify it didn't crash.
    // If it rejects, we verify it's an Err.
    match result {
        Ok(c) => assert!(c.user_agent.contains('\0')),
        Err(e) => assert!(!e.is_empty()),
    }
}

// ==========================================
// OUTPUT FORMAT CORRECTNESS TESTS
// ==========================================

#[test]
fn test_output_json_injection() {
    let target = Target::Domain(DomainTarget {
        domain: "example.com".into(),
        source: DiscoverySource::Seed,
    });
    
    // Injecting quotes, newlines, and control characters to try and break JSON output
    let finding = make_finding(
        "test-scanner",
        target.clone(),
        Severity::High,
        "Injection Title \"; drop tables; //",
        "Detail with \n newlines and \t tabs and \x08 backspaces",
    ).unwrap();

    let json_str = serde_json::to_string(&finding).unwrap();
    
    // Parse it back to ensure it is valid JSON and not corrupted
    let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
    assert_eq!(parsed["title"].as_str().unwrap(), "Injection Title \"; drop tables; //");
    assert_eq!(parsed["detail"].as_str().unwrap(), "Detail with \n newlines and \t tabs and \x08 backspaces");
}

#[test]
fn test_output_json_evidence_raw_injection() {
    let target = Target::Domain(DomainTarget {
        domain: "example.com".into(),
        source: DiscoverySource::Seed,
    });
    
    let mut finding = make_finding(
        "test-scanner",
        target.clone(),
        Severity::High,
        "Title",
        "Detail",
    ).unwrap();

    // Inject massive raw evidence
    let massive_evidence = "A".repeat(1_000_000);
    finding.evidence().push(Evidence::raw(massive_evidence.clone()));

    let json_str = serde_json::to_string(&finding).unwrap();
    
    // Ensure serialization succeeded and the output is extremely large but valid JSON
    assert!(json_str.len() > 1_000_000);
    let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
    // secfinding serializes Evidence::Raw generically depending on serde setup, 
    // we ensure it deserialized properly
    let ev = parsed["evidence"][0].as_object().unwrap();
    assert_eq!(ev["raw"].as_str().unwrap().len(), 1_000_000);
}
