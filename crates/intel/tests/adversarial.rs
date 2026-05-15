use gossan_core::{Config, ScanInput, Scanner, Target, HostTarget, DomainTarget};
use gossan_intel::{db::{IntelDb, IntelRecord}, ingest::Ingester, IntelScanner};
use std::sync::Arc;
use tempfile::NamedTempFile;
use std::io::Write;

fn get_test_config() -> Config {
    Config::default()
}

/// Build a ScanInput for tests using the streaming API. The
/// pre-streaming literal-struct form (`targets: Vec<_>`,
/// `live_tx: None`, `target_tx: None`, plus a `cancel` field that
/// no longer exists) was retired during the streaming refactor.
fn get_test_scan_input(targets: Vec<Target>) -> ScanInput {
    let (in_tx, in_rx) = tokio::sync::mpsc::unbounded_channel::<Target>();
    for t in targets {
        let _ = in_tx.send(t);
    }
    drop(in_tx);
    let (live_tx, _live_rx) = tokio::sync::mpsc::unbounded_channel();
    let (target_tx, _target_rx) = tokio::sync::mpsc::unbounded_channel();
    ScanInput {
        seed: "test".to_string(),
        target_rx: tokio::sync::Mutex::new(in_rx),
        live_tx,
        target_tx,
        resolver: Arc::new(gossan_core::net::build_resolver(&get_test_config()).unwrap()),
    }
}

/// Run the scanner against synthetic targets and return everything
/// it emitted on the live (Finding) channel. `Scanner::run` returns
/// `Result<()>` now — findings flow through `live_tx`. Tests want
/// `Vec<Finding>` assertions, so this drains the channel after the
/// scanner returns.
async fn run_and_collect_findings(
    scanner: &IntelScanner,
    targets: Vec<Target>,
    config: &gossan_core::Config,
) -> Vec<secfinding::Finding> {
    let (in_tx, in_rx) = tokio::sync::mpsc::unbounded_channel::<Target>();
    for t in targets {
        let _ = in_tx.send(t);
    }
    drop(in_tx);
    let (live_tx, mut live_rx) = tokio::sync::mpsc::unbounded_channel();
    let (target_tx, _target_rx) = tokio::sync::mpsc::unbounded_channel();
    let input = ScanInput {
        seed: "test".to_string(),
        target_rx: tokio::sync::Mutex::new(in_rx),
        live_tx,
        target_tx,
        resolver: Arc::new(gossan_core::net::build_resolver(config).unwrap()),
    };
    scanner.run(input, config).await.unwrap();
    // Channels stay open as long as the senders inside the input
    // exist; `scanner.run` drops them on return, so try_recv drains
    // cleanly.
    let mut out = Vec::new();
    while let Ok(f) = live_rx.try_recv() {
        out.push(f);
    }
    out
}

// 1. Basic IP Reputation Lookup
#[tokio::test]
async fn test_01_ip_reputation_lookup() {
    let db_path = NamedTempFile::new().unwrap().into_temp_path();
    let db = IntelDb::open(&db_path).unwrap();
    let record = IntelRecord {
        ip: "192.168.1.100".to_string(),
        host: None,
        port: 80,
        protocol: "tcp".to_string(),
        banner: Some("Known bad ip".to_string()),
        tech_stack: vec!["malware".to_string()],
        last_seen: None,
    };
    db.insert_batch(&[record]).unwrap();

    let scanner = IntelScanner::new(db_path.to_str().unwrap()).unwrap();
    let target = Target::Host(HostTarget { ip: "192.168.1.100".parse().unwrap(), domain: None });
    let res_findings = run_and_collect_findings(&scanner, vec![target], &get_test_config()).await;
    assert_eq!(res_findings.len(), 1);
    assert!(res_findings[0].detail().contains("Known bad ip"));
}

// 2. Domain Age Check (Simulated via last_seen/banner)
#[tokio::test]
async fn test_02_domain_age_check() {
    let db_path = NamedTempFile::new().unwrap().into_temp_path();
    let db = IntelDb::open(&db_path).unwrap();
    let record = IntelRecord {
        ip: "10.0.0.1".to_string(),
        host: Some("example.com".to_string()),
        port: 443,
        protocol: "tcp".to_string(),
        banner: Some("Created: 1999".to_string()),
        tech_stack: vec![],
        last_seen: Some("2023-01-01".to_string()),
    };
    db.insert_batch(&[record]).unwrap();

    let scanner = IntelScanner::new(db_path.to_str().unwrap()).unwrap();
    let target = Target::Domain(DomainTarget { domain: "example.com".to_string(), source: gossan_core::target::DiscoverySource::Seed });
    let res_findings = run_and_collect_findings(&scanner, vec![target], &get_test_config()).await;
    assert_eq!(res_findings.len(), 1);
    assert!(res_findings[0].detail().contains("Created: 1999"));
}

// 3. ASN Information Enrichment (Simulated via banner)
#[tokio::test]
async fn test_03_asn_information_enrichment() {
    let db_path = NamedTempFile::new().unwrap().into_temp_path();
    let db = IntelDb::open(&db_path).unwrap();
    let record = IntelRecord {
        ip: "8.8.8.8".to_string(),
        host: None,
        port: 53,
        protocol: "udp".to_string(),
        banner: Some("ASN15169".to_string()),
        tech_stack: vec![],
        last_seen: None,
    };
    db.insert_batch(&[record]).unwrap();

    let scanner = IntelScanner::new(db_path.to_str().unwrap()).unwrap();
    let target = Target::Host(HostTarget { ip: "8.8.8.8".parse().unwrap(), domain: None });
    let res_findings = run_and_collect_findings(&scanner, vec![target], &get_test_config()).await;
    assert_eq!(res_findings.len(), 1);
    assert!(res_findings[0].detail().contains("ASN15169"));
}

// 4. WHOIS Data Parsing (Simulated via banner)
#[tokio::test]
async fn test_04_whois_data_parsing() {
    let db_path = NamedTempFile::new().unwrap().into_temp_path();
    let db = IntelDb::open(&db_path).unwrap();
    let record = IntelRecord {
        ip: "1.1.1.1".to_string(),
        host: Some("cloudflare.com".to_string()),
        port: 443,
        protocol: "tcp".to_string(),
        banner: Some("WHOIS: Cloudflare Inc".to_string()),
        tech_stack: vec![],
        last_seen: None,
    };
    db.insert_batch(&[record]).unwrap();

    let scanner = IntelScanner::new(db_path.to_str().unwrap()).unwrap();
    let target = Target::Domain(DomainTarget { domain: "cloudflare.com".to_string(), source: gossan_core::target::DiscoverySource::Seed });
    let res_findings = run_and_collect_findings(&scanner, vec![target], &get_test_config()).await;
    assert_eq!(res_findings.len(), 1);
    assert!(res_findings[0].detail().contains("WHOIS"));
}

// 5. Certificate Transparency Log Query
#[tokio::test]
async fn test_05_certificate_transparency_log_query() {
    let db_path = NamedTempFile::new().unwrap().into_temp_path();
    let db = IntelDb::open(&db_path).unwrap();
    let record = IntelRecord {
        ip: "9.9.9.9".to_string(),
        host: Some("quad9.net".to_string()),
        port: 443,
        protocol: "tcp".to_string(),
        banner: Some("CT Log: 0x123456".to_string()),
        tech_stack: vec![],
        last_seen: None,
    };
    db.insert_batch(&[record]).unwrap();

    let scanner = IntelScanner::new(db_path.to_str().unwrap()).unwrap();
    let target = Target::Domain(DomainTarget { domain: "quad9.net".to_string(), source: gossan_core::target::DiscoverySource::Seed });
    let res_findings = run_and_collect_findings(&scanner, vec![target], &get_test_config()).await;
    assert_eq!(res_findings.len(), 1);
    assert!(res_findings[0].detail().contains("CT Log"));
}

// 6. Passive DNS Correlation (Multiple IPs for one domain)
#[tokio::test]
async fn test_06_passive_dns_correlation() {
    let db_path = NamedTempFile::new().unwrap().into_temp_path();
    let db = IntelDb::open(&db_path).unwrap();
    let r1 = IntelRecord { ip: "1.2.3.4".to_string(), host: Some("test.com".to_string()), port: 80, protocol: "tcp".to_string(), banner: None, tech_stack: vec![], last_seen: None };
    let r2 = IntelRecord { ip: "1.2.3.5".to_string(), host: Some("test.com".to_string()), port: 80, protocol: "tcp".to_string(), banner: None, tech_stack: vec![], last_seen: None };
    db.insert_batch(&[r1, r2]).unwrap();

    let scanner = IntelScanner::new(db_path.to_str().unwrap()).unwrap();
    let target = Target::Domain(DomainTarget { domain: "test.com".to_string(), source: gossan_core::target::DiscoverySource::Seed });
    let res_findings = run_and_collect_findings(&scanner, vec![target], &get_test_config()).await;
    assert_eq!(res_findings.len(), 2);
}

// 7. Known-bad IP List Matching
#[tokio::test]
async fn test_07_known_bad_ip_list_matching() {
    let db_path = NamedTempFile::new().unwrap().into_temp_path();
    let db = IntelDb::open(&db_path).unwrap();
    let record = IntelRecord {
        ip: "6.6.6.6".to_string(),
        host: None,
        port: 445,
        protocol: "tcp".to_string(),
        banner: Some("botnet".to_string()),
        tech_stack: vec!["c2".to_string()],
        last_seen: None,
    };
    db.insert_batch(&[record]).unwrap();

    let scanner = IntelScanner::new(db_path.to_str().unwrap()).unwrap();
    let target = Target::Host(HostTarget { ip: "6.6.6.6".parse().unwrap(), domain: None });
    let res_findings = run_and_collect_findings(&scanner, vec![target], &get_test_config()).await;
    assert_eq!(res_findings.len(), 1);
    
    // tags() returns `&[Arc<str>]`. Compare against an Arc<str> Vec
    // to avoid Arc<str>-vs-String type mismatch on the assert_eq.
    // Sorting both first gives an order-insensitive comparison.
    let mut actual_tags: Vec<std::sync::Arc<str>> = res_findings[0].tags().to_vec();
    actual_tags.sort();

    let mut expected_tags: Vec<std::sync::Arc<str>> = vec![
        "passive".into(),
        "intel".into(),
        "tech:c2".into(),
    ];
    expected_tags.sort();

    assert_eq!(actual_tags, expected_tags);
}

// 8. Concurrent Intel Lookups
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn test_08_concurrent_intel_lookups() {
    let db_path = NamedTempFile::new().unwrap().into_temp_path();
    let db = IntelDb::open(&db_path).unwrap();
    let record = IntelRecord {
        ip: "10.10.10.10".to_string(),
        host: None,
        port: 80,
        protocol: "tcp".to_string(),
        banner: None,
        tech_stack: vec![],
        last_seen: None,
    };
    db.insert_batch(&[record]).unwrap();

    let scanner = Arc::new(IntelScanner::new(db_path.to_str().unwrap()).unwrap());
    let mut handles = vec![];
    for _ in 0..100 {
        let sc = scanner.clone();
        handles.push(tokio::spawn(async move {
            let target = Target::Host(HostTarget { ip: "10.10.10.10".parse().unwrap(), domain: None });
            let res_findings = run_and_collect_findings(&sc, vec![target], &get_test_config()).await;
            assert_eq!(res_findings.len(), 1);
        }));
    }
    for h in handles {
        h.await.unwrap();
    }
}

// 9. Timeout on Slow APIs (Simulated via cancellation)
#[tokio::test]
async fn test_09_timeout_on_slow_apis() {
    let db_path = NamedTempFile::new().unwrap().into_temp_path();
    let _db = IntelDb::open(&db_path).unwrap();
    let scanner = IntelScanner::new(db_path.to_str().unwrap()).unwrap();
    
    // The pre-streaming `ScanInput.cancel` field is gone — cancellation
    // now flows in via dropping the live_tx/target_tx senders, which
    // happens automatically when the channels in `run_and_collect_findings`
    // go out of scope. There's no longer a way to "cancel immediately"
    // mid-call; this test now just verifies the scanner returns
    // gracefully on a fresh DB with no matching records, which is the
    // only behaviour the assertion ever actually checked.
    let res_findings = run_and_collect_findings(
        &scanner,
        vec![
            Target::Host(HostTarget { ip: "1.1.1.1".parse().unwrap(), domain: None }),
            Target::Host(HostTarget { ip: "2.2.2.2".parse().unwrap(), domain: None }),
        ],
        &get_test_config(),
    ).await;
    assert_eq!(res_findings.len(), 0);
}

// 10. Cache Hit/Miss Correctness
#[tokio::test]
async fn test_10_cache_hit_miss_correctness() {
    let db_path = NamedTempFile::new().unwrap().into_temp_path();
    let db = IntelDb::open(&db_path).unwrap();
    let record = IntelRecord { ip: "11.11.11.11".to_string(), host: None, port: 80, protocol: "tcp".to_string(), banner: None, tech_stack: vec![], last_seen: None };
    db.insert_batch(&[record]).unwrap();

    let scanner = IntelScanner::new(db_path.to_str().unwrap()).unwrap();
    let hit_target = Target::Host(HostTarget { ip: "11.11.11.11".parse().unwrap(), domain: None });
    let miss_target = Target::Host(HostTarget { ip: "12.12.12.12".parse().unwrap(), domain: None });
    
    let hit_res_findings = run_and_collect_findings(&scanner, vec![hit_target], &get_test_config()).await;
    let miss_res_findings = run_and_collect_findings(&scanner, vec![miss_target], &get_test_config()).await;

    assert_eq!(hit_res_findings.len(), 1);
    assert_eq!(miss_res_findings.len(), 0);
}

// 11. Empty/Null Response Handling from Data Sources
#[tokio::test]
async fn test_11_empty_null_response_handling() {
    let db_path = NamedTempFile::new().unwrap().into_temp_path();
    let _db = IntelDb::open(&db_path).unwrap();
    let scanner = IntelScanner::new(db_path.to_str().unwrap()).unwrap();
    
    let target = Target::Domain(DomainTarget { domain: "nonexistent.com".to_string(), source: gossan_core::target::DiscoverySource::Seed });
    let res_findings = run_and_collect_findings(&scanner, vec![target], &get_test_config()).await;
    assert_eq!(res_findings.len(), 0);
}

// 12. Ingestion of Empty File
#[tokio::test]
async fn test_12_ingestion_empty_file() {
    let db_path = NamedTempFile::new().unwrap().into_temp_path();
    let mut db = IntelDb::open(&db_path).unwrap();
    let jsonl_file = NamedTempFile::new().unwrap();
    
    let count = Ingester::ingest_jsonl(&db, jsonl_file.path()).unwrap();
    assert_eq!(count, 0);
}

// 13. Ingestion of Malformed JSONL
#[tokio::test]
async fn test_13_ingestion_malformed_jsonl() {
    let db_path = NamedTempFile::new().unwrap().into_temp_path();
    let mut db = IntelDb::open(&db_path).unwrap();
    let mut jsonl_file = NamedTempFile::new().unwrap();
    writeln!(jsonl_file, "invalid json").unwrap();
    writeln!(jsonl_file, "{{\"ip\": \"1.1.1.1\", \"port\": 80, \"protocol\": \"tcp\"}}").unwrap(); // valid
    writeln!(jsonl_file, "{{\"ip\":").unwrap(); // invalid
    jsonl_file.flush().unwrap();
    let _ = jsonl_file.as_file().sync_all();
    
    
    let count = Ingester::ingest_jsonl(&db, jsonl_file.path()).unwrap();
    assert_eq!(count, 1);
    
    let res = db.query_by_ip("1.1.1.1").unwrap();
    assert_eq!(res.len(), 1);
}

// 14. Ingestion with Massive Inputs (100k records)
#[tokio::test]
async fn test_14_ingestion_massive_inputs() {
    let db_path = NamedTempFile::new().unwrap().into_temp_path();
    let mut db = IntelDb::open(&db_path).unwrap();
    let mut jsonl_file = NamedTempFile::new().unwrap();
    
    for i in 0..10_000 {
        writeln!(jsonl_file, "{{\"ip\": \"10.0.0.{}\", \"port\": 80, \"protocol\": \"tcp\"}}", i % 256).unwrap();
    }
    jsonl_file.flush().unwrap();
    let _ = jsonl_file.as_file().sync_all();
    
    
    let count = Ingester::ingest_jsonl(&db, jsonl_file.path()).unwrap();
    assert_eq!(count, 10_000);
}

// 15. Concurrent Inserts
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn test_15_concurrent_inserts() {
    let db_path = NamedTempFile::new().unwrap().into_temp_path();
    let db = Arc::new(IntelDb::open(&db_path).unwrap());
    
    let mut handles = vec![];
    for i in 0..10 {
        let db_clone = db.clone();
        handles.push(tokio::spawn(async move {
            let r = IntelRecord { ip: format!("10.0.{}.1", i), host: None, port: 80, protocol: "tcp".to_string(), banner: None, tech_stack: vec![], last_seen: None };
            db_clone.insert_batch(&[r]).unwrap();
        }));
    }
    for h in handles {
        h.await.unwrap();
    }
    
    let r = db.query_by_ip("10.0.5.1").unwrap();
    assert_eq!(r.len(), 1);
}

// 16. Unique Constraints Violation
#[tokio::test]
async fn test_16_unique_constraints() {
    let db_path = NamedTempFile::new().unwrap().into_temp_path();
    let db = IntelDb::open(&db_path).unwrap();
    let r1 = IntelRecord { ip: "1.1.1.1".to_string(), host: Some("h".to_string()), port: 80, protocol: "tcp".to_string(), banner: None, tech_stack: vec![], last_seen: None };
    let r2 = IntelRecord { ip: "1.1.1.1".to_string(), host: Some("h".to_string()), port: 80, protocol: "tcp".to_string(), banner: Some("new".to_string()), tech_stack: vec![], last_seen: None };
    
    // Should overwrite due to INSERT OR REPLACE
    db.insert_batch(&[r1]).unwrap();
    db.insert_batch(&[r2]).unwrap();
    
    let res = db.query_by_ip("1.1.1.1").unwrap();
    assert_eq!(res.len(), 1);
    assert_eq!(res[0].banner, Some("new".to_string()));
}

// 17. Null Bytes in Strings
#[tokio::test]
async fn test_17_null_bytes() {
    let db_path = NamedTempFile::new().unwrap().into_temp_path();
    let db = IntelDb::open(&db_path).unwrap();
    let r = IntelRecord { ip: "1.1.1.1\0".to_string(), host: Some("a\0b".to_string()), port: 80, protocol: "tcp".to_string(), banner: None, tech_stack: vec!["\0".to_string()], last_seen: None };
    
    db.insert_batch(&[r]).unwrap();
    let res = db.query_by_ip("1.1.1.1\0").unwrap();
    assert_eq!(res.len(), 1);
    assert_eq!(res[0].host, Some("a\0b".to_string()));
}

// 18. Large Banner Strings
#[tokio::test]
async fn test_18_large_banner() {
    let db_path = NamedTempFile::new().unwrap().into_temp_path();
    let db = IntelDb::open(&db_path).unwrap();
    let large_banner = "A".repeat(1024 * 1024); // 1MB
    let r = IntelRecord { ip: "2.2.2.2".to_string(), host: None, port: 80, protocol: "tcp".to_string(), banner: Some(large_banner.clone()), tech_stack: vec![], last_seen: None };
    
    db.insert_batch(&[r]).unwrap();
    let res = db.query_by_ip("2.2.2.2").unwrap();
    assert_eq!(res.len(), 1);
    assert_eq!(res[0].banner, Some(large_banner));
}

// 19. Large Tech Stack
#[tokio::test]
async fn test_19_large_tech_stack() {
    let db_path = NamedTempFile::new().unwrap().into_temp_path();
    let db = IntelDb::open(&db_path).unwrap();
    let tech_stack: Vec<String> = (0..10_000).map(|i| format!("tech_{}", i)).collect();
    let r = IntelRecord { ip: "3.3.3.3".to_string(), host: None, port: 80, protocol: "tcp".to_string(), banner: None, tech_stack: tech_stack.clone(), last_seen: None };
    
    db.insert_batch(&[r]).unwrap();
    let res = db.query_by_ip("3.3.3.3").unwrap();
    assert_eq!(res.len(), 1);
    assert_eq!(res[0].tech_stack.len(), 10_000);
}

// 20. Scanner Accepts Method
#[tokio::test]
async fn test_20_scanner_accepts() {
    let db_path = NamedTempFile::new().unwrap().into_temp_path();
    let scanner = IntelScanner::new(db_path.to_str().unwrap()).unwrap();
    
    assert!(scanner.accepts(&Target::Host(HostTarget { ip: "1.1.1.1".parse().unwrap(), domain: None })));
    assert!(scanner.accepts(&Target::Domain(DomainTarget { domain: "test.com".to_string(), source: gossan_core::target::DiscoverySource::Seed })));
    // Add Service check if it were part of Accepts, but intel only accepts Domain | Host
}

// 21. Query By Host
#[tokio::test]
async fn test_21_query_by_host() {
    let db_path = NamedTempFile::new().unwrap().into_temp_path();
    let db = IntelDb::open(&db_path).unwrap();
    let r = IntelRecord { ip: "4.4.4.4".to_string(), host: Some("query.com".to_string()), port: 80, protocol: "tcp".to_string(), banner: None, tech_stack: vec![], last_seen: None };
    
    db.insert_batch(&[r]).unwrap();
    let res = db.query_by_host("query.com").unwrap();
    assert_eq!(res.len(), 1);
    assert_eq!(res[0].ip, "4.4.4.4");
}

// 22. Max U16 Port Boundary
#[tokio::test]
async fn test_22_max_u16_port() {
    let db_path = NamedTempFile::new().unwrap().into_temp_path();
    let db = IntelDb::open(&db_path).unwrap();
    let r = IntelRecord { ip: "5.5.5.5".to_string(), host: None, port: std::u16::MAX, protocol: "tcp".to_string(), banner: None, tech_stack: vec![], last_seen: None };
    
    db.insert_batch(&[r]).unwrap();
    let res = db.query_by_ip("5.5.5.5").unwrap();
    assert_eq!(res[0].port, 65535);
}

// 23. Duplicate Unique Constraints in Batch
#[tokio::test]
async fn test_23_duplicate_in_batch() {
    let db_path = NamedTempFile::new().unwrap().into_temp_path();
    let db = IntelDb::open(&db_path).unwrap();
    let r1 = IntelRecord { ip: "6.6.6.6".to_string(), host: None, port: 80, protocol: "tcp".to_string(), banner: Some("a".to_string()), tech_stack: vec![], last_seen: None };
    let r2 = IntelRecord { ip: "6.6.6.6".to_string(), host: None, port: 80, protocol: "tcp".to_string(), banner: Some("b".to_string()), tech_stack: vec![], last_seen: None };
    
    // In db.rs, the uniqueness is UNIQUE(ip, host, port, protocol)
    // The insert_batch should INSERT OR REPLACE the second over the first since they share UNIQUE keys
    db.insert_batch(&[r1, r2]).unwrap();
    
    let res = db.query_by_ip("6.6.6.6").unwrap();
    assert_eq!(res.len(), 1);
    assert_eq!(res[0].banner, Some("b".to_string()));
}

// 24. Unicode in Host and IP
#[tokio::test]
async fn test_24_unicode_host_ip() {
    let db_path = NamedTempFile::new().unwrap().into_temp_path();
    let db = IntelDb::open(&db_path).unwrap();
    let r = IntelRecord { ip: "あ.あ.あ.あ".to_string(), host: Some("💩.com".to_string()), port: 80, protocol: "tcp".to_string(), banner: None, tech_stack: vec![], last_seen: None };
    
    db.insert_batch(&[r]).unwrap();
    let res = db.query_by_host("💩.com").unwrap();
    assert_eq!(res.len(), 1);
    assert_eq!(res[0].ip, "あ.あ.あ.あ");
}

// 25. Extremely Long Strings (e.g. 1MB in Protocol)
#[tokio::test]
async fn test_25_extreme_long_strings() {
    let db_path = NamedTempFile::new().unwrap().into_temp_path();
    let db = IntelDb::open(&db_path).unwrap();
    let long_str = "A".repeat(1024 * 1024);
    let r = IntelRecord { ip: "7.7.7.7".to_string(), host: None, port: 80, protocol: long_str.clone(), banner: None, tech_stack: vec![], last_seen: None };
    
    db.insert_batch(&[r]).unwrap();
    let res = db.query_by_ip("7.7.7.7").unwrap();
    assert_eq!(res[0].protocol, long_str);
}

// 26. Malformed Constraints (SQL Injection Attempts)
#[tokio::test]
async fn test_26_sql_injection_attempt() {
    let db_path = NamedTempFile::new().unwrap().into_temp_path();
    let db = IntelDb::open(&db_path).unwrap();
    let r = IntelRecord { ip: "1' OR '1'='1".to_string(), host: None, port: 80, protocol: "tcp".to_string(), banner: None, tech_stack: vec![], last_seen: None };
    
    db.insert_batch(&[r]).unwrap();
    let res = db.query_by_ip("1' OR '1'='1").unwrap();
    assert_eq!(res.len(), 1);
}

// 27. Scanner Run with Multiple Targets
#[tokio::test]
async fn test_27_scanner_multiple_targets() {
    let db_path = NamedTempFile::new().unwrap().into_temp_path();
    let db = IntelDb::open(&db_path).unwrap();
    let r1 = IntelRecord { ip: "8.8.8.8".to_string(), host: None, port: 80, protocol: "tcp".to_string(), banner: None, tech_stack: vec![], last_seen: None };
    let r2 = IntelRecord { ip: "9.9.9.9".to_string(), host: None, port: 80, protocol: "tcp".to_string(), banner: None, tech_stack: vec![], last_seen: None };
    db.insert_batch(&[r1, r2]).unwrap();

    let scanner = IntelScanner::new(db_path.to_str().unwrap()).unwrap();
    let t1 = Target::Host(HostTarget { ip: "8.8.8.8".parse().unwrap(), domain: None });
    let t2 = Target::Host(HostTarget { ip: "9.9.9.9".parse().unwrap(), domain: None });
    
    let res_findings = run_and_collect_findings(&scanner, vec![t1, t2], &get_test_config()).await;
    assert_eq!(res_findings.len(), 2);
}

// 28. No Targets Input
#[tokio::test]
async fn test_28_no_targets() {
    let db_path = NamedTempFile::new().unwrap().into_temp_path();
    let scanner = IntelScanner::new(db_path.to_str().unwrap()).unwrap();
    
    let res_findings = run_and_collect_findings(&scanner, vec![], &get_test_config()).await;
    assert_eq!(res_findings.len(), 0);
}

// 29. Corrupted DB Path
#[tokio::test]
async fn test_29_corrupted_db_path() {
    let res = IntelScanner::new("/dev/null/invalid");
    assert!(res.is_err());
}

// 30. Database Locked Simulator
#[tokio::test]
async fn test_30_database_locked() {
    // Sqlite normally handles this with PRAGMA busy_timeout, but we test open
    let db_path = NamedTempFile::new().unwrap().into_temp_path();
    let _db1 = IntelDb::open(&db_path).unwrap();
    let db2 = IntelDb::open(&db_path).unwrap();
    
    // SQLite allows multiple opens. Try to write concurrently
    let r = IntelRecord { ip: "10.10.10.10".to_string(), host: None, port: 80, protocol: "tcp".to_string(), banner: None, tech_stack: vec![], last_seen: None };
    db2.insert_batch(&[r]).unwrap();
}

// 31. Invalid Protocol Field
#[tokio::test]
async fn test_31_invalid_protocol() {
    let db_path = NamedTempFile::new().unwrap().into_temp_path();
    let db = IntelDb::open(&db_path).unwrap();
    let r = IntelRecord { ip: "11.11.11.11".to_string(), host: None, port: 80, protocol: "".to_string(), banner: None, tech_stack: vec![], last_seen: None };
    
    db.insert_batch(&[r]).unwrap();
    let res = db.query_by_ip("11.11.11.11").unwrap();
    assert_eq!(res[0].protocol, "");
}

// 32. Ingester with Trailing Whitespace
#[tokio::test]
async fn test_32_ingester_trailing_whitespace() {
    let db_path = NamedTempFile::new().unwrap().into_temp_path();
    let mut db = IntelDb::open(&db_path).unwrap();
    let mut jsonl_file = NamedTempFile::new().unwrap();
    writeln!(jsonl_file, "{{\"ip\": \"12.12.12.12\", \"port\": 80, \"protocol\": \"tcp\"}}   ").unwrap();
    jsonl_file.flush().unwrap();
    let _ = jsonl_file.as_file().sync_all();
    
    
    let count = Ingester::ingest_jsonl(&db, jsonl_file.path()).unwrap();
    assert_eq!(count, 1);
}

// 33. Empty Protocol and IP
#[tokio::test]
async fn test_33_empty_protocol_and_ip() {
    let db_path = NamedTempFile::new().unwrap().into_temp_path();
    let db = IntelDb::open(&db_path).unwrap();
    let r = IntelRecord { ip: "".to_string(), host: None, port: 0, protocol: "".to_string(), banner: None, tech_stack: vec![], last_seen: None };
    
    db.insert_batch(&[r]).unwrap();
    let res = db.query_by_ip("").unwrap();
    assert_eq!(res[0].ip, "");
    assert_eq!(res[0].port, 0);
}

// 34. Check Finding Tag assignment
#[tokio::test]
async fn test_34_finding_tags() {
    let db_path = NamedTempFile::new().unwrap().into_temp_path();
    let db = IntelDb::open(&db_path).unwrap();
    let record = IntelRecord {
        ip: "13.13.13.13".to_string(),
        host: None,
        port: 80,
        protocol: "tcp".to_string(),
        banner: None,
        tech_stack: vec!["rust".to_string(), "react".to_string()],
        last_seen: None,
    };
    db.insert_batch(&[record]).unwrap();

    let scanner = IntelScanner::new(db_path.to_str().unwrap()).unwrap();
    let target = Target::Host(HostTarget { ip: "13.13.13.13".parse().unwrap(), domain: None });
    let res_findings = run_and_collect_findings(&scanner, vec![target], &get_test_config()).await;
    
    // tags() returns &[Arc<str>]; compare element-wise to avoid the
    // Arc<str>-vs-String type wall on `Vec::contains`.
    let tag_strs: Vec<&str> = res_findings[0].tags().iter().map(|t| t.as_ref()).collect();
    assert!(tag_strs.contains(&"tech:rust"));
    assert!(tag_strs.contains(&"tech:react"));
}
