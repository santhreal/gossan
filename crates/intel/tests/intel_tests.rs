use gossan_core::{Config, ScanInput, Scanner, Target};
use gossan_intel::{
    cache::IntelCache,
    db::{IntelDb, IntelRecord},
    enrichment::IntelEnrichment,
    ingest::Ingester,
    IntelScanner,
};
use std::sync::Arc;
use tempfile::NamedTempFile;
use tokio::sync::mpsc;

fn get_test_config() -> Config {
    Config::default()
}

fn make_input(targets: Vec<Target>) -> (ScanInput, mpsc::UnboundedReceiver<secfinding::Finding>) {
    let (live_tx, live_rx) = mpsc::unbounded_channel();
    let (target_tx, target_rx) = mpsc::unbounded_channel();

    // Send targets to the channel before creating the input
    for t in targets {
        let _ = target_tx.send(t);
    }
    // Drop the sender so the receiver will eventually return None
    drop(target_tx);

    let input = ScanInput {
        seed: "test".to_string(),
        target_rx: tokio::sync::Mutex::new(target_rx),
        live_tx,
        target_tx: mpsc::unbounded_channel().0, // New sender for downstream targets
        resolver: Arc::new(gossan_core::net::build_resolver(&get_test_config()).unwrap()),
    };
    (input, live_rx)
}

#[tokio::test]
async fn test_ip_lookup_offline() {
    let db_path = NamedTempFile::new().unwrap().into_temp_path();
    let db = IntelDb::open(&db_path).unwrap();
    let record = IntelRecord {
        ip: "192.168.1.1".to_string(),
        host: None,
        port: 80,
        protocol: "tcp".to_string(),
        banner: None,
        tech_stack: vec![],
        last_seen: None,
    };
    db.insert_batch(&[record]).unwrap();

    let scanner = IntelScanner::new(db_path.to_str().unwrap()).unwrap();
    let target = Target::Host(gossan_core::HostTarget {
        ip: "192.168.1.1".parse().unwrap(),
        domain: None,
    });

    let (input, mut live_rx) = make_input(vec![target]);
    scanner.run(input, &get_test_config()).await.unwrap();

    let finding = live_rx.recv().await.expect("expected a finding");
    assert!(finding.detail().contains("IP: 192.168.1.1"));
    assert!(finding.detail().contains("Port: 80"));
}

#[tokio::test]
async fn test_domain_lookup_offline() {
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
    let target = Target::Domain(gossan_core::DomainTarget {
        domain: "example.com".to_string(),
        source: gossan_core::target::DiscoverySource::Seed,
    });

    let (input, mut live_rx) = make_input(vec![target]);
    scanner.run(input, &get_test_config()).await.unwrap();

    let finding = live_rx.recv().await.expect("expected a finding");
    assert!(finding.detail().contains("Created: 1999"));
}

#[tokio::test]
async fn test_concurrent_intel_lookups() {
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
    for _ in 0..10 {
        let sc = Arc::clone(&scanner);
        handles.push(tokio::spawn(async move {
            let target = Target::Host(gossan_core::HostTarget {
                ip: "10.10.10.10".parse().unwrap(),
                domain: None,
            });
            let (input, mut live_rx) = make_input(vec![target]);
            sc.run(input, &get_test_config()).await.unwrap();
            let finding = live_rx.recv().await.expect("expected a finding");
            assert!(finding.detail().contains("10.10.10.10"));
        }));
    }
    for h in handles {
        h.await.unwrap();
    }
}

#[tokio::test]
async fn test_cache_hit_miss_correctness() {
    let cache_path = NamedTempFile::new().unwrap().into_temp_path();
    let cache = IntelCache::open(&cache_path).unwrap();

    let enrichment = IntelEnrichment::new("shodan", "ip", "11.11.11.11");
    cache.put(&enrichment).unwrap();

    let hit = cache.get("shodan", "ip", "11.11.11.11", 3600).unwrap();
    assert!(hit.is_some());

    let miss = cache.get("shodan", "ip", "12.12.12.12", 3600).unwrap();
    assert!(miss.is_none());
}

#[tokio::test]
async fn test_ingestion_empty_file() {
    let db_path = NamedTempFile::new().unwrap().into_temp_path();
    let mut db = IntelDb::open(&db_path).unwrap();
    let jsonl_file = NamedTempFile::new().unwrap();

    let count = Ingester::ingest_jsonl(&db, jsonl_file.path()).unwrap();
    assert_eq!(count, 0);
}

#[tokio::test]
async fn test_ingestion_malformed_jsonl() {
    use std::io::Write;

    let db_path = NamedTempFile::new().unwrap().into_temp_path();
    let mut db = IntelDb::open(&db_path).unwrap();
    let mut jsonl_file = NamedTempFile::new().unwrap();
    writeln!(jsonl_file, "invalid json").unwrap();
    writeln!(
        jsonl_file,
        r#"{{"ip": "1.1.1.1", "port": 80, "protocol": "tcp"}}"#
    )
    .unwrap();
    writeln!(jsonl_file, r#"{{"ip": "#).unwrap();
    jsonl_file.flush().unwrap();
    let _ = jsonl_file.as_file().sync_all();

    let count = Ingester::ingest_jsonl(&db, jsonl_file.path()).unwrap();
    assert_eq!(count, 1);

    let res = db.query_by_ip("1.1.1.1").unwrap();
    assert_eq!(res.len(), 1);
}

#[tokio::test]
async fn test_ingestion_massive_inputs() {
    use std::io::Write;

    let db_path = NamedTempFile::new().unwrap().into_temp_path();
    let mut db = IntelDb::open(&db_path).unwrap();
    let mut jsonl_file = NamedTempFile::new().unwrap();

    for i in 0..10_000 {
        writeln!(
            jsonl_file,
            r#"{{"ip": "10.0.0.{}", "port": 80, "protocol": "tcp"}}"#,
            i % 256
        )
        .unwrap();
    }
    jsonl_file.flush().unwrap();
    let _ = jsonl_file.as_file().sync_all();

    let count = Ingester::ingest_jsonl(&db, jsonl_file.path()).unwrap();
    assert_eq!(count, 10_000);
}

#[tokio::test]
async fn test_port_validation_rejects_negative() {
    let db_path = NamedTempFile::new().unwrap().into_temp_path();
    let db = IntelDb::open(&db_path).unwrap();
    // Insert an invalid port directly via SQL to simulate corruption
    {
        // Reach into the connection via the documented test helper —
        // the field itself is private. See `IntelDb::_test_conn`.
        let conn = db._test_conn().lock().unwrap();
        conn.execute(
            "INSERT INTO intel (ip, host, port, protocol) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params!["1.1.1.1", None::<String>, -1, "tcp"],
        )
        .unwrap();
    }
    let res = db.query_by_ip("1.1.1.1");
    assert!(res.is_err());
}

#[tokio::test]
async fn test_scanner_accepts() {
    // Use the canonical builder; the previous open-coded
    // `IntelScanner { client, sources, cache, cache_ttl_secs, db,
    // limiter }` was based on a struct shape that has since changed
    // (the `client` field is `ScanClient`, not `reqwest::Client`,
    // and the build path is `IntelScanner::from_config(&Config)`).
    let cfg = gossan_core::Config::default();
    let scanner =
        IntelScanner::from_config(&cfg).expect("intel scanner must build from default config");

    assert!(scanner.accepts(&Target::Host(gossan_core::HostTarget {
        ip: "1.1.1.1".parse().unwrap(),
        domain: None,
    })));
    assert!(scanner.accepts(&Target::Domain(gossan_core::DomainTarget {
        domain: "test.com".to_string(),
        source: gossan_core::target::DiscoverySource::Seed,
    })));
    // WebAssetTarget grew several fields (favicon_hash, body_hash,
    // forms, params) and ServiceTarget added (banner, tls). The
    // Target::Web variant is now boxed (Box<WebAssetTarget>) too.
    // url switched from String to url::Url.
    let web = gossan_core::WebAssetTarget {
        url: "https://example.com".parse().unwrap(),
        service: gossan_core::ServiceTarget {
            host: gossan_core::HostTarget {
                ip: "1.1.1.1".parse().unwrap(),
                domain: None,
            },
            port: 443,
            protocol: gossan_core::Protocol::Tcp,
            banner: None,
            tls: true,
        },
        tech: vec![],
        status: 200,
        title: None,
        favicon_hash: None,
        body_hash: None,
        forms: vec![],
        params: vec![],
    };
    assert!(!scanner.accepts(&Target::Web(Box::new(web))));
}
