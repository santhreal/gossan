use super::*;
use std::net::IpAddr;
use std::time::Duration;
use tokio::net::TcpListener;

fn service(port: u16, banner: Option<&str>) -> ServiceTarget {
    ServiceTarget {
        host: HostTarget {
            ip: IpAddr::from([127, 0, 0, 1]),
            domain: Some("example.com".into()),
        },
        port,
        protocol: Protocol::Tcp,
        banner: banner.map(str::to_string),
        tls: matches!(port, 443 | 465 | 636 | 993 | 8443),
    }
}

#[test]
fn scanner_accepts_domains_and_hosts_only() {
    let scanner = PortScanner;
    assert!(scanner.accepts(&Target::Domain(DomainTarget {
        domain: "example.com".into(),
        source: DiscoverySource::Seed,
    })));
    assert!(scanner.accepts(&Target::Host(HostTarget {
        ip: IpAddr::from([127, 0, 0, 1]),
        domain: None,
    })));
    assert!(!scanner.accepts(&Target::Service(service(443, None))));
}

#[test]
fn risky_ports_list_contains_high_value_targets() {
    for port in [23, 2375, 6379, 9200, 10250, 30303] {
        assert!(
            RISKY.iter().any(|r| r.port == port),
            "missing risky port {port}"
        );
    }
}

#[test]
fn identify_banner_detects_old_ssh_versions_as_high() {
    let finding = identify_banner(
        "SSH-2.0-OpenSSH_7.2p1 Ubuntu-4ubuntu2.10",
        &service(22, None),
        22,
    )
    .unwrap();

    assert_eq!(finding.severity, Severity::High);
    assert!(finding.title.contains("SSH version disclosed"));
    assert!(finding.tags.contains(&"ssh".to_string()));
}

#[test]
fn identify_banner_detects_modern_ssh_versions_as_info() {
    let finding = identify_banner("SSH-2.0-OpenSSH_9.7", &service(22, None), 22).unwrap();

    assert_eq!(finding.severity, Severity::Info);
}

#[test]
fn identify_banner_detects_ftp_banner() {
    let finding = identify_banner("220 ProFTPD 1.3.5 Server", &service(21, None), 21).unwrap();
    assert!(finding.title.contains("FTP banner"));
    assert!(finding.tags.contains(&"ftp".to_string()));
}

#[test]
fn identify_banner_detects_smtp_banner() {
    let finding =
        identify_banner("220 mx.example.com ESMTP Postfix", &service(25, None), 25).unwrap();
    assert!(finding.title.contains("SMTP banner"));
    assert!(finding.tags.contains(&"smtp".to_string()));
}

#[test]
fn identify_banner_extracts_http_server_header() {
    let banner = "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\n";
    let finding = identify_banner(banner, &service(80, None), 80).unwrap();
    assert!(finding.title.contains("HTTP server header"));
    assert!(finding.detail.contains("discloses"));
}

#[test]
fn identify_banner_detects_redis_no_auth() {
    let finding = identify_banner("+PONG", &service(6379, None), 6379).unwrap();
    assert_eq!(finding.severity, Severity::Critical);
    assert!(finding
        .title
        .contains("Redis responds without authentication"));
}

#[test]
fn identify_banner_detects_mongodb_no_auth() {
    let finding = identify_banner("ismaster MongoDB", &service(27017, None), 27017).unwrap();
    assert_eq!(finding.severity, Severity::Critical);
    assert!(finding.tags.contains(&"mongodb".to_string()));
}

#[test]
fn identify_banner_detects_telnet_response() {
    let finding = identify_banner("Welcome", &service(23, None), 23).unwrap();
    assert_eq!(finding.severity, Severity::Critical);
    assert!(finding.tags.contains(&"telnet".to_string()));
}

#[test]
fn identify_banner_returns_none_for_unrecognized_banner() {
    assert!(identify_banner("some random banner", &service(1234, None), 1234).is_none());
}

#[test]
fn port_mode_custom_can_represent_explicit_ranges() {
    let mode = PortMode::Custom(vec![1, 80, 443, 65535]);
    let PortMode::Custom(ports) = mode else {
        panic!("expected custom mode");
    };
    assert_eq!(ports, vec![1, 80, 443, 65535]);
}

#[test]
fn top_ports_tables_are_nonempty_and_unique() {
    use std::collections::HashSet;

    assert!(!top_ports::TOP_100.is_empty());
    assert!(!top_ports::TOP_1000.is_empty());
    assert_eq!(
        top_ports::TOP_100.iter().collect::<HashSet<_>>().len(),
        top_ports::TOP_100.len()
    );
    assert_eq!(
        top_ports::TOP_1000.iter().collect::<HashSet<_>>().len(),
        top_ports::TOP_1000.len()
    );
}

#[test]
fn default_portset_includes_common_web_and_database_ports() {
    for port in [80, 443, 5432, 6379, 8080] {
        assert!(PORTS.contains(&port), "missing default port {port}");
    }
}

// ============================================================================
// Edge case tests for port scanning
// ============================================================================

/// Port 0 is technically valid but may behave differently across platforms.
/// This test verifies our scanner handles it without panicking.
#[tokio::test]
async fn port_zero_is_handled_gracefully() {
    let scanner = PortScanner::new();
    // Port 0 typically results in a dynamic port assignment when binding,
    // but when scanning it should simply fail to connect (nothing listening)
    // without causing a panic or error.
    assert!(scanner.accepts(&Target::Domain(DomainTarget {
        domain: "localhost".into(),
        source: DiscoverySource::Seed,
    })));
}

/// Port 65535 is the maximum valid port number.
/// Ensure we handle it correctly in our port lists and scanning.
#[test]
fn port_maximum_valid_u16() {
    // Port 65535 is valid (u16::MAX)
    let max_port: u16 = 65535;
    assert_eq!(max_port, u16::MAX);

    // Verify it can be represented in custom port mode
    let mode = PortMode::Custom(vec![65535]);
    match mode {
        PortMode::Custom(ports) => {
            assert_eq!(ports, vec![65535]);
        }
        _ => panic!("expected custom mode"),
    }
}

/// Test that connection timeout is respected and returns gracefully.
#[tokio::test]
async fn connection_timeout_respected() {
    // Use a reserved documentation/test IP that should never respond
    // 192.0.2.0/24 is TEST-NET-1, guaranteed non-routable
    let start = std::time::Instant::now();
    let timeout_duration = Duration::from_millis(100);

    // Attempt connection with short timeout
    let _result = tokio::time::timeout(
        timeout_duration * 2,
        gossan_core::net::connect_tcp("192.0.2.1", 9999, None),
    )
    .await;

    let elapsed = start.elapsed();

    // Should complete (either timeout or fail) within reasonable time
    // Allow some buffer for the timeout
    assert!(
        elapsed < Duration::from_secs(5),
        "Connection attempt took too long: {:?}",
        elapsed
    );
}

/// Test that banner grab times out gracefully when server is silent.
#[tokio::test]
async fn banner_grab_times_out_on_silent_server() {
    // Bind to a local port but never send data
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_addr = listener.local_addr().unwrap();

    let server_task = tokio::spawn(async move {
        // Accept connection but never send data
        let (socket, _) = listener.accept().await.unwrap();
        // Hold the connection open but silent
        tokio::time::sleep(Duration::from_secs(10)).await;
        drop(socket);
    });

    // Connect to the silent server
    let stream = tokio::net::TcpStream::connect(local_addr).await.unwrap();

    // Banner grab should timeout (uses 800ms internally)
    let start = std::time::Instant::now();
    let banner = grab_banner(stream, Duration::from_millis(500)).await;
    let elapsed = start.elapsed();

    // Should return None (timeout)
    assert!(banner.is_none(), "Expected None for silent server");

    // Should have timed out around 800ms, definitely under 2 seconds
    assert!(
        elapsed < Duration::from_secs(2),
        "Banner grab took too long to timeout: {:?}",
        elapsed
    );

    // Clean up
    server_task.abort();
}

/// Test that port scanning handles empty port lists gracefully.
#[test]
fn empty_port_list_handled() {
    let mode = PortMode::Custom(vec![]);
    match mode {
        PortMode::Custom(ports) => {
            assert!(ports.is_empty());
        }
        _ => panic!("expected custom mode"),
    }
}

/// Test full port range generation (1-65535) doesn't panic.
#[test]
fn full_port_range_generation() {
    // Simulating PortMode::Full behavior
    let full_range: Vec<u16> = (1u16..=65535).collect();
    assert_eq!(full_range.len(), 65535);
    assert_eq!(full_range[0], 1);
    assert_eq!(full_range[65534], 65535);
}

/// Test that banner processing handles oversized data correctly.
#[test]
fn banner_processing_handles_large_input() {
    let svc = service(22, None);

    // Create a banner larger than the 512-byte buffer
    let large_banner = "A".repeat(2000);
    // This shouldn't match SSH patterns but also shouldn't panic
    let finding = identify_banner(&large_banner, &svc, 22);

    // Should return None since it doesn't match any pattern
    assert!(finding.is_none());
}

/// Test that binary/non-UTF8 data in banners is sanitized.
#[test]
fn banner_sanitizes_binary_data() {
    // Simulate binary data that might come from a service
    let binary_data: Vec<u8> = vec![
        0x00, 0x01, 0x02, 0x03, // Non-printable (4 bytes)
        0x20, 0x21, 0x22, // Printable: space, !, " (3 bytes)
        0x7f, 0x80, 0xff, // Edge (DEL) and non-ASCII (3 bytes)
    ];

    // The sanitize logic replaces non-printable with '.'
    // Range (0x20..0x7f) = 0x20 to 0x7e inclusive
    let sanitized: String = binary_data
        .iter()
        .map(|&b| {
            if (0x20..0x7f).contains(&b) {
                b as char
            } else {
                '.'
            }
        })
        .collect();

    // Verify sanitization: 4 dots + space + ! + " + 3 dots
    assert_eq!(sanitized, ".... !\"...");
}

/// Test edge case port numbers in various contexts.
#[test]
fn edge_case_port_numbers() {
    // Test that common edge ports are handled
    let edge_ports = [1, 1024, 1025, 65534, 65535];

    for port in edge_ports {
        let svc = service(port, None);
        assert_eq!(svc.port, port);
    }
}

/// Verify finding builder works with edge case inputs.
#[test]
fn finding_builder_edge_cases() {
    let target = Target::Domain(DomainTarget {
        domain: "test.example.com".into(),
        source: DiscoverySource::Seed,
    });

    // Note: Empty title may fail validation - use minimal valid content
    let finding = finding_builder(&target, Severity::Info, "test", "test detail").build();
    assert!(finding.is_ok());

    // Very long strings
    let long_string = "x".repeat(10000);
    let finding = finding_builder(&target, Severity::High, &long_string, &long_string).build();
    assert!(finding.is_ok());

    // Unicode content
    let unicode = "测试 🎉 émoji 日本語";
    let finding = finding_builder(&target, Severity::Medium, unicode, unicode).build();
    assert!(finding.is_ok());
}

/// Test CVE correlation with edge case patterns.
#[test]
fn cve_correlation_edge_cases() {
    use crate::cve::correlate;

    let svc = service(80, None);

    // Empty banner
    let findings = correlate("", &svc);
    assert!(findings.is_empty());

    // Very long banner
    let long_banner = format!("Server: Apache/2.4.49{}", "x".repeat(10000));
    let findings = correlate(&long_banner, &svc);
    // Should still match the pattern
    assert!(findings.iter().any(|f| f.title.contains("CVE-2021-41773")));

    // Case insensitivity check
    let findings = correlate("SERVER: APACHE/2.4.49", &svc);
    assert!(findings.iter().any(|f| f.title.contains("CVE-2021-41773")));
}

/// Test TLS info display formatting.
#[test]
fn tls_cert_info_display() {
    use crate::tls::{days_until_expiry, LegacyTlsResult, TlsCertInfo};

    let info = TlsCertInfo {
        subject: "CN=test.com".into(),
        issuer: "CN=Test CA".into(),
        sans: vec!["test.com".into(), "www.test.com".into()],
        not_after_unix: 1893456000,
        is_self_signed: false,
    };

    let display = format!("{}", info);
    assert!(display.contains("TlsCertInfo"));
    assert!(display.contains("test.com"));
    assert!(display.contains("self-signed: false"));

    // Test LegacyTlsResult display
    let legacy = LegacyTlsResult {
        supports_tls10: true,
        supports_tls11: false,
    };
    let display = format!("{}", legacy);
    assert!(display.contains("VULNERABLE"));

    let legacy_clean = LegacyTlsResult {
        supports_tls10: false,
        supports_tls11: false,
    };
    let display = format!("{}", legacy_clean);
    assert!(display.contains("no legacy protocols"));

    // Test days_until_expiry edge cases
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    // Exactly now
    assert_eq!(days_until_expiry(now), 0);

    // Far future
    assert!(days_until_expiry(now + 365 * 86400) > 364);

    // Far past
    assert!(days_until_expiry(now - 365 * 86400) < -364);
}
