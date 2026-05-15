use gossan_correlation::{AdminExposedRule, CorrelationEngine, CorrelationRule, TlsWeaknessRule};
use secfinding::{Finding, Severity};

fn create_finding(scanner: &str, target: &str, title: &str) -> Finding {
    Finding::builder(scanner, target, Severity::High)
        .title(title)
        .build()
        .expect("finding builder")
}

#[test]
fn gap_tls_weakness_should_group_by_port_not_just_host() {
    // Current implementation groups entirely by `target.as_str()`.
    // If a target contains the port (e.g., example.com:443 vs example.com:8443)
    // and a single scanner runs, it may produce findings on both.
    // If we have Self-signed on 443 and Missing HSTS on 8443, they shouldn't
    // necessarily correlate UNLESS the host is parsed correctly to strip ports,
    // OR we strictly isolate by exact service/port combination to prevent
    // false chaining across entirely different services.

    // In this gap test, we assert that the engine is smart enough to realize
    // these are different services, and therefore the TLS weaknesses on 443
    // do not "combine" with weaknesses on 8443 to create a chain for either.
    // (Or conversely, if the intention is host-level chaining, we assert they DO combine
    // and produce a host-level chain finding. We test the latter, more restrictive API contract here).

    let findings = vec![
        create_finding("portscan", "example.com:443", "Self-signed TLS certificate"),
        create_finding("hidden", "example.com:8443", "Missing HSTS header"),
    ];

    let chains = TlsWeaknessRule.check(&findings, &[]);

    // Ideal contract: the rule recognizes they share the same HOST ("example.com")
    // and emits a chain finding for "example.com".
    // Alternatively, it strictly isolates them and emits 0.
    // Let's assert the ideal "host-level correlation" behaviour: it SHOULD find them
    // and group them under the stripped host.
    //
    // CURRENT BUG/GAP: The implementation uses `host.clone()` from `f.target()`.
    // So "example.com:443" and "example.com:8443" are treated as totally different hosts.
    // Thus it will emit 0 chains, failing this test.
    assert_eq!(
        chains.len(),
        1,
        "GAP FINDING: TlsWeaknessRule fails to strip ports and correlate across the same host"
    );
    assert_eq!(chains[0].target(), "example.com");
}

#[test]
fn gap_admin_exposed_should_correlate_across_http_and_https() {
    // Similar to above, `admin.example.com` via HTTP might lack auth,
    // while `https://admin.example.com` has the exposed panel.
    // The target strings might look like `http://admin.example.com` and `https://admin.example.com`.

    let findings = vec![
        create_finding("hidden", "https://admin.example.com", "Admin panel exposed"),
        create_finding(
            "hidden",
            "http://admin.example.com",
            "No authentication required",
        ),
    ];

    let chains = AdminExposedRule.check(&findings, &[]);

    // Ideal contract: The engine normalizes targets (stripping scheme/port) before correlating.
    // CURRENT BUG/GAP: AdminExposedRule just compares the raw `f.target()`.
    // It will fail to match "https://admin.example.com" with "http://admin.example.com".
    assert_eq!(chains.len(), 1, "GAP FINDING: AdminExposedRule fails to correlate across different schemes/protocols for the same host");
}

#[test]
fn gap_correlation_engine_should_track_evidence_accurately() {
    let findings = vec![
        create_finding("hidden", "admin.example.com", "Admin panel exposed"),
        create_finding("hidden", "admin.example.com", "No authentication required"),
    ];

    // The engine creates a chain.
    let engine = CorrelationEngine::new();
    let chains = engine.run(&findings, &[]);
    assert_eq!(chains.len(), 1);

    // Ideal contract: A chain finding SHOULD include evidence linking back to ALL
    // findings that triggered it, so the user knows exactly why the chain was formed.
    // CURRENT BUG/GAP: AdminExposedRule only grabs the `evidence_id` of the FIRST finding
    // (the admin panel exposure) and completely ignores the second finding in its evidence.

    let evidence_str = format!("{:?}", chains[0].evidence());
    assert!(
        evidence_str.contains(&findings[0].id().to_string()),
        "Should contain first finding ID"
    );
    assert!(
        evidence_str.contains(&findings[1].id().to_string()),
        "GAP FINDING: Chain evidence is missing the second finding ID"
    );
}
