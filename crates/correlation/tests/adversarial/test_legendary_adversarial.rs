use gossan_correlation::{AdminExposedRule, CorrelationEngine, CorrelationRule, TlsWeaknessRule};
use secfinding::{Finding, Severity};

fn create_finding(scanner: &str, target: &str, title: &str) -> Finding {
    Finding::builder(scanner, target, Severity::Medium)
        .title(title)
        .build()
        .expect("finding builder")
}

#[test]
fn engine_handles_empty_input() {
    let engine = CorrelationEngine::new();
    let chains = engine.run(&[], &[]);
    assert!(chains.is_empty());
}

#[test]
fn tls_weakness_handles_null_bytes() {
    // The contract under test:
    //   - secfinding rejects null bytes in `target` at construction
    //     (intentional sanitisation barrier).
    //   - The correlation engine therefore can never receive a finding
    //     with a null-byte target, but it MUST also not panic when
    //     handed targets with adjacent suspicious characters (control
    //     chars, unicode separators) that DO get through validation.
    //
    // We assert both halves so the boundary is documented and a
    // future loosening of secfinding's validator gets caught here.
    let rejected = Finding::builder("portscan", "example.com\x00malicious", Severity::Medium)
        .title("Self-signed TLS certificate")
        .build()
        .expect_err("secfinding must reject null bytes in target");
    assert!(
        format!("{rejected:#}").contains("null"),
        "rejection error must name null-byte cause; got {rejected:#}"
    );

    // Suspicious but legal: U+200B (zero-width space) and U+0001 (SOH)
    // pass secfinding's validator. The engine must group them.
    let weird_target = "example\u{200b}.com";
    let findings = vec![
        create_finding("portscan", weird_target, "Self-signed TLS certificate"),
        create_finding("portscan", weird_target, "Missing HSTS header"),
    ];
    let chains = TlsWeaknessRule.check(&findings, &[]);
    assert_eq!(chains.len(), 1);
    assert!(chains[0].target().contains("example"));
}

#[test]
fn admin_exposed_handles_unicode_targets() {
    let target = "hëllö-wórld.com/çhîñæ/経路";
    let findings = vec![
        create_finding("hidden", target, "Admin panel exposed"),
        create_finding("hidden", target, "No authentication required"),
    ];

    let chains = AdminExposedRule.check(&findings, &[]);
    assert_eq!(chains.len(), 1);
    assert_eq!(chains[0].target(), target);
}

#[test]
fn engine_handles_huge_input() {
    let mut findings = Vec::with_capacity(100_000);

    // Create 100k noise findings
    for i in 0..100_000 {
        findings.push(create_finding(
            "noise",
            &format!("host-{}.internal", i),
            "Unrelated finding",
        ));
    }

    // Embed correlation triggers at the very end
    findings.push(create_finding(
        "hidden",
        "admin.internal",
        "Admin panel exposed",
    ));
    findings.push(create_finding(
        "hidden",
        "admin.internal",
        "No authentication required",
    ));

    let engine = CorrelationEngine::new();
    let chains = engine.run(&findings, &[]);

    // Engine should efficiently filter the noise and find the 1 chain
    assert_eq!(chains.len(), 1);
    assert!(chains[0]
        .title()
        .contains("Admin panel exposed without authentication"));
}

#[test]
fn tls_weakness_handles_path_traversal_titles() {
    let findings = vec![
        create_finding(
            "portscan",
            "example.com",
            "../../../etc/passwd Self-signed TLS certificate",
        ),
        create_finding(
            "portscan",
            "example.com",
            "Missing HSTS header /var/log/../../",
        ),
    ];

    let chains = TlsWeaknessRule.check(&findings, &[]);
    assert_eq!(chains.len(), 1);
}

#[test]
fn engine_handles_duplicate_huge_findings() {
    let mut findings = Vec::new();
    // 100 duplicate findings
    for _ in 0..100 {
        findings.push(create_finding(
            "portscan",
            "example.com",
            "Self-signed TLS certificate",
        ));
    }

    let engine = CorrelationEngine::new();
    let chains = engine.run(&findings, &[]);

    // Rule deduplication should ensure we don't get 100 identical chains or panic
    assert!(chains.is_empty(), "Multiple IDENTICAL tls issues should not trigger the chain rule since it requires DISTINCT issues");
}

#[test]
fn engine_handles_0xff_bytes_in_target() {
    // The contract under test:
    //   - secfinding rejects targets containing the Unicode replacement
    //     character (U+FFFD), which is what `String::from_utf8_lossy`
    //     produces when given invalid UTF-8 bytes like 0xFF. This is
    //     deliberate — a U+FFFD in a target name almost always means
    //     a discovery source mis-decoded raw bytes upstream and we
    //     don't want that propagating into the asset graph.
    //   - The correlation engine MUST also handle exotic-but-legal
    //     unicode targets (CJK, emoji, RTL marks) without panicking.
    let target_lossy = String::from_utf8_lossy(&[0xFF, 0xFF, 0xFF, 0xFF]).into_owned();
    let err = Finding::builder("hidden", target_lossy, Severity::Medium)
        .title("Admin panel exposed")
        .build()
        .expect_err("secfinding must reject U+FFFD in target");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("FFFD") || msg.to_lowercase().contains("replacement"),
        "rejection error must name U+FFFD; got {msg}"
    );

    // Exotic-but-legal unicode the engine must still group. Mixes RTL
    // mark, CJK, emoji, and a zero-width joiner.
    let exotic = "\u{200f}例.com/path\u{1f600}";
    let findings = vec![
        create_finding("hidden", exotic, "Admin panel exposed"),
        create_finding("hidden", exotic, "No authentication required"),
    ];
    let engine = CorrelationEngine::new();
    let chains = engine.run(&findings, &[]);
    assert_eq!(chains.len(), 1);
    assert_eq!(chains[0].target(), exotic);
}
