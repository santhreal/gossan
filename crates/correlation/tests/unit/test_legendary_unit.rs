use gossan_correlation::{AdminExposedRule, CorrelationEngine, CorrelationRule, TlsWeaknessRule};
use secfinding::{Finding, Severity};

fn create_finding(scanner: &str, target: &str, title: &str, severity: Severity) -> Finding {
    Finding::builder(scanner, target, severity)
        .title(title)
        .build()
        .expect("finding builder: required fields are set")
}

#[test]
fn engine_initialization() {
    let engine = CorrelationEngine::new();
    let default_engine = CorrelationEngine::default();

    let findings = vec![];
    let targets = vec![];

    let result1 = engine.run(&findings, &targets);
    let result2 = default_engine.run(&findings, &targets);

    assert!(result1.is_empty());
    assert!(result2.is_empty());
}

#[test]
fn admin_exposed_rule_basic() {
    let rule = AdminExposedRule;
    assert_eq!(rule.name(), "admin-no-auth-chain");

    let findings = vec![
        create_finding(
            "hidden",
            "admin.example.com",
            "Admin panel exposed",
            Severity::High,
        ),
        create_finding(
            "hidden",
            "admin.example.com",
            "No authentication required",
            Severity::High,
        ),
    ];

    let new_findings = rule.check(&findings, &[]);
    assert_eq!(new_findings.len(), 1);
    assert_eq!(new_findings[0].severity(), Severity::Critical);
    assert!(new_findings[0]
        .title()
        .contains("Admin panel exposed without authentication"));
}

#[test]
fn admin_exposed_rule_no_match() {
    let rule = AdminExposedRule;

    let findings = vec![
        create_finding(
            "hidden",
            "admin.example.com",
            "Admin panel exposed",
            Severity::High,
        ),
        create_finding(
            "hidden",
            "other.example.com",
            "No authentication required",
            Severity::High,
        ),
    ];

    let new_findings = rule.check(&findings, &[]);
    assert!(new_findings.is_empty());
}

#[test]
fn tls_weakness_rule_basic() {
    let rule = TlsWeaknessRule;
    assert_eq!(rule.name(), "tls-weakness-chain");

    let findings = vec![
        create_finding(
            "portscan",
            "example.com",
            "Self-signed TLS certificate",
            Severity::Medium,
        ),
        create_finding(
            "hidden",
            "example.com",
            "Missing HSTS header",
            Severity::Low,
        ),
    ];

    let new_findings = rule.check(&findings, &[]);
    assert_eq!(new_findings.len(), 1);
    assert_eq!(new_findings[0].severity(), Severity::High);
    assert!(new_findings[0].title().contains("Multiple TLS weaknesses"));
}

#[test]
fn tls_weakness_rule_single_issue() {
    let rule = TlsWeaknessRule;

    let findings = vec![create_finding(
        "portscan",
        "example.com",
        "Self-signed TLS certificate",
        Severity::Medium,
    )];

    let new_findings = rule.check(&findings, &[]);
    assert!(new_findings.is_empty());
}
