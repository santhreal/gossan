use gossan_correlation::{CorrelationEngine, CorrelationRule, TlsWeaknessRule, AdminExposedRule, ApiAuthRule, ShadowInfrastructureRule, SourceCodeSecretsRule, SsrfInternalRule};
use secfinding::{Finding, Severity, Evidence};
use gossan_core::{Target, DomainTarget, DiscoverySource};

fn create_finding(scanner: &str, target: &str, title: &str) -> Finding {
    Finding::builder(scanner, target, Severity::Medium)
        .title(title)
        .build()
        .expect("finding builder")
}

#[test]
fn test_evidence_chain_construction() {
    let f1 = create_finding("hidden", "admin.example.com", "Admin dashboard exposed");
    let f2 = create_finding("techstack", "admin.example.com", "Missing authentication");
    let chains = AdminExposedRule.check(&[f1.clone(), f2.clone()], &[]);
    assert_eq!(chains.len(), 1);
    let ev = &chains[0].evidence();
    assert_eq!(ev.len(), 1);
    match &ev[0] {
        secfinding::Evidence::Raw(s) => {
            assert!(s.contains(&f1.id.to_string()));
            assert!(s.contains(&f2.id.to_string()));
        }
        _ => panic!("Expected Raw evidence"),
    }
}

#[test]
fn test_concurrent_finding_submission_from_8_modules() {
    use std::sync::{Arc, Mutex};
    use std::thread;

    let engine = Arc::new(CorrelationEngine::new());
    let results = Arc::new(Mutex::new(Vec::new()));

    let mut handles = vec![];
    for _i in 0..8 {
        let engine_clone = Arc::clone(&engine);
        let results_clone = Arc::clone(&results);
        handles.push(thread::spawn(move || {
            let mut findings = Vec::new();
            for j in 0..100 {
                findings.push(create_finding("hidden", &format!("admin{}.example.com", j), "Admin panel exposed"));
                findings.push(create_finding("hidden", &format!("admin{}.example.com", j), "No authentication required"));
            }
            let chains = engine_clone.run(&findings, &[]);
            results_clone.lock().unwrap().extend(chains);
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    let total = results.lock().unwrap().len();
    assert_eq!(total, 800);
}

#[test]
fn test_finding_with_empty_evidence() {
    let f1 = create_finding("hidden", "admin.example.com", "Admin panel exposed");
    let f2 = create_finding("hidden", "admin.example.com", "No authentication required");
    let chains = AdminExposedRule.check(&[f1, f2], &[]);
    assert_eq!(chains.len(), 1);
}

#[test]
fn test_finding_serialization() {
    let f1 = create_finding("hidden", "admin.example.com", "Admin panel exposed");
    let json = serde_json::to_string(&f1).unwrap();
    let back: Finding = serde_json::from_str(&json).unwrap();
    assert_eq!(f1.title, back.title);
}

#[test]
fn test_severity_aggregation() {
    // Verify that two Medium findings correlate to a Critical finding.
    let f1 = create_finding("hidden", "admin.example.com", "Admin dashboard exposed");
    let f2 = create_finding("hidden", "admin.example.com", "No authentication required");
    let chains = AdminExposedRule.check(&[f1, f2], &[]);
    assert_eq!(chains.len(), 1);
    assert_eq!(chains[0].severity(), Severity::Critical);
}

#[test]
fn test_correlation_across_scan_phases() {
    let f1 = create_finding("portscan", "example.com", "Self-signed TLS certificate");
    let f2 = create_finding("hidden", "example.com", "Missing HSTS header");
    let chains = TlsWeaknessRule.check(&[f1, f2], &[]);
    assert_eq!(chains.len(), 1);
}

// Ensure 33 total tests in this file to cover adversarial/edge cases comprehensively.
// Let's write the remaining 28 actual adversarial tests targeting various rules & engine bounds.

#[test]
fn test_api_auth_rule_missing_auth() {
    let mut f1 = create_finding("hidden", "api.example.com", "API version enumeration");
    f1.tags.push("api-version".to_string());
    let f2 = create_finding("hidden", "api.example.com", "No authentication required");
    let chains = ApiAuthRule.check(&[f1, f2], &[]);
    assert_eq!(chains.len(), 1);
}

#[test]
fn test_api_auth_rule_no_versions() {
    let f2 = create_finding("hidden", "api.example.com", "No authentication required");
    let chains = ApiAuthRule.check(&[f2], &[]);
    assert!(chains.is_empty());
}

#[test]
fn test_shadow_infra_rule_known_domain() {
    let mut f1 = create_finding("hidden", "1.2.3.4", "TLS Certificate");
    f1.evidence.push(Evidence::Certificate {
        subject: "example.com".to_string(),
        issuer: "Let's Encrypt".to_string(),
        san: vec![],
        expires: "2025".to_string(),
    });
    let t = Target::Domain(DomainTarget {
        domain: "example.com".into(),
        source: DiscoverySource::Seed,
    });
    let chains = ShadowInfrastructureRule.check(&[f1], &[t]);
    assert!(chains.is_empty());
}

#[test]
fn test_shadow_infra_rule_unknown_domain() {
    let mut f1 = create_finding("hidden", "1.2.3.4", "TLS Certificate");
    f1.evidence.push(Evidence::Certificate {
        subject: "unknown.com".to_string(),
        issuer: "Let's Encrypt".to_string(),
        san: vec![],
        expires: "2025".to_string(),
    });
    let t = Target::Domain(DomainTarget {
        domain: "example.com".into(),
        source: DiscoverySource::Seed,
    });
    let chains = ShadowInfrastructureRule.check(&[f1], &[t]);
    assert_eq!(chains.len(), 1);
}

#[test]
fn test_source_secrets_rule_both_present() {
    let f1 = create_finding("hidden", "example.com", ".git/config exposed");
    let f2 = create_finding("js", "example.com", "AWS Access Key in JavaScript");
    let chains = SourceCodeSecretsRule.check(&[f1, f2], &[]);
    assert_eq!(chains.len(), 1);
}

#[test]
fn test_source_secrets_rule_only_secrets() {
    let f2 = create_finding("js", "example.com", "AWS Access Key in JavaScript");
    let chains = SourceCodeSecretsRule.check(&[f2], &[]);
    assert!(chains.is_empty());
}

#[test]
fn test_ssrf_internal_rule_both_present() {
    let f1 = create_finding("hidden", "example.com", "Server-side request forgery");
    let f2 = create_finding("hidden", "example.com", "Redis exposed without authentication");
    let chains = SsrfInternalRule.check(&[f1, f2], &[]);
    assert_eq!(chains.len(), 1);
}

#[test]
fn test_ssrf_internal_rule_only_ssrf() {
    let f1 = create_finding("hidden", "example.com", "Server-side request forgery");
    let chains = SsrfInternalRule.check(&[f1], &[]);
    assert!(chains.is_empty());
}

#[test]
fn test_admin_exposed_missing_auth_with_path() {
    let f1 = create_finding("hidden", "admin.example.com/login", "Admin dashboard exposed");
    let f2 = create_finding("techstack", "admin.example.com", "Missing authentication");
    let chains = AdminExposedRule.check(&[f1, f2], &[]);
    assert_eq!(chains.len(), 1);
}

#[test]
fn test_admin_exposed_missing_auth_with_scheme_and_port() {
    let f1 = create_finding("hidden", "https://admin.example.com:443", "Admin dashboard exposed");
    let f2 = create_finding("techstack", "http://admin.example.com:80", "Missing authentication");
    let chains = AdminExposedRule.check(&[f1, f2], &[]);
    assert_eq!(chains.len(), 1);
}

#[test]
fn test_tls_weakness_rule_with_scheme_and_port() {
    let f1 = create_finding("hidden", "https://example.com:443", "Missing HSTS header");
    let f2 = create_finding("portscan", "http://example.com:80", "Self-signed TLS certificate");
    let chains = TlsWeaknessRule.check(&[f1, f2], &[]);
    assert_eq!(chains.len(), 1);
}

#[test]
fn test_tls_weakness_rule_same_title() {
    let f1 = create_finding("hidden", "https://example.com:443", "Missing HSTS header");
    let f2 = create_finding("portscan", "http://example.com:80", "Missing HSTS header");
    let chains = TlsWeaknessRule.check(&[f1, f2], &[]);
    assert!(chains.is_empty()); // Deduplicated
}

#[test]
fn test_engine_empty_input_produces_no_chains() {
    let engine = CorrelationEngine::new();
    let chains = engine.run(&[], &[]);
    assert!(chains.is_empty());
}

#[test]
fn test_engine_single_finding_produces_no_chains() {
    let engine = CorrelationEngine::new();
    let f1 = create_finding("hidden", "admin.example.com", "Admin dashboard exposed");
    let chains = engine.run(&[f1], &[]);
    assert!(chains.is_empty());
}

#[test]
fn test_engine_no_correlation_criteria_met() {
    let engine = CorrelationEngine::new();
    let findings = vec![
        create_finding("hidden", "example.com", "Some random finding"),
        create_finding("portscan", "example.com", "Another random finding"),
    ];
    let chains = engine.run(&findings, &[]);
    assert!(chains.is_empty());
}

#[test]
fn test_engine_multiple_rules_fire() {
    let engine = CorrelationEngine::new();
    let findings = vec![
        create_finding("hidden", "admin.example.com", "Admin dashboard exposed"),
        create_finding("techstack", "admin.example.com", "Missing authentication"),
        create_finding("portscan", "example.com", "Self-signed TLS certificate"),
        create_finding("hidden", "example.com", "Missing HSTS header"),
    ];
    let chains = engine.run(&findings, &[]);
    assert_eq!(chains.len(), 2);
}

#[test]
fn test_shadow_infra_rule_ignore_cloudfront() {
    let mut f1 = create_finding("hidden", "1.2.3.4", "TLS Certificate");
    f1.evidence.push(Evidence::Certificate {
        subject: "foo.cloudfront.net".to_string(),
        issuer: "Let's Encrypt".to_string(),
        san: vec![],
        expires: "2025".to_string(),
    });
    let chains = ShadowInfrastructureRule.check(&[f1], &[]);
    assert!(chains.is_empty());
}

#[test]
fn test_shadow_infra_rule_ignore_empty() {
    let mut f1 = create_finding("hidden", "1.2.3.4", "TLS Certificate");
    f1.evidence.push(Evidence::Certificate {
        subject: "".to_string(),
        issuer: "Let's Encrypt".to_string(),
        san: vec![],
        expires: "2025".to_string(),
    });
    let chains = ShadowInfrastructureRule.check(&[f1], &[]);
    assert!(chains.is_empty());
}

#[test]
fn test_shadow_infra_rule_multiple_sans() {
    let mut f1 = create_finding("hidden", "1.2.3.4", "TLS Certificate");
    f1.evidence.push(Evidence::Certificate {
        subject: "unknown.com".to_string(),
        issuer: "Let's Encrypt".to_string(),
        san: vec!["also-unknown.com".to_string(), "foo.cloudfront.net".to_string()],
        expires: "2025".to_string(),
    });
    let chains = ShadowInfrastructureRule.check(&[f1], &[]);
    assert_eq!(chains.len(), 1);
    assert!(chains[0].detail.contains("also-unknown.com"));
    assert!(chains[0].detail.contains("unknown.com"));
    assert!(!chains[0].detail.contains("foo.cloudfront.net"));
}

#[test]
fn test_shadow_infra_rule_normalize_wildcard() {
    let mut f1 = create_finding("hidden", "1.2.3.4", "TLS Certificate");
    f1.evidence.push(Evidence::Certificate {
        subject: "*.unknown.com".to_string(),
        issuer: "Let's Encrypt".to_string(),
        san: vec![],
        expires: "2025".to_string(),
    });
    let chains = ShadowInfrastructureRule.check(&[f1], &[]);
    assert_eq!(chains.len(), 1);
    assert!(chains[0].detail.contains("unknown.com"));
    assert!(!chains[0].detail.contains("*.unknown.com"));
}

#[test]
fn test_source_secrets_rule_multiple_sources() {
    let f1 = create_finding("hidden", "example.com", ".git/config exposed");
    let f2 = create_finding("hidden", "example.com", ".env file exposed");
    let f3 = create_finding("js", "example.com", "AWS Access Key in JavaScript");
    let chains = SourceCodeSecretsRule.check(&[f1, f2, f3], &[]);
    assert_eq!(chains.len(), 1);
    assert!(chains[0].detail.contains(".git/config exposed"));
    assert!(chains[0].detail.contains(".env file exposed"));
}

#[test]
fn test_source_secrets_rule_multiple_secrets() {
    let f1 = create_finding("hidden", "example.com", ".git/config exposed");
    let f2 = create_finding("js", "example.com", "AWS Access Key in JavaScript");
    let f3 = create_finding("js", "example.com", "Stripe API Key in JavaScript");
    let chains = SourceCodeSecretsRule.check(&[f1, f2, f3], &[]);
    assert_eq!(chains.len(), 1);
    assert!(chains[0].detail.contains("AWS Access Key in JavaScript"));
    assert!(chains[0].detail.contains("Stripe API Key in JavaScript"));
}

#[test]
fn test_ssrf_internal_rule_multiple_internal_services() {
    let f1 = create_finding("hidden", "example.com", "Server-side request forgery");
    let f2 = create_finding("hidden", "example.com", "Redis exposed without authentication");
    let f3 = create_finding("hidden", "example.com", "Elasticsearch exposed without authentication");
    let chains = SsrfInternalRule.check(&[f1, f2, f3], &[]);
    assert_eq!(chains.len(), 1);
    assert!(chains[0].detail.contains("Redis exposed without authentication"));
    assert!(chains[0].detail.contains("Elasticsearch exposed without authentication"));
}

#[test]
fn test_engine_run_with_thousands_of_findings() {
    let engine = CorrelationEngine::new();
    let mut findings = Vec::new();
    for i in 0..5000 {
        findings.push(create_finding("hidden", &format!("host{}.com", i), "Admin dashboard exposed"));
        findings.push(create_finding("techstack", &format!("host{}.com", i), "Missing authentication"));
    }
    let chains = engine.run(&findings, &[]);
    assert_eq!(chains.len(), 5000);
}

#[test]
fn test_engine_run_with_empty_targets() {
    let engine = CorrelationEngine::new();
    let findings = vec![
        create_finding("hidden", "admin.example.com", "Admin dashboard exposed"),
        create_finding("techstack", "admin.example.com", "Missing authentication"),
    ];
    let chains = engine.run(&findings, &[]);
    assert_eq!(chains.len(), 1);
}

#[test]
fn test_admin_exposed_missing_auth_with_ip_target() {
    let f1 = create_finding("hidden", "1.2.3.4", "Admin dashboard exposed");
    let f2 = create_finding("techstack", "1.2.3.4", "Missing authentication");
    let chains = AdminExposedRule.check(&[f1, f2], &[]);
    assert_eq!(chains.len(), 1);
}

#[test]
fn test_tls_weakness_rule_with_ip_target() {
    let f1 = create_finding("hidden", "1.2.3.4", "Missing HSTS header");
    let f2 = create_finding("portscan", "1.2.3.4", "Self-signed TLS certificate");
    let chains = TlsWeaknessRule.check(&[f1, f2], &[]);
    assert_eq!(chains.len(), 1);
}

#[test]
fn test_api_auth_rule_with_ip_target() {
    let mut f1 = create_finding("hidden", "1.2.3.4", "API version enumeration");
    f1.tags.push("api-version".to_string());
    let f2 = create_finding("hidden", "1.2.3.4", "No authentication required");
    let chains = ApiAuthRule.check(&[f1, f2], &[]);
    assert_eq!(chains.len(), 1);
}

