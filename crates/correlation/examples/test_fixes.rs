//! Standalone test to verify our fixes work

use gossan_correlation::{CorrelationEngine, TlsWeaknessRule, AdminExposedRule, CorrelationRule};
use secfinding::{Finding, Severity};

fn create_finding(scanner: &str, target: &str, title: &str) -> Finding {
    Finding::builder(scanner, target, Severity::High)
        .title(title)
        .build()
        .expect("finding builder")
}

fn main() {
    println!("Testing correlation fixes...");
    
    // Test 1: TLS weakness rule with port normalization
    println!("\n1. Testing TLS weakness rule with ports:");
    let findings = vec![
        create_finding("portscan", "example.com:443", "Self-signed TLS certificate"),
        create_finding("hidden", "example.com:8443", "Missing HSTS header"),
    ];
    let chains = TlsWeaknessRule.check(&findings, &[]);
    println!("   Chains found: {} (expected: 1)", chains.len());
    if chains.len() == 1 {
        println!("   ✓ Port normalization working");
    }
    
    // Test 2: Admin exposed rule with scheme normalization  
    println!("\n2. Testing Admin exposed rule with schemes:");
    let findings = vec![
        create_finding("hidden", "https://admin.example.com", "Admin panel exposed"),
        create_finding("hidden", "http://admin.example.com", "No authentication required"),
    ];
    let chains = AdminExposedRule.check(&findings, &[]);
    println!("   Chains found: {} (expected: 1)", chains.len());
    if chains.len() == 1 {
        println!("   ✓ Scheme normalization working");
        // Check evidence
        let evidence_str = format!("{:?}", chains[0].evidence());
        let finding_1_in_evidence = evidence_str.contains(&findings[0].id().to_string());
        let finding_2_in_evidence = evidence_str.contains(&findings[1].id().to_string());
        println!("   Evidence contains finding 1: {} (expected: true)", finding_1_in_evidence);
        println!("   Evidence contains finding 2: {} (expected: true)", finding_2_in_evidence);
        if finding_1_in_evidence && finding_2_in_evidence {
            println!("   ✓ Evidence tracking working");
        }
    }
    
    // Test 3: Null bytes handling
    println!("\n3. Testing null bytes handling:");
    let findings = vec![
        create_finding("portscan", "example.com\x00malicious", "Self-signed TLS certificate"),
        create_finding("portscan", "example.com\x00malicious", "Missing HSTS header"),
    ];
    let chains = TlsWeaknessRule.check(&findings, &[]);
    println!("   Chains found: {} (expected: 1)", chains.len());
    if chains.len() == 1 {
        println!("   ✓ Null bytes handling working");
        println!("   Target contains null: {}", chains[0].target().contains("\x00"));
    }
    
    // Test 4: 0xFF bytes handling
    println!("\n4. Testing 0xFF bytes handling:");
    let target = String::from_utf8_lossy(&[0xFF, 0xFF, 0xFF, 0xFF]).into_owned();
    let findings = vec![
        create_finding("hidden", &target, "Admin panel exposed"),
        create_finding("hidden", &target, "No authentication required"),
    ];
    let engine = CorrelationEngine::new();
    let chains = engine.run(&findings, &[]);
    println!("   Chains found: {} (expected: 1)", chains.len());
    if chains.len() == 1 {
        println!("   ✓ 0xFF bytes handling working");
    }
    
    println!("\nTest complete!");
}