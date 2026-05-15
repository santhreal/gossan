use gossan_scm::ScmScanner;
use gossan_core::{Scanner, Target, target::{DomainTarget, DiscoverySource}};

#[tokio::test]
async fn test_adversarial_domain_inputs() {
    let scanner = ScmScanner;
    
    // 1. Empty string
    let empty = Target::Domain(DomainTarget {
        domain: "".to_string(),
        source: DiscoverySource::Seed,
    });
    assert!(scanner.accepts(&empty));

    // 2. Huge string (1MB+)
    let huge = Target::Domain(DomainTarget {
        domain: "A".repeat(1024 * 1024),
        source: DiscoverySource::Seed,
    });
    assert!(scanner.accepts(&huge));

    // 3. Null bytes
    let nulls = Target::Domain(DomainTarget {
        domain: "domain\x00with\x00nulls".to_string(),
        source: DiscoverySource::Seed,
    });
    assert!(scanner.accepts(&nulls));

    // 4. Unicode / homoglyphs
    let unicode = Target::Domain(DomainTarget {
        domain: "éxàmplé.com".to_string(),
        source: DiscoverySource::Seed,
    });
    assert!(scanner.accepts(&unicode));

    // 5. Path traversal / malicious
    let traversal = Target::Domain(DomainTarget {
        domain: "../../../etc/passwd".to_string(),
        source: DiscoverySource::Seed,
    });
    assert!(scanner.accepts(&traversal));
}
