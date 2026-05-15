use gossan_scm::ScmScanner;
use gossan_core::{Scanner, Target, target::{DomainTarget, RepositoryTarget, ScmService, DiscoverySource}};
use url::Url;

#[tokio::test]
async fn test_scm_scanner_metadata() {
    let scanner = ScmScanner;
    assert_eq!(scanner.name(), "scm");
    assert_eq!(scanner.tags(), &["osint", "secret", "supply-chain"]);
}

#[tokio::test]
async fn test_scm_scanner_accepts() {
    let scanner = ScmScanner;
    
    let domain = Target::Domain(DomainTarget {
        domain: "example.com".to_string(),
        source: DiscoverySource::Seed,
    });
    assert!(scanner.accepts(&domain));

    let repo = Target::Repository(RepositoryTarget {
        url: Url::parse("https://github.com/example/repo").unwrap(),
        service: ScmService::GitHub,
        source: DiscoverySource::ScmMapping,
        branch: None,
    });
    assert!(scanner.accepts(&repo));

    let net = Target::Network(gossan_core::target::NetworkTarget {
        cidr: "1.2.3.0/24".to_string(),
        source: DiscoverySource::Seed,
    });
    assert!(!scanner.accepts(&net));
}
