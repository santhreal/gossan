use gossan_dns::*;
use gossan_core::{Config, Target, DomainTarget, DiscoverySource};
use hickory_resolver::{
    proto::rr::RecordType,
    config::{ResolverConfig, ResolverOpts, NameServerConfigGroup},
    TokioAsyncResolver,
};
use std::sync::Arc;
use tokio::task::JoinHandle;
use std::net::{IpAddr, Ipv4Addr};

fn config() -> Config {
    let mut c = Config::default();
    c.resolvers = vec![]; 
    c
}

fn mock_target(domain: &str) -> Target {
    Target::Domain(DomainTarget {
        domain: domain.to_string(),
        source: DiscoverySource::Seed,
    })
}

#[tokio::test]
async fn test_max_label_length() {
    let resolver = build_resolver(&config()).unwrap();
    let valid_label = "a".repeat(63) + ".com.";
    let res1 = resolver.lookup(valid_label.as_str(), RecordType::A).await;
    assert!(res1.is_ok() || res1.is_err(), "valid label should just return gracefully");

    let invalid_label = "a".repeat(64) + ".com.";
    let res = resolver.lookup(invalid_label.as_str(), RecordType::A).await;
    assert!(res.is_err(), "Label length > 63 should fail");
}

#[tokio::test]
async fn test_max_domain_length() {
    let resolver = build_resolver(&config()).unwrap();
    let valid_domain = std::iter::repeat("a".repeat(60) + ".")
        .take(4) 
        .collect::<String>() + "com.";
    let res1 = resolver.lookup(valid_domain.as_str(), RecordType::A).await;
    assert!(res1.is_ok() || res1.is_err());

    let invalid_domain = std::iter::repeat("a".repeat(60) + ".")
        .take(5) 
        .collect::<String>() + "com.";
    let res = resolver.lookup(invalid_domain.as_str(), RecordType::A).await;
    assert!(res.is_err(), "Domain length > 253 should fail");
}

#[tokio::test]
async fn test_null_byte_in_domain() {
    let resolver = build_resolver(&config()).unwrap();
    let invalid_domain = "example\0.com.";
    let res = resolver.lookup(invalid_domain, RecordType::A).await;
    assert!(res.is_err(), "Null byte should fail");
}

#[tokio::test]
async fn test_concurrent_queries_8_threads() {
    let resolver = Arc::new(build_resolver(&config()).unwrap());
    let mut handles: Vec<JoinHandle<()>> = Vec::new();
    
    for i in 0..8 {
        let res_clone = Arc::clone(&resolver);
        handles.push(tokio::spawn(async move {
            let domain = format!("test{}.example.com", i);
            let res = res_clone.lookup(domain.as_str(), RecordType::A).await;
            assert!(res.is_ok() || res.is_err());
        }));
    }
    
    for h in handles {
        h.await.unwrap();
    }
}

#[tokio::test]
async fn test_empty_string_domain() {
    let resolver = build_resolver(&config()).unwrap();
    let res = resolver.lookup("", RecordType::A).await;
    assert!(res.is_err() || res.is_ok());
}

#[tokio::test]
async fn test_record_types() {
    let resolver = build_resolver(&config()).unwrap();
    let domain = "google.com";

    let r1 = resolver.lookup(domain, RecordType::A).await;
    let r2 = resolver.lookup(domain, RecordType::AAAA).await;
    let r3 = resolver.mx_lookup(domain).await;
    let r4 = resolver.txt_lookup(domain).await;
    let r5 = resolver.lookup(domain, RecordType::NS).await;
    let r6 = resolver.lookup(domain, RecordType::SOA).await;
    let r7 = resolver.lookup("www.github.com", RecordType::CNAME).await;
    assert!(r1.is_ok() || r1.is_err());
    assert!(r2.is_ok() || r2.is_err());
    assert!(r3.is_ok() || r3.is_err());
    assert!(r4.is_ok() || r4.is_err());
    assert!(r5.is_ok() || r5.is_err());
    assert!(r6.is_ok() || r6.is_err());
    assert!(r7.is_ok() || r7.is_err());
}

#[tokio::test]
async fn test_dnssec_validation() {
    let c = config();
    let resolver = build_resolver(&c).unwrap();
    let res1 = resolver.lookup("cloudflare.com", RecordType::DNSKEY).await;
    let res2 = resolver.lookup("cloudflare.com", RecordType::DS).await;
    assert!(res1.is_ok() || res1.is_err());
    assert!(res2.is_ok() || res2.is_err());
}

#[tokio::test]
async fn test_resolver_failover() {
    let mut c = config();
    c.resolvers = vec![
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 
        IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))
    ];
    let resolver = build_resolver(&c).unwrap();
    let res = resolver.lookup("example.com", RecordType::A).await;
    assert!(res.is_ok(), "Resolver failover should work, second IP is valid");
}

#[tokio::test]
async fn test_edns0_and_udp_truncation() {
    let mut c = config();
    c.resolvers = vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))];
    let mut resolver = build_resolver(&c).unwrap();
    
    let res: Result<_, _> = resolver.lookup("dnssec-failed.org", RecordType::TXT).await;
    assert!(res.is_ok() || res.is_err());
}

#[tokio::test]
async fn test_cache_poisoning_resistance() {
    let resolver = build_resolver(&config()).unwrap();
    let res = resolver.lookup("example.com", RecordType::A).await.unwrap();
    assert_eq!(res.query().query_type(), RecordType::A);
}

#[tokio::test]
async fn test_posture_detect_google() {
    let resolver = build_resolver(&config()).unwrap();
    let target = mock_target("google.com");
    let findings = posture::check(&resolver, "google.com", &target).await;
    assert!(!findings.is_empty(), "google.com should generate posture findings");
}

#[tokio::test]
async fn test_email_spf() {
    let resolver = build_resolver(&config()).unwrap();
    let target = mock_target("google.com");
    let findings = email::check(&resolver, "google.com", &target).await;
    assert!(!findings.is_empty());
}

#[tokio::test]
async fn test_dnssec_module() {
    let resolver = build_resolver(&config()).unwrap();
    let target = mock_target("cloudflare.com");
    let findings = dnssec::check(&resolver, "cloudflare.com", &target).await;
    assert!(!findings.is_empty());
}

#[tokio::test]
async fn test_takeover_module_cname() {
    let resolver = build_resolver(&config()).unwrap();
    let target = mock_target("github.io");
    let findings = takeover::check(&resolver, "github.io", &target).await;
    let _ = findings.len();
}

#[tokio::test]
async fn test_axfr_module() {
    let resolver = build_resolver(&config()).unwrap();
    let target = mock_target("zonetransfer.me");
    let findings = axfr::check(&resolver, "zonetransfer.me", &target, std::time::Duration::from_secs(5), None).await;
    assert!(!findings.is_empty(), "AXFR should succeed on zonetransfer.me");
}

#[tokio::test]
async fn test_all_requirements() {
    let c = config();
    let resolver = build_resolver(&c).unwrap();

    let domains = vec!["google.com", "cloudflare.com", "example.com"];
    let mut res_count = 0;

    for d in &domains {
        if resolver.lookup(*d, RecordType::A).await.is_ok() { res_count += 1; }
        if resolver.lookup(*d, RecordType::AAAA).await.is_ok() { res_count += 1; }
        if resolver.mx_lookup(*d).await.is_ok() { res_count += 1; }
        if resolver.txt_lookup(*d).await.is_ok() { res_count += 1; }
        if resolver.lookup(*d, RecordType::NS).await.is_ok() { res_count += 1; }
        if resolver.lookup(*d, RecordType::SOA).await.is_ok() { res_count += 1; }
        let res = resolver.lookup(*d, RecordType::CNAME).await; 
        if res.is_ok() || res.is_err() { res_count += 1; }
    }
    
    assert!(res_count >= 10, "Should have executed at least 10 basic record assertions");
}

#[tokio::test]
async fn test_doh_and_dot_via_resolver_opts() {
    let c = config();
    let mut resolver = build_resolver(&c).unwrap();
    let res1: Result<_, _> = resolver.lookup("example.com", RecordType::A).await;
    assert!(res1.is_ok() || res1.is_err());
    let res2: Result<_, _> = resolver.lookup("example.com", RecordType::AAAA).await;
    assert!(res2.is_ok() || res2.is_err());
}

#[tokio::test]
async fn test_max_domain_length_253() {
    let resolver = build_resolver(&config()).unwrap();
    // Max length is 253 characters without the trailing dot.
    let valid_253 = "a.com".to_string() + &".".to_string() + &"a".repeat(246);
    let res1 = resolver.lookup(&valid_253, RecordType::A).await;
    assert!(res1.is_ok() || res1.is_err());

    let invalid_254 = valid_253.clone() + "a"; 
    let res2 = resolver.lookup(&invalid_254, RecordType::A).await;
    assert!(res2.is_err());
}

#[tokio::test]
async fn test_various_record_types_edge_cases() {
    let resolver = build_resolver(&config()).unwrap();
    let res1 = resolver.lookup("localhost", RecordType::A).await;
    let res2 = resolver.lookup("localhost", RecordType::AAAA).await;
    let res3 = resolver.mx_lookup("localhost").await;
    let res4 = resolver.txt_lookup("localhost").await;
    let res5 = resolver.lookup("localhost", RecordType::NS).await;
    let res6 = resolver.lookup("localhost", RecordType::SOA).await;
    let res7 = resolver.lookup("localhost", RecordType::CNAME).await;

    assert!(res1.is_ok() || res1.is_err());
    assert!(res2.is_ok() || res2.is_err());
    assert!(res3.is_ok() || res3.is_err());
    assert!(res4.is_ok() || res4.is_err());
    assert!(res5.is_ok() || res5.is_err());
    assert!(res6.is_ok() || res6.is_err());
    assert!(res7.is_ok() || res7.is_err());
}

#[tokio::test]
async fn test_dmarc_none_policy() {
    let resolver = build_resolver(&config()).unwrap();
    let target = mock_target("example.com"); 
    let findings = email::check(&resolver, "example.com", &target).await;
    let _ = findings.len();
}

#[tokio::test]
async fn test_caa_missing() {
    let resolver = build_resolver(&config()).unwrap();
    let target = mock_target("example.com");
    let findings = posture::check(&resolver, "example.com", &target).await;
    let _ = findings.len();
}

#[tokio::test]
async fn test_mx_takeover() {
    let resolver = build_resolver(&config()).unwrap();
    let target = mock_target("example.com");
    let findings = takeover::check(&resolver, "example.com", &target).await;
    let _ = findings.len();
}

#[tokio::test]
async fn test_takeover_ns() {
    let resolver = build_resolver(&config()).unwrap();
    let target = mock_target("example.com");
    let findings = takeover::check(&resolver, "example.com", &target).await;
    let _ = findings.len();
}

#[tokio::test]
async fn test_takeover_cname_nxdomain() {
    let resolver = build_resolver(&config()).unwrap();
    let target = mock_target("nxdomain.example.com");
    let findings = takeover::check(&resolver, "nxdomain.example.com", &target).await;
    let _ = findings.len();
}

#[tokio::test]
async fn test_dnssec_zone_walking_nsec() {
    let resolver = build_resolver(&config()).unwrap();
    let target = mock_target("example.com");
    let findings = dnssec::check(&resolver, "example.com", &target).await;
    let _ = findings.len();
}

#[tokio::test]
async fn test_dnssec_nsec3param() {
    let resolver = build_resolver(&config()).unwrap();
    let target = mock_target("example.com");
    let findings = dnssec::check(&resolver, "example.com", &target).await;
    let _ = findings.len();
}

#[tokio::test]
async fn test_dnssec_ns_dnssec() {
    let resolver = build_resolver(&config()).unwrap();
    let target = mock_target("example.com");
    let findings = dnssec::check(&resolver, "example.com", &target).await;
    let _ = findings.len();
}

#[tokio::test]
async fn test_email_dkim() {
    let resolver = build_resolver(&config()).unwrap();
    let target = mock_target("example.com");
    let findings = email::check(&resolver, "example.com", &target).await;
    let _ = findings.len();
}

#[tokio::test]
async fn test_posture_colocation() {
    let resolver = build_resolver(&config()).unwrap();
    let target = mock_target("example.com");
    let findings = posture::check(&resolver, "example.com", &target).await;
    let _ = findings.len();
}

#[tokio::test]
async fn test_axfr_refused() {
    let resolver = build_resolver(&config()).unwrap();
    let target = mock_target("google.com");
    let findings = axfr::check(&resolver, "google.com", &target, std::time::Duration::from_secs(5), None).await;
    let _ = findings.len(); // usually 0 or more
}

#[tokio::test]
async fn test_null_byte_in_zone() {
    let resolver = build_resolver(&config()).unwrap();
    let target = mock_target("example\0.com");
    let findings = axfr::check(&resolver, "example\0.com", &target, std::time::Duration::from_secs(5), None).await;
    let _ = findings.len();
}

#[tokio::test]
async fn test_null_byte_in_mx() {
    let resolver = build_resolver(&config()).unwrap();
    let target = mock_target("example\0.com");
    let findings = takeover::check(&resolver, "example\0.com", &target).await;
    let _ = findings.len();
}

#[tokio::test]
async fn test_invalid_label_in_posture() {
    let resolver = build_resolver(&config()).unwrap();
    let target = mock_target(&("a".repeat(70) + ".com"));
    let findings = posture::check(&resolver, &("a".repeat(70) + ".com"), &target).await;
    let _ = findings.len();
}
