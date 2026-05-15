// `GraphStore::target_id(&Target)` is now a free function `target_id`
// re-exported at crate root (the per-backend graph store split made
// the associated method redundant since the ID is backend-agnostic).
use gossan_graph::target_id;
use gossan_core::{Target, DomainTarget, DiscoverySource, HostTarget};

#[test]
fn test_target_id_domain() {
    let t = Target::Domain(DomainTarget {
        domain: "example.com".into(),
        source: DiscoverySource::Seed,
    });
    assert_eq!(target_id(&t), "domain:example.com");
}

#[test]
fn test_target_id_host() {
    let t = Target::Host(HostTarget {
        ip: "1.2.3.4".parse().unwrap(),
        domain: None,
    });
    assert_eq!(target_id(&t), "host:1.2.3.4");
}
