use gossan_core::{
    target::{DiscoverySource, DomainTarget},
    Scanner, Target,
};
use gossan_scm::ScmScanner;
use proptest::prelude::*;

proptest! {
    #[test]
    fn test_accepts_invariant_domain(domain_str in any::<String>()) {
        let scanner = ScmScanner;
        let domain = Target::Domain(DomainTarget {
            domain: domain_str,
            source: DiscoverySource::Seed,
        });

        // accepts must return a boolean without panicking for any generated String.
        let result = scanner.accepts(&domain);

        // In this particular implementation, domain should always return true.
        assert!(result);
    }
}
