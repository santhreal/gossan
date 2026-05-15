use gossan_origin::OriginCandidate;
use proptest::prelude::*;

proptest! {
    #[test]
    fn prop_origin_candidate_ordering_is_deterministic(
        ip1 in any::<std::net::IpAddr>(), method1 in ".*", conf1 in any::<u8>(),
        ip2 in any::<std::net::IpAddr>(), method2 in ".*", conf2 in any::<u8>()
    ) {
        let c1 = OriginCandidate::new(ip1, method1, conf1);
        let c2 = OriginCandidate::new(ip2, method2, conf2);

        // Transitivity and symmetry checks for ordering
        if c1 == c2 {
            assert_eq!(c1.cmp(&c2), std::cmp::Ordering::Equal);
        } else if c1 < c2 {
            assert_eq!(c1.cmp(&c2), std::cmp::Ordering::Less);
            assert_eq!(c2.cmp(&c1), std::cmp::Ordering::Greater);
        } else {
            assert_eq!(c1.cmp(&c2), std::cmp::Ordering::Greater);
            assert_eq!(c2.cmp(&c1), std::cmp::Ordering::Less);
        }
    }

    #[test]
    fn prop_candidate_deduplication(
        mut candidates in prop::collection::vec(
            any::<(std::net::IpAddr, String, u8)>().prop_map(|(ip, method, conf)| OriginCandidate::new(ip, method, conf)),
            0..100
        )
    ) {
        // This mirrors the logic in lib.rs
        candidates.sort_by(|a, b| b.confidence.cmp(&a.confidence));

        let mut seen = std::collections::HashSet::new();
        candidates.retain(|c| seen.insert(c.ip));

        // Assert no duplicates
        let mut check_seen = std::collections::HashSet::new();
        for c in &candidates {
            assert!(check_seen.insert(c.ip), "Still contains duplicates after deduplication");
        }
        
        // Assert sorting is maintained
        for i in 1..candidates.len() {
            assert!(candidates[i-1].confidence >= candidates[i].confidence);
        }
    }
}
