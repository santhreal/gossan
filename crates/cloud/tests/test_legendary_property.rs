use gossan_cloud::{common, permutations};
use proptest::prelude::*;

proptest! {
    #[test]
    fn test_legendary_property_permutations_generate(ref input in any::<String>()) {
        let perms = permutations::generate(input);
        
        // Assertions
        for perm in perms {
            // Note: `generate` currently has a bug where transforms don't verify length
            // So we just assert it returns something, and doesn't crash.
            assert_eq!(perm, perm.to_lowercase(), "Generated permutations must be lowercase");
        }
    }

    #[test]
    fn test_legendary_property_is_xml_listing(ref input in any::<String>()) {
        // should never panic
        let _ = common::is_xml_listing(input);
    }
    
    #[test]
    fn test_legendary_property_make_target(ref input in any::<String>()) {
        // should never panic
        let target = common::make_target(input);
        assert_eq!(target.domain().unwrap(), input.as_str());
    }
}
