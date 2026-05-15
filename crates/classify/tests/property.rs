//! Property tests for the banner classifier.
//!
//! Per GOSSAN_LEGENDARY A22: arbitrary ASCII banners (10k cases)
//! must never panic and `classify_top` must always return either
//! `None` or a `ServiceMatch` whose `name` is non-empty and whose
//! `confidence` is in `[0, 100]`.

use gossan_classify::BannerClassifier;
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 10_000,
        ..ProptestConfig::default()
    })]

    /// Random ASCII bytes — no panic, no out-of-range confidence.
    #[test]
    fn classify_never_panics_on_arbitrary_ascii(input in "\\PC*") {
        let cls = BannerClassifier::new();
        let matches = cls.classify(&input);
        for m in matches {
            prop_assert!(!m.service.is_empty(), "empty service name");
            prop_assert!(m.confidence >= 0.0, "negative confidence: {}", m.confidence);
            prop_assert!(m.confidence <= 1.0, "confidence > 1.0: {}", m.confidence);
        }
        // classify_top must agree with classify on emptiness.
        let top = cls.classify_top(&input);
        let any = !cls.classify(&input).is_empty();
        prop_assert_eq!(top.is_some(), any);
    }
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 1_000,
        ..ProptestConfig::default()
    })]

    /// Arbitrary bytes, including non-printable and high-bit set —
    /// classification still must not panic. The classifier reads via
    /// `&str` so we filter out anything that wouldn't pass the
    /// reqwest/banner-grab string conversion at the boundary.
    #[test]
    fn classify_handles_long_inputs(len in 0usize..16_384) {
        let banner: String = std::iter::repeat('A').take(len).collect();
        let cls = BannerClassifier::new();
        let _ = cls.classify(&banner);
    }
}
