//! W9 gossan-classify proptest
use gossan_classify::BannerClassifier;
use proptest::prelude::*;

proptest! {
    #[test]
    fn prop_never_panics(input in ".*") {
        let c = BannerClassifier::new();
        let _ = c.classify(&input);
        let _ = c.classify_top(&input);
    }

    #[test]
    fn prop_confidence_bounded(input in ".*") {
        let c = BannerClassifier::new();
        for m in c.classify(&input) {
            prop_assert!(m.confidence >= 0.0 && m.confidence <= 1.0);
            prop_assert!(!m.service.is_empty());
        }
    }

    #[test]
    fn prop_top_matches_nonempty(input in ".*") {
        let c = BannerClassifier::new();
        let top = c.classify_top(&input);
        let any = !c.classify(&input).is_empty();
        prop_assert_eq!(top.is_some(), any);
    }

    #[test]
    fn prop_long_banner(len in 0usize..8192) {
        let banner: String = std::iter::repeat('Z').take(len).collect();
        let c = BannerClassifier::new();
        let _ = c.classify(&banner);
    }

    #[test]
    fn prop_empty_no_top(_ in 0u8..3) {
        let c = BannerClassifier::new();
        prop_assert!(c.classify_top("").is_none());
    }

    #[test]
    fn prop_service_names_nonempty(input in "[A-Za-z0-9 -]{0,200}") {
        let c = BannerClassifier::new();
        for m in c.classify(&input) {
            prop_assert!(!m.service.is_empty());
        }
    }

    #[test]
    fn prop_deterministic(input in ".*") {
        let a = BannerClassifier::new().classify(&input);
        let b = BannerClassifier::new().classify(&input);
        prop_assert_eq!(a.len(), b.len());
    }

    #[test]
    fn prop_classify_len_bounded(input in ".*") {
        let c = BannerClassifier::new();
        prop_assert!(c.classify(&input).len() < 256);
    }

    #[test]
    fn prop_top_confidence_bounded(input in ".*") {
        let c = BannerClassifier::new();
        if let Some(t) = c.classify_top(&input) {
            prop_assert!(t.confidence >= 0.0 && t.confidence <= 1.0);
        }
    }

    #[test]
    fn prop_new_classifier_empty(_ in 0u8..5) {
        let c = BannerClassifier::new();
        prop_assert!(c.classify("").is_empty());
    }

    #[test]
    fn prop_ssh_banner_no_panic(s in "SSH-[0-9.]+") {
        let c = BannerClassifier::new();
        let _ = c.classify(&s);
    }

    #[test]
    fn prop_http_banner_no_panic(s in "HTTP/[0-9.]+ [0-9]{3}") {
        let _ = BannerClassifier::new().classify(&s);
    }

    #[test]
    fn prop_finite_confidence(input in ".*") {
        for m in BannerClassifier::new().classify(&input) {
            prop_assert!(m.confidence.is_finite());
        }
    }

    #[test]
    fn prop_classify_idempotent(input in ".*") {
        let c = BannerClassifier::new();
        let a = c.classify(&input);
        let b = c.classify(&input);
        prop_assert_eq!(a.len(), b.len());
    }

    #[test]
    fn prop_ascii_banner(input in "[\\x20-\\x7E]{0,500}") {
        let _ = BannerClassifier::new().classify(&input);
    }
}
