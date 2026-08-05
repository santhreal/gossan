//! Public-facing banner classifier.
//!
//! [`BannerClassifier`] is the thin facade callers reach for. Internally
//! it just owns a [`CpuMatcher`] over the [`builtin_rules`] set, so the
//! classify crate can grow a GPU backend later without rewriting the
//! callers (gossan-portscan, gossan-cli, gossan-correlation, etc.).
//!
//! Prefer the `*_bytes` methods when the banner may contain non-UTF-8
//! protocol bytes (RDP, Modbus, MySQL greeting). The `&str` methods are
//! thin wrappers over the bytes path.

use crate::matcher::CpuMatcher;
use crate::rules::{builtin_rules, ServiceMatch, ServiceRule};

/// Top-level classifier, drop a banner in, get a ranked list of
/// service matches out.
pub struct BannerClassifier {
    matcher: CpuMatcher,
}

impl BannerClassifier {
    /// Build a classifier seeded with [`builtin_rules`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            matcher: CpuMatcher::new(builtin_rules()),
        }
    }

    /// Build a classifier from a custom rule set. Callers wiring in
    /// community-contributed TOML rule packs should use this.
    #[must_use]
    pub fn with_rules(rules: Vec<ServiceRule>) -> Self {
        Self {
            matcher: CpuMatcher::new(rules),
        }
    }

    /// Classify a raw banner. Canonical entry point for binary protocols.
    #[must_use]
    pub fn classify_bytes(&self, banner: &[u8]) -> Vec<ServiceMatch> {
        self.matcher.match_banner_bytes(banner)
    }

    /// Classify a UTF-8 banner. Wrapper over [`Self::classify_bytes`].
    #[must_use]
    pub fn classify(&self, banner: &str) -> Vec<ServiceMatch> {
        self.classify_bytes(banner.as_bytes())
    }

    /// Classify a batch of raw banners.
    #[must_use]
    pub fn classify_batch_bytes(&self, banners: &[&[u8]]) -> Vec<Vec<ServiceMatch>> {
        self.matcher.match_batch_bytes(banners)
    }

    /// Classify a batch of UTF-8 banners.
    #[must_use]
    pub fn classify_batch(&self, banners: &[&str]) -> Vec<Vec<ServiceMatch>> {
        self.matcher.match_batch(banners)
    }

    /// First match for a raw banner, if any.
    #[must_use]
    pub fn classify_top_bytes(&self, banner: &[u8]) -> Option<ServiceMatch> {
        self.matcher.match_banner_bytes(banner).into_iter().next()
    }

    /// First match for a UTF-8 banner, if any.
    #[must_use]
    pub fn classify_top(&self, banner: &str) -> Option<ServiceMatch> {
        self.classify_top_bytes(banner.as_bytes())
    }
}

impl Default for BannerClassifier {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn classifier_loads_builtin_rules_without_panic() {
        let c = BannerClassifier::new();
        let _ = c.classify("Server: nginx/1.25.3\r\n");
    }

    #[test]
    fn classify_top_returns_none_for_garbage() {
        let c = BannerClassifier::new();
        assert!(c.classify_top("\x00\x00\x00\x00").is_none());
    }

    #[test]
    fn classify_batch_preserves_ordering() {
        let c = BannerClassifier::new();
        let banners = ["Server: nginx", "SSH-2.0-OpenSSH_8.9", "garbage"];
        let out = c.classify_batch(&banners);
        assert_eq!(out.len(), banners.len(), "one result vec per input banner");
    }

    #[test]
    fn with_rules_uses_caller_rule_set() {
        let c = BannerClassifier::with_rules(vec![]);
        assert!(c.classify("Server: nginx/1.25.3").is_empty());
        assert!(c.classify_top("anything").is_none());
    }

    #[test]
    fn classify_top_bytes_matches_rdp_tpkt() {
        let c = BannerClassifier::new();
        let banner = [
            0x03u8, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xff, 0xfe,
        ];
        let top = c
            .classify_top_bytes(&banner)
            .expect("RDP TPKT must classify via bytes API");
        assert_eq!(top.service, "RDP");
    }

    // --- Property tests ---

    proptest! {
        #[test]
        fn classify_never_panics(banner in ".*") {
            let c = BannerClassifier::new();
            let _ = c.classify(&banner);
        }

        #[test]
        fn classify_bytes_never_panics(banner in prop::collection::vec(any::<u8>(), 0..512)) {
            let c = BannerClassifier::new();
            let _ = c.classify_bytes(&banner);
        }

        #[test]
        fn classify_top_never_panics(banner in ".*") {
            let c = BannerClassifier::new();
            let _ = c.classify_top(&banner);
        }

        #[test]
        fn classify_batch_preserves_length(banners in proptest::collection::vec(".*", 0..=20)) {
            let c = BannerClassifier::new();
            let banners_refs: Vec<&str> = banners.iter().map(|s| s.as_str()).collect();
            let out = c.classify_batch(&banners_refs);
            prop_assert_eq!(out.len(), banners.len());
        }

        #[test]
        fn empty_rules_never_panic(banner in prop::collection::vec(any::<u8>(), 0..128)) {
            let c = BannerClassifier::with_rules(vec![]);
            let _ = c.classify_bytes(&banner);
            let _ = c.classify_top_bytes(&banner);
        }

        #[test]
        fn confidence_is_finite(banner in prop::collection::vec(any::<u8>(), 0..256)) {
            let c = BannerClassifier::new();
            for m in c.classify_bytes(&banner) {
                prop_assert!(m.confidence.is_finite(), "confidence must not be NaN or Inf: got {}", m.confidence);
                prop_assert!(m.confidence >= 0.0 && m.confidence <= 1.0, "confidence out of range: {}", m.confidence);
            }
        }
    }
}
