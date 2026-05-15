//! Public-facing banner classifier.
//!
//! [`BannerClassifier`] is the thin facade callers reach for. Internally
//! it just owns a [`CpuMatcher`] over the [`builtin_rules`] set, so the
//! classify crate can grow a GPU backend later without rewriting the
//! callers (gossan-portscan, gossan-cli, gossan-correlation, etc.).

use crate::matcher::CpuMatcher;
use crate::rules::{builtin_rules, ServiceMatch, ServiceRule};

/// Top-level classifier — drop a banner in, get a ranked list of
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

    /// Classify a single banner. Returns matches sorted by priority
    /// (highest first); empty vec when nothing fires.
    #[must_use]
    pub fn classify(&self, banner: &str) -> Vec<ServiceMatch> {
        self.matcher.match_banner(banner)
    }

    /// Classify a batch of banners. Mirrors `CpuMatcher::match_batch`.
    /// The returned outer vec has one entry per input banner; inner
    /// vecs follow `classify`'s ordering.
    #[must_use]
    pub fn classify_batch(&self, banners: &[&str]) -> Vec<Vec<ServiceMatch>> {
        self.matcher.match_batch(banners)
    }

    /// First match for a banner, if any. Useful when callers only
    /// want the top service identification and don't care about
    /// alternative rule hits.
    #[must_use]
    pub fn classify_top(&self, banner: &str) -> Option<ServiceMatch> {
        self.matcher.match_banner(banner).into_iter().next()
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
        // Rules vec deliberately empty — classifier must accept it
        // and return empty matches for every banner.
        let c = BannerClassifier::with_rules(vec![]);
        assert!(c.classify("Server: nginx/1.25.3").is_empty());
        assert!(c.classify_top("anything").is_none());
    }
}
