//! Pattern matcher for banner classification.
//!
//! CPU-based implementation using raw-byte substring search + regex
//! version extraction. Matching is `&[u8]`-first so binary protocols
//! (RDP, Modbus, MySQL greeting) are not corrupted by UTF-8 lossy conversion.

use crate::rules::{ServiceMatch, ServiceRule};
use std::collections::HashMap;

/// Confidence multiplier applied when a rule matches but no version string
/// was captured.  A version-captured match is worth the full 1.0 weight;
/// a keyword-only match is penalised to reflect lower specificity.
const CONFIDENCE_NO_VERSION_FACTOR: f32 = 0.8;

/// A rule with its patterns pre-lowercased (ASCII) as raw bytes so
/// `match_banner_bytes` pays zero allocation cost per pattern per call.
struct CompiledRule {
    rule: ServiceRule,
    /// ASCII-lowercased copies of `rule.patterns` as bytes.
    patterns_lower: Vec<Vec<u8>>,
}

/// CPU-based banner pattern matcher.
pub struct CpuMatcher {
    compiled: Vec<CompiledRule>,
    /// Compiled regexes for version extraction, keyed by rule id.
    version_regexes: HashMap<String, Option<regex_lite::Regex>>,
}

impl CpuMatcher {
    /// Create a new matcher with the given rules.
    ///
    /// Patterns are ASCII-lowercased at construction time so matching
    /// never reallocates per-pattern during the hot loop.
    #[must_use]
    pub fn new(rules: Vec<ServiceRule>) -> Self {
        let mut version_regexes = HashMap::with_capacity(rules.len());
        let mut compiled = Vec::with_capacity(rules.len());

        for rule in rules {
            if let Some(pattern) = &rule.version_pattern {
                // Compile version patterns case-insensitive so they match the
                // same lowercased text view used for pattern matching.
                match regex_lite::Regex::new(&format!("(?i){pattern}")) {
                    Ok(re) => {
                        version_regexes.insert(rule.id.clone(), Some(re));
                    }
                    Err(e) => {
                        tracing::warn!(
                            rule_id = %rule.id,
                            pattern = %pattern,
                            error = %e,
                            "classify: invalid version_pattern regex; version extraction disabled for rule"
                        );
                        version_regexes.insert(rule.id.clone(), None);
                    }
                }
            }
            let patterns_lower = rule
                .patterns
                .iter()
                .map(|p| ascii_lower_bytes(p.as_bytes()))
                .collect();
            compiled.push(CompiledRule {
                rule,
                patterns_lower,
            });
        }

        Self {
            compiled,
            version_regexes,
        }
    }

    /// Match a raw banner against all rules.
    ///
    /// This is the canonical matching entry point. Binary protocol banners
    /// (RDP TPKT, Modbus MBAP, MySQL handshake) must be passed as `&[u8]`
    /// without a UTF-8 lossy round-trip.
    ///
    /// Returns all matching rules sorted by confidence (highest first).
    pub fn match_banner_bytes(&self, banner: &[u8]) -> Vec<ServiceMatch> {
        let mut matches = Vec::new();
        let banner_lower = ascii_lower_bytes(banner);
        // Version regexes run on a lossy UTF-8 view. Binary-only rules do not
        // ship version_pattern, so lossy replacement cannot hide their hits.
        let banner_text = String::from_utf8_lossy(banner);

        for cr in &self.compiled {
            let matched = cr
                .patterns_lower
                .iter()
                .any(|p| !p.is_empty() && contains_bytes(&banner_lower, p));

            if !matched {
                continue;
            }

            let version = self
                .version_regexes
                .get(&cr.rule.id)
                .and_then(|re| re.as_ref())
                .and_then(|re| {
                    re.captures(banner_text.as_ref())
                        .and_then(|caps| caps.get(1))
                        .map(|m| m.as_str().to_string())
                });

            let pattern_matches: usize = cr
                .patterns_lower
                .iter()
                .filter(|p| !p.is_empty() && contains_bytes(&banner_lower, p))
                .count();
            let confidence = if cr.rule.patterns.is_empty() {
                0.0
            } else {
                (pattern_matches as f32 / cr.rule.patterns.len() as f32).min(1.0)
                    * if version.is_some() {
                        1.0
                    } else {
                        CONFIDENCE_NO_VERSION_FACTOR
                    }
            };

            let signals = detect_security_signals(&banner_lower, &cr.rule.security_signals);

            matches.push(ServiceMatch {
                rule_id: cr.rule.id.clone(),
                service: cr.rule.service.clone(),
                version,
                confidence,
                signals,
                metadata: HashMap::new(),
                priority: cr.rule.priority,
            });
        }

        matches.sort_by(|a, b| {
            b.confidence
                .total_cmp(&a.confidence)
                .then_with(|| b.priority.cmp(&a.priority))
        });
        matches
    }

    /// Match a UTF-8 banner against all rules.
    ///
    /// Convenience wrapper over [`Self::match_banner_bytes`]. Prefer the
    /// bytes API when the banner may contain non-UTF-8 protocol bytes.
    pub fn match_banner(&self, banner: &str) -> Vec<ServiceMatch> {
        self.match_banner_bytes(banner.as_bytes())
    }

    /// Batch-match multiple raw banners. Returns one result set per banner.
    pub fn match_batch_bytes(&self, banners: &[&[u8]]) -> Vec<Vec<ServiceMatch>> {
        banners
            .iter()
            .map(|b| self.match_banner_bytes(b))
            .collect()
    }

    /// Batch-match multiple UTF-8 banners. Returns one result set per banner.
    pub fn match_batch(&self, banners: &[&str]) -> Vec<Vec<ServiceMatch>> {
        banners.iter().map(|b| self.match_banner(b)).collect()
    }
}

/// ASCII-only lowercase copy. Binary high bytes and NULs are preserved
/// unchanged so protocol signatures survive case folding.
fn ascii_lower_bytes(src: &[u8]) -> Vec<u8> {
    src.iter().map(|b| b.to_ascii_lowercase()).collect()
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// Detect security-relevant signals in a banner.
/// `banner_lower` must already be ASCII-lowercased bytes.
fn detect_security_signals(banner_lower: &[u8], rule_signals: &[String]) -> Vec<String> {
    let mut signals = Vec::new();

    if contains_bytes(banner_lower, b"debug") || contains_bytes(banner_lower, b"stack trace") {
        signals.push("debug-mode-enabled".into());
    }
    if contains_bytes(banner_lower, b"default password")
        || contains_bytes(banner_lower, b"admin:admin")
    {
        signals.push("default-credentials".into());
    }
    if contains_bytes(banner_lower, b"directory listing")
        || contains_bytes(banner_lower, b"index of /")
    {
        signals.push("directory-listing".into());
    }
    if contains_bytes(banner_lower, b"x-powered-by") {
        signals.push("technology-disclosure".into());
    }

    for signal in rule_signals {
        if !signals.contains(signal) {
            signals.push(signal.clone());
        }
    }

    signals
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::builtin_rules;
    use proptest::prelude::*;

    fn matcher() -> CpuMatcher {
        CpuMatcher::new(builtin_rules())
    }

    #[test]
    fn matches_apache() {
        let m = matcher();
        let results = m.match_banner("HTTP/1.1 200 OK\r\nServer: Apache/2.4.52\r\n\r\n");
        assert!(!results.is_empty());
        assert_eq!(results[0].service, "Apache HTTP Server");
        assert_eq!(results[0].version.as_deref(), Some("2.4.52"));
    }

    #[test]
    fn matches_nginx() {
        let m = matcher();
        let results = m.match_banner("HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n\r\n");
        assert!(!results.is_empty());
        assert_eq!(results[0].service, "nginx");
        assert_eq!(results[0].version.as_deref(), Some("1.24.0"));
    }

    #[test]
    fn matches_openssh() {
        let m = matcher();
        let results = m.match_banner("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6");
        assert!(!results.is_empty());
        assert_eq!(results[0].service, "OpenSSH");
        assert_eq!(results[0].version.as_deref(), Some("8.9p1"));
    }

    #[test]
    fn matches_redis() {
        let m = matcher();
        let results = m.match_banner("+PONG\r\n");
        assert!(!results.is_empty());
        assert_eq!(results[0].service, "Redis");
    }

    #[test]
    fn matches_redis_version() {
        let m = matcher();
        let results = m.match_banner("redis_version:7.2.4\r\n");
        assert!(!results.is_empty());
        assert_eq!(results[0].version.as_deref(), Some("7.2.4"));
    }

    #[test]
    fn matches_elasticsearch() {
        let m = matcher();
        let banner = r#"{"cluster_name":"docker-cluster","tagline":"You Know, for Search","version":{"number":"8.12.0"}}"#;
        let results = m.match_banner(banner);
        assert!(!results.is_empty());
        assert_eq!(results[0].service, "Elasticsearch");
        assert_eq!(results[0].version.as_deref(), Some("8.12.0"));
    }

    #[test]
    fn matches_mysql() {
        let m = matcher();
        let results = m.match_banner("5.7.42-0ubuntu0.18.04.1\x00...mysql_native_password\x00");
        assert!(!results.is_empty());
        assert_eq!(results[0].service, "MySQL");
    }

    #[test]
    fn no_match_for_unknown_banner() {
        let m = matcher();
        let results = m.match_banner("XYZZY UNKNOWN PROTOCOL\r\n");
        assert!(results.is_empty());
    }

    #[test]
    fn detects_debug_mode() {
        let signals = detect_security_signals(b"stack trace: at foo.bar()", &[]);
        assert!(signals.contains(&"debug-mode-enabled".to_string()));
    }

    #[test]
    fn detects_directory_listing() {
        let signals = detect_security_signals(b"<title>index of /</title>", &[]);
        assert!(signals.contains(&"directory-listing".to_string()));
    }

    #[test]
    fn case_insensitive_version_capture() {
        let m = matcher();
        let results = m.match_banner("SERVER: NGINX/1.24.0");
        let nginx = results
            .iter()
            .find(|m| m.service == "nginx")
            .expect("nginx match");
        assert_eq!(nginx.version.as_deref(), Some("1.24.0"));
    }

    #[test]
    fn mysql_caching_sha2_password_matches() {
        let m = matcher();
        let banner = "8.0.33-0ubuntu0.20.04.2\x00...caching_sha2_password\x00";
        let results = m.match_banner(banner);
        let mysql = results
            .iter()
            .find(|m| m.service == "MySQL")
            .expect("MySQL match");
        assert_eq!(mysql.version.as_deref(), Some("8.0.33"));
    }

    #[test]
    fn elasticsearch_compact_json_matches() {
        let m = matcher();
        let banner = r#"{"cluster_name":"docker-cluster","tagline":"You Know, for Search","version":{"number":"8.12.0"}}"#;
        let results = m.match_banner(banner);
        let es = results
            .iter()
            .find(|m| m.service == "Elasticsearch")
            .expect("Elasticsearch match");
        assert_eq!(es.version.as_deref(), Some("8.12.0"));
    }

    #[test]
    fn idrac_full_version_capture() {
        let m = matcher();
        let results = m.match_banner("Server: iDRAC/9.2.0");
        let idrac = results
            .iter()
            .find(|m| m.service == "Dell iDRAC")
            .expect("iDRAC match");
        assert_eq!(idrac.version.as_deref(), Some("9.2.0"));
    }

    #[test]
    fn batch_match_works() {
        let m = matcher();
        let banners = vec![
            "SSH-2.0-OpenSSH_9.0",
            "HTTP/1.1 200 OK\r\nServer: nginx/1.25.0",
            "totally unknown thing",
        ];
        let results = m.match_batch(&banners);
        assert_eq!(results.len(), 3);
        assert!(!results[0].is_empty());
        assert!(!results[1].is_empty());
        assert!(results[2].is_empty());
    }

    #[test]
    fn confidence_higher_with_version() {
        let m = matcher();
        let with_version = m.match_banner("Server: Apache/2.4.52");
        let without_detail = m.match_banner("Server: Apache");

        if !with_version.is_empty() && !without_detail.is_empty() {
            assert!(
                with_version[0].confidence >= without_detail[0].confidence,
                "version match should have >= confidence"
            );
        }
    }

    #[test]
    fn empty_patterns_rule_does_not_produce_nan() {
        let rule = ServiceRule {
            id: "empty-test".into(),
            service: "Empty Service".into(),
            protocol: "tcp".into(),
            common_ports: vec![],
            patterns: vec![],
            version_pattern: None,
            security_signals: vec![],
            priority: 1,
        };
        let m = CpuMatcher::new(vec![rule]);
        let results = m.match_banner("anything");
        assert!(
            results.is_empty(),
            "rule with empty patterns should never match"
        );
    }

    #[test]
    fn empty_patterns_with_version_regex_does_not_panic() {
        let rule = ServiceRule {
            id: "empty-version-test".into(),
            service: "Empty Version Service".into(),
            protocol: "tcp".into(),
            common_ports: vec![],
            patterns: vec![],
            version_pattern: Some(r"(\d+\.\d+)".into()),
            security_signals: vec![],
            priority: 1,
        };
        let m = CpuMatcher::new(vec![rule]);
        let results = m.match_banner("Apache/2.4");
        assert!(
            results.is_empty(),
            "rule with empty patterns should never match even with version regex"
        );
    }

    #[test]
    fn rdp_tpkt_raw_bytes_match() {
        let m = matcher();
        // Real RDP Negotiation Response (TPKT + X.224) with non-UTF8-safe
        // high bytes that from_utf8_lossy would corrupt.
        let banner: Vec<u8> = vec![
            0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08,
            0x00, 0x0b, 0x00, 0x00, 0x00, 0xff, 0xfe, 0xfd,
        ];
        let lossy = String::from_utf8_lossy(&banner);
        assert!(
            lossy.contains('\u{fffd}'),
            "fixture must include bytes that lossy UTF-8 would corrupt"
        );
        let results = m.match_banner_bytes(&banner);
        let rdp = results
            .iter()
            .find(|m| m.service == "RDP")
            .expect("RDP must match raw TPKT bytes");
        assert!(rdp.signals.iter().any(|s| s == "rdp-exposed"));
    }

    #[test]
    fn modbus_mbap_raw_bytes_match() {
        let m = matcher();
        // MBAP: txn=0, proto=0, len=6, unit=1, then FC=0x03 + payload with
        // invalid UTF-8 trailing bytes.
        let banner: Vec<u8> = vec![
            0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x0a, 0xff, 0xfe,
        ];
        let results = m.match_banner_bytes(&banner);
        let modbus = results
            .iter()
            .find(|m| m.service == "Modbus TCP")
            .expect("Modbus must match raw MBAP bytes");
        assert!(modbus.signals.iter().any(|s| s == "modbus-exposed"));
    }

    #[test]
    fn lossy_utf8_roundtrip_misses_rdp_high_bytes() {
        let m = matcher();
        let banner: Vec<u8> = vec![
            0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0xff, 0xfe, 0xfd, 0x00, 0x00, 0x01,
        ];
        assert!(
            m.match_banner_bytes(&banner)
                .iter()
                .any(|r| r.service == "RDP"),
            "bytes API must hit RDP"
        );
        // Demonstrate why the str/lossy path is insufficient for binary:
        // replacing invalid sequences changes the byte stream after the TPKT
        // header when callers only keep the lossy String. Matching on the
        // lossy string still finds \x03\x00 for this particular pattern, so
        // assert the stronger property that invalid bytes survive only via
        // the bytes API (needle with 0xFF must be found in raw, not lossy).
        let lossy = String::from_utf8_lossy(&banner);
        assert!(
            !lossy.as_bytes().windows(3).any(|w| w == [0xff, 0xfe, 0xfd]),
            "lossy UTF-8 must destroy the high-byte signature"
        );
        assert!(contains_bytes(&banner, &[0xff, 0xfe, 0xfd]));
    }

    #[test]
    fn str_api_delegates_to_bytes_for_ascii() {
        let m = matcher();
        let s = "Server: nginx/1.24.0";
        let a = m.match_banner(s);
        let b = m.match_banner_bytes(s.as_bytes());
        assert_eq!(a.len(), b.len());
        assert_eq!(a[0].service, b[0].service);
        assert_eq!(a[0].version, b[0].version);
    }

    proptest! {
        #[test]
        fn match_banner_never_panics(banner in ".*") {
            let m = matcher();
            let _ = m.match_banner(&banner);
        }

        #[test]
        fn match_banner_bytes_never_panics(banner in prop::collection::vec(any::<u8>(), 0..512)) {
            let m = matcher();
            let _ = m.match_banner_bytes(&banner);
        }

        #[test]
        fn match_batch_never_panics(banners in proptest::collection::vec(".*", 0..=20)) {
            let m = matcher();
            let banners_refs: Vec<&str> = banners.iter().map(|s| s.as_str()).collect();
            let _ = m.match_batch(&banners_refs);
        }

        #[test]
        fn results_have_finite_confidence(banner in prop::collection::vec(any::<u8>(), 0..256)) {
            let m = matcher();
            for result in m.match_banner_bytes(&banner) {
                prop_assert!(result.confidence.is_finite(), "confidence must be finite, got {}", result.confidence);
                prop_assert!(result.confidence >= 0.0 && result.confidence <= 1.0, "confidence out of range: {}", result.confidence);
            }
        }

        #[test]
        fn empty_rule_set_never_panics(banner in prop::collection::vec(any::<u8>(), 0..128)) {
            let m = CpuMatcher::new(vec![]);
            let results = m.match_banner_bytes(&banner);
            prop_assert!(results.is_empty());
        }

        #[test]
        fn detect_security_signals_never_panics(banner in prop::collection::vec(any::<u8>(), 0..128)) {
            let signals = detect_security_signals(&banner, &[]);
            prop_assert!(signals.iter().all(|s| !s.is_empty()));
        }
    }
}
