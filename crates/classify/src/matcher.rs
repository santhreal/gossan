//! Pattern matcher for banner classification.
//!
//! CPU-based implementation using substring search + regex version extraction.
//! This is the fallback when Vyre GPU acceleration is not available.

use crate::rules::{ServiceMatch, ServiceRule};
use std::collections::HashMap;

/// CPU-based banner pattern matcher.
pub struct CpuMatcher {
    rules: Vec<ServiceRule>,
    /// Compiled regexes for version extraction (lazily compiled).
    version_regexes: HashMap<String, Option<regex_lite::Regex>>,
}

impl CpuMatcher {
    /// Create a new matcher with the given rules.
    #[must_use]
    pub fn new(rules: Vec<ServiceRule>) -> Self {
        let mut version_regexes = HashMap::new();
        for rule in &rules {
            if let Some(pattern) = &rule.version_pattern {
                let re = regex_lite::Regex::new(pattern).ok();
                version_regexes.insert(rule.id.clone(), re);
            }
        }
        Self {
            rules,
            version_regexes,
        }
    }

    /// Match a banner against all rules.
    ///
    /// Returns all matching rules sorted by priority (highest first).
    pub fn match_banner(&self, banner: &str) -> Vec<ServiceMatch> {
        let mut matches = Vec::new();
        let banner_lower = banner.to_lowercase();

        for rule in &self.rules {
            let matched = rule.patterns.iter().any(|p| {
                let p_lower = p.to_lowercase();
                banner_lower.contains(&p_lower)
            });

            if !matched {
                continue;
            }

            // Extract version if we have a regex
            let version = self
                .version_regexes
                .get(&rule.id)
                .and_then(|re| re.as_ref())
                .and_then(|re| {
                    re.captures(banner)
                        .and_then(|caps| caps.get(1))
                        .map(|m| m.as_str().to_string())
                });

            // Compute confidence based on specificity
            let pattern_matches: usize = rule
                .patterns
                .iter()
                .filter(|p| banner_lower.contains(&p.to_lowercase()))
                .count();
            let confidence = (pattern_matches as f32 / rule.patterns.len() as f32).min(1.0)
                * if version.is_some() { 1.0 } else { 0.8 };

            // Detect security signals
            let signals = detect_security_signals(banner, &rule.security_signals);

            matches.push(ServiceMatch {
                rule_id: rule.id.clone(),
                service: rule.service.clone(),
                version,
                confidence,
                signals,
                metadata: HashMap::new(),
            });
        }

        matches.sort_by(|a, b| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        matches
    }

    /// Batch-match multiple banners. Returns one result set per banner.
    pub fn match_batch(&self, banners: &[&str]) -> Vec<Vec<ServiceMatch>> {
        banners.iter().map(|b| self.match_banner(b)).collect()
    }
}

/// Detect security-relevant signals in a banner.
fn detect_security_signals(banner: &str, rule_signals: &[String]) -> Vec<String> {
    let mut signals = Vec::new();
    let bl = banner.to_lowercase();

    // Always check for generic security signals
    if bl.contains("debug") || bl.contains("stack trace") {
        signals.push("debug-mode-enabled".into());
    }
    if bl.contains("default password") || bl.contains("admin:admin") {
        signals.push("default-credentials".into());
    }
    if bl.contains("directory listing") || bl.contains("index of /") {
        signals.push("directory-listing".into());
    }
    if bl.contains("x-powered-by") {
        signals.push("technology-disclosure".into());
    }

    // Add rule-specific signals
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
        let signals = detect_security_signals("Stack Trace: at foo.bar()", &[]);
        assert!(signals.contains(&"debug-mode-enabled".to_string()));
    }

    #[test]
    fn detects_directory_listing() {
        let signals = detect_security_signals("<title>Index of /</title>", &[]);
        assert!(signals.contains(&"directory-listing".to_string()));
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
        assert!(!results[0].is_empty()); // SSH
        assert!(!results[1].is_empty()); // nginx
        assert!(results[2].is_empty()); // unknown
    }

    #[test]
    fn confidence_higher_with_version() {
        let m = matcher();
        let with_version = m.match_banner("Server: Apache/2.4.52");
        let without_detail = m.match_banner("Server: Apache");

        if !with_version.is_empty() && !without_detail.is_empty() {
            // Both should match, but versioned banner should have higher confidence
            assert!(
                with_version[0].confidence >= without_detail[0].confidence,
                "version match should have >= confidence"
            );
        }
    }
}
