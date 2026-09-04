//! CVE correlation from service banners.
//!
//! Maps version strings found in TCP banners to known CVEs with CVSS scores.
//! Prioritises remotely exploitable, high-CVSS, recently active CVEs.
//!
//! # Community extension
//!
//! The built-in rule set ships compiled into the binary. Users and the community
//! can contribute additional rules by placing `*.toml` files into a `rules/cve/`
//! directory alongside the binary (or at a path given via `--cve-rules-dir`).
//!
//! Each TOML file follows this format:
//!
//! ```toml
//! [[rule]]
//! pattern = "openssh_9.5"
//! cve = "CVE-2024-XXXXX"
//! cvss = 7.5
//! severity = "high"
//! description = "OpenSSH 9.5 (example vulnerability)."
//! exploit = "ssh -o ... TARGET"
//!
//! # Optional semantic version range (example: OpenSSH < 9.3p2)
//! product = "openssh"
//! fixed_version = "9.3p2"
//! ```
pub mod nvd;

use gossan_core::{ServiceTarget, Target};
use secfinding::{Evidence, Finding, Severity};
use serde::Deserialize;
use std::fmt;
use std::sync::LazyLock;

/// Maximum number of characters from a banner included in CVE-finding evidence.
/// Long banners often contain noise; 120 chars covers all common version strings.
const MAX_BANNER_EVIDENCE_CHARS: usize = 120;

/// A CVE detection rule that matches banner substrings.
///
/// Rules can be loaded from built-in defaults or from community TOML files.
/// Each rule specifies a pattern to search for, CVE metadata, and optional
/// exploit hints.
///
/// Rules may optionally declare `product`, `min_version`, `max_version`, and
/// `fixed_version` to enable semantic version-range matching instead of (or
/// in addition to) raw substring matching. When `product` is set, the matcher
/// extracts a version number from the banner after the product name and
/// compares it against the declared range.
///
/// # Example
///
/// ```rust
/// use gossan_portscan::cve::CveRule;
/// use secfinding::Severity;
///
/// let rule = CveRule {
///     pattern: "apache/2.4.49".into(),
///     cve: "CVE-2021-41773".into(),
///     cvss: 9.8,
///     severity: Severity::Critical,
///     description: "Apache 2.4.49 path traversal".into(),
///     exploit: Some("curl http://TARGET/cgi-bin/.%2e/.%2e/bin/sh".into()),
///     product: None,
///     min_version: None,
///     max_version: None,
///     fixed_version: None,
/// };
/// ```
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct CveRule {
    /// Substring that must appear in the banner (case-insensitive).
    pub pattern: String,
    /// CVE identifier (e.g., `CVE-2021-41773`).
    pub cve: String,
    /// CVSS v3 base score (0.0 - 10.0).
    pub cvss: f32,
    /// Finding severity.
    #[serde(deserialize_with = "deserialize_severity")]
    pub severity: Severity,
    /// Human-readable description of the vulnerability.
    pub description: String,
    /// Optional ready-to-run exploit/PoC command. `TARGET` is replaced at runtime.
    #[serde(default)]
    pub exploit: Option<String>,
    /// Optional product name for semantic version extraction.
    #[serde(default)]
    pub product: Option<String>,
    /// Optional minimum vulnerable version (inclusive).
    #[serde(default)]
    pub min_version: Option<String>,
    /// Optional maximum vulnerable version (inclusive).
    #[serde(default)]
    pub max_version: Option<String>,
    /// Optional version that fixes the vulnerability; versions >= this do not match.
    #[serde(default)]
    pub fixed_version: Option<String>,
}

impl fmt::Display for CveRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CveRule({} - {} [{}] CVSS: {:.1})",
            self.cve,
            self.pattern,
            format!("{:?}", self.severity).to_lowercase(),
            self.cvss
        )
    }
}

/// TOML file containing one or more CVE rules.
#[derive(Debug, Deserialize)]
struct CveRulesFile {
    rule: Vec<CveRule>,
}

fn deserialize_severity<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Severity, D::Error> {
    let s = String::deserialize(d)?;
    match s.to_ascii_lowercase().as_str() {
        "info" => Ok(Severity::Info),
        "low" => Ok(Severity::Low),
        "medium" => Ok(Severity::Medium),
        "high" => Ok(Severity::High),
        "critical" => Ok(Severity::Critical),
        other => Err(serde::de::Error::custom(format!(
            "unknown severity: {other}"
        ))),
    }
}

/// Built-in CVE rules embedded at compile time from `rules/cve/builtin.toml`.
///
/// Previously this function allocated a fresh `Vec<CveRule>` (with 200+
/// String allocations) on every call.  Each `correlate()` call invoked it
/// once, meaning every open-port banner scan triggered a fresh heap
/// allocation storm.  The lazy static amortises that to a single init.
static BUILTIN_RULES: LazyLock<Vec<CveRule>> = LazyLock::new(|| {
    const TOML: &str = include_str!("../rules/cve/builtin.toml");
    let file: CveRulesFile = toml::from_str(TOML).expect("compiled-in builtin.toml is valid");
    for rule in &file.rule {
        if !semver_constraints_valid(rule) {
            panic!(
                "compiled-in CVE rule {} has invalid semver constraints (min/max/fixed_version)",
                rule.cve
            );
        }
    }
    file.rule
});

/// Built-in CVE rules compiled into the binary.
///
/// Returns a reference to the lazily-initialised, permanently-cached Vec.
fn builtin_rules() -> &'static Vec<CveRule> {
    &BUILTIN_RULES
}

/// Load community CVE rules from a directory of `*.toml` files.
///
/// Each file must contain a `[[rule]]` array. Invalid files are logged and
/// skipped (a single malformed community file must not crash the scan).
///
/// # Arguments
///
/// * `dir` - Path to directory containing `*.toml` rule files
///
/// # Returns
///
/// Returns a vector of successfully parsed `CveRule`s. Missing directories
/// result in an empty vector rather than an error.
///
/// # Example
///
/// ```rust,no_run
/// use gossan_portscan::cve::load_community_rules;
/// use std::path::Path;
///
/// let rules = load_community_rules(Path::new("./rules/cve"));
/// println!("Loaded {} community CVE rules", rules.len());
/// ```
pub fn load_community_rules(dir: &std::path::Path) -> Vec<CveRule> {
    let mut rules = Vec::new();
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return rules, // directory missing is fine
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }
        // Skip the compiled-in rule file so it is not double-loaded as community rules.
        if path
            .file_stem()
            .and_then(|s| s.to_str())
            .map(|s| s == "builtin")
            .unwrap_or(false)
        {
            continue;
        }
        match std::fs::read_to_string(&path) {
            Ok(content) => match toml::from_str::<CveRulesFile>(&content) {
                Ok(file) => {
                    let mut valid_count = 0;
                    let mut skipped_count = 0;
                    for rule in file.rule {
                        if semver_constraints_valid(&rule) {
                            rules.push(rule);
                            valid_count += 1;
                        } else {
                            skipped_count += 1;
                            tracing::warn!(
                                path = %path.display(),
                                cve = %rule.cve,
                                "skipping CVE rule with invalid semver constraints"
                            );
                        }
                    }
                    tracing::info!(
                        path = %path.display(),
                        valid = valid_count,
                        skipped = skipped_count,
                        "loaded community CVE rules"
                    );
                }
                Err(e) => {
                    tracing::warn!(path = %path.display(), err = %e, "skipping malformed CVE rules file")
                }
            },
            Err(e) => {
                tracing::warn!(path = %path.display(), err = %e, "failed to read CVE rules file")
            }
        }
    }
    rules
}

/// Load all CVE rules: built-in defaults + any community TOML files.
///
/// Combines the built-in rule set with any community rules found in the
/// specified directory. Community rules are loaded after built-ins, so
/// they can supplement or override (if patterns match) the defaults.
///
/// # Arguments
///
/// * `community_dir` - Optional path to directory containing `*.toml` rule files
///
/// # Returns
///
/// Returns a vector containing all available CVE rules.
///
/// # Example
///
/// ```rust,no_run
/// use gossan_portscan::cve::all_rules;
/// use std::path::Path;
///
/// // Load only built-in rules
/// let builtin_only = all_rules(None);
///
/// // Load built-in + community rules
/// let with_community = all_rules(Some(Path::new("./rules/cve")));
/// ```
pub fn all_rules(community_dir: Option<&std::path::Path>) -> Vec<CveRule> {
    let mut rules: Vec<CveRule> = builtin_rules().clone();
    if let Some(dir) = community_dir {
        rules.extend(load_community_rules(dir));
    }
    rules
}

/// Correlate a banner against the given rule set.
///
/// Searches the banner (case-insensitively) for each rule's pattern.
/// Matching rules generate `Finding`s with appropriate severity,
/// evidence, and exploit hints.
///
/// # Arguments
///
/// * `banner` - The service banner to analyze
/// * `svc` - The service target (used for context and exploit hint generation)
/// * `rules` - Slice of `CveRule`s to match against
///
/// # Returns
///
/// Returns a vector of `Finding`s for all matched rules. Empty if no rules match.
///
/// # Example
///
/// ```rust
/// use gossan_portscan::cve::{correlate_with_rules, CveRule};
/// use gossan_core::{ServiceTarget, HostTarget, Protocol};
/// use secfinding::Severity;
/// use std::net::IpAddr;
///
/// let svc = ServiceTarget {
///     host: HostTarget {
///         ip: IpAddr::from([127, 0, 0, 1]),
///         domain: Some("example.com".into()),
///     },
///     port: 80,
///     protocol: Protocol::Tcp,
///     banner: None,
///     tls: false,
/// };
///
/// let custom_rules = vec![CveRule {
///     pattern: "myapp/1.0".into(),
///     cve: "CVE-2024-1234".into(),
///     cvss: 7.5,
///     severity: Severity::High,
///     description: "Test vulnerability".into(),
///     exploit: Some("curl http://TARGET/exploit".into()),
///     product: None,
///     min_version: None,
///     max_version: None,
///     fixed_version: None,
/// }];
///
/// let findings = correlate_with_rules("Server: MyApp/1.0", &svc, &custom_rules);
/// assert!(!findings.is_empty());
/// ```

pub fn correlate_with_rules(banner: &str, svc: &ServiceTarget, rules: &[CveRule]) -> Vec<Finding> {
    let lower = banner.to_lowercase();
    let mut findings = Vec::new();

    for rule in rules {
        let is_match = if rule.product.is_some() {
            matches_semantic_version(banner, rule)
        } else {
            matches_pattern(banner, &lower, rule)
        };

        if is_match {

            let target = Target::Service(svc.clone());
            let mut f = crate::finding_builder(
                &target,
                rule.severity,
                format!(
                    "{}: {} (CVSS {:.1})",
                    rule.cve,
                    rule.description.split(": ").next().unwrap_or("").trim(),
                    rule.cvss
                ),
                &rule.description,
            )
            .cve(rule.cve.as_str())
            .confidence((rule.cvss / 10.0) as f64)
            .evidence(Evidence::Banner {
                raw: banner
                    .chars()
                    .take(MAX_BANNER_EVIDENCE_CHARS)
                    .collect::<String>()
                    .into(),
            })
            .tag("cve")
            .tag("version-disclosure");
            if let Some(hint) = &rule.exploit {
                let target_str = format!("{}:{}", svc.host.ip, svc.port);
                f = f.exploit_hint(hint.replace("TARGET", &target_str));
            }
            gossan_core::try_push_finding(f, &mut findings);
        }
    }

    findings
}


/// Pattern-based matching for rules without semantic version information.
fn matches_pattern(banner: &str, lower: &str, rule: &CveRule) -> bool {
    let pattern_lower = rule.pattern.to_lowercase();
    let mut start_idx = 0;

    while let Some(offset) = lower[start_idx..].find(&pattern_lower) {
        let actual_idx = start_idx + offset;
        let end_idx = actual_idx + pattern_lower.len();

        // Check character immediately following the match (if any)
        let next_char = lower.as_bytes().get(end_idx).copied();

        if pattern_lower == "openssl/1.0.1" {
            // Heartbleed affects OpenSSL 1.0.1 through 1.0.1f.
            // 1.0.1g is the first fixed version.
            if let Some(c) = next_char {
                if c.is_ascii_alphanumeric() {
                    let is_vuln_letter = c >= b'a' && c <= b'f';
                    let next_next_char = lower.as_bytes().get(end_idx + 1).copied();
                    let next_next_is_alphanumeric = next_next_char
                        .map(|nc| nc.is_ascii_alphanumeric())
                        .unwrap_or(false);
                    if is_vuln_letter && !next_next_is_alphanumeric {
                        return true;
                    }
                } else {
                    return true;
                }
            } else {
                return true;
            }
        } else if pattern_lower.starts_with("openssh_") {
            // OpenSSH portable versions have a 'pX' suffix (e.g. openssh_8.0p1).
            // We should allow 'p' followed by digits.
            let mut suffix_len = 0;
            if next_char == Some(b'p') {
                suffix_len += 1;
                while let Some(c) = lower.as_bytes().get(end_idx + suffix_len).copied() {
                    if c.is_ascii_digit() {
                        suffix_len += 1;
                    } else {
                        break;
                    }
                }
            }
            let post_suffix_char = lower.as_bytes().get(end_idx + suffix_len).copied();
            let post_suffix_is_alphanumeric = post_suffix_char
                .map(|c| c.is_ascii_alphanumeric())
                .unwrap_or(false);
            if !post_suffix_is_alphanumeric {
                return true;
            }
        } else {
            // Standard precise matching: the character following the pattern must not be alphanumeric or extend the version
            let mut suffix_len = 0;
            if pattern_lower.ends_with('.') {
                while let Some(c) = lower.as_bytes().get(end_idx + suffix_len).copied() {
                    if c.is_ascii_digit() {
                        suffix_len += 1;
                    } else {
                        break;
                    }
                }
            }
            let post_suffix_char = lower.as_bytes().get(end_idx + suffix_len).copied();
            let post_suffix_is_alphanumeric = post_suffix_char
                .map(|c| c.is_ascii_alphanumeric())
                .unwrap_or(false);
            if !post_suffix_is_alphanumeric {
                return true;
            }
        }
        start_idx = actual_idx + 1;
    }

    false
}

/// Semantic version matching for rules that declare a product and optional range.
fn matches_semantic_version(banner: &str, rule: &CveRule) -> bool {
    let product = match rule.product.as_deref() {
        Some(p) => p,
        None => return false,
    };

    let lower = banner.to_lowercase();
    let product_lower = product.to_lowercase();
    let mut start = 0;

    while let Some(pos) = lower[start..].find(&product_lower) {
        let idx = start + pos;
        let after_product = &lower[idx + product_lower.len()..];
        let after_sep = after_product
            .trim_start_matches(|c: char| c == '_' || c == '/' || c == ' ' || c == '-');
        let sep_skipped = after_product.len() - after_sep.len();

        if let Some(first_digit) = after_sep.find(|c: char| c.is_ascii_digit()) {
            let version_start = idx + product_lower.len() + sep_skipped + first_digit;
            let version_end = lower[version_start..]
                .find(|c: char| !c.is_ascii_digit() && c != '.' && c != 'p')
                .map(|i| version_start + i)
                .unwrap_or(lower.len());
            let version = &lower[version_start..version_end];

            if let Some(parsed) = parse_semver(version) {
                if version_rule_matches(&parsed, rule) {
                    return true;
                }
            }
        }

        start = idx + 1;
    }

    false
}

/// Check whether a parsed version satisfies the rule's declared range.
/// Invalid min/max/fixed_version constraints are treated as no-match
/// (fail closed) rather than silently unconstrained.
fn version_rule_matches(version: &[u32], rule: &CveRule) -> bool {
    // Product rules without any range constraint would match every version.
    // Fail closed: require at least one of min/max/fixed_version.
    if rule.min_version.is_none() && rule.max_version.is_none() && rule.fixed_version.is_none() {
        return false;
    }
    if let Some(min_str) = rule.min_version.as_deref() {
        let Some(min) = parse_semver(min_str) else {
            return false;
        };
        if cmp_semver(version, &min) == std::cmp::Ordering::Less {
            return false;
        }
    }
    if let Some(max_str) = rule.max_version.as_deref() {
        let Some(max) = parse_semver(max_str) else {
            return false;
        };
        if cmp_semver(version, &max) == std::cmp::Ordering::Greater {
            return false;
        }
    }
    if let Some(fixed_str) = rule.fixed_version.as_deref() {
        let Some(fixed) = parse_semver(fixed_str) else {
            return false;
        };
        if cmp_semver(version, &fixed) != std::cmp::Ordering::Less {
            return false;
        }
    }
    true
}

/// Return true if every declared semver constraint on the rule parses.
fn semver_constraints_valid(rule: &CveRule) -> bool {
    rule.min_version
        .as_deref()
        .map_or(true, |s| parse_semver(s).is_some())
        && rule
            .max_version
            .as_deref()
            .map_or(true, |s| parse_semver(s).is_some())
        && rule
            .fixed_version
            .as_deref()
            .map_or(true, |s| parse_semver(s).is_some())
}

/// Parse a dotted version string with an optional 'p' portable suffix.
///
/// Examples:
/// - `"8.5"` -> `[8, 5]`
/// - `"9.3p2"` -> `[9, 3, 2]`
/// - `"1.0.1f"` -> `[1, 0, 1]`
fn parse_semver(s: &str) -> Option<Vec<u32>> {
    let mut parts = Vec::new();
    let mut chars = s.chars().peekable();

    while chars.peek().copied().map(|c| c.is_ascii_digit()).unwrap_or(false) {
        let mut num = 0u32;
        while let Some(c) = chars.peek().copied() {
            if c.is_ascii_digit() {
                num = num * 10 + c.to_digit(10).unwrap();
                chars.next();
            } else {
                break;
            }
        }
        parts.push(num);

        match chars.peek().copied() {
            Some('.') => {
                chars.next();
            }
            Some('p') => {
                chars.next();
            }
            _ => break,
        }
    }

    if parts.is_empty() {
        None
    } else {
        Some(parts)
    }
}

/// Compare two semantic version vectors, treating missing components as zero.
fn cmp_semver(a: &[u32], b: &[u32]) -> std::cmp::Ordering {
    let len = std::cmp::max(a.len(), b.len());
    for i in 0..len {
        let av = a.get(i).copied().unwrap_or(0);
        let bv = b.get(i).copied().unwrap_or(0);
        match av.cmp(&bv) {
            std::cmp::Ordering::Equal => continue,
            other => return other,
        }
    }
    std::cmp::Ordering::Equal
}


/// Correlate a banner using all built-in rules (no community extensions).
///
/// Convenience wrapper for callers that don't use community rules.
/// For community rule support, use [`correlate_with_rules`] with [`all_rules`].
///
/// # Arguments
///
/// * `banner` - The service banner to analyze
/// * `svc` - The service target for context
///
/// # Returns
///
/// Returns a vector of `Finding`s for matched CVE rules.
///
/// # Example
///
/// ```rust
/// use gossan_portscan::cve::correlate;
/// use gossan_core::{ServiceTarget, HostTarget, Protocol};
/// use std::net::IpAddr;
///
/// let svc = ServiceTarget {
///     host: HostTarget {
///         ip: IpAddr::from([127, 0, 0, 1]),
///         domain: None,
///     },
///     port: 22,
///     protocol: Protocol::Tcp,
///     banner: None,
///     tls: false,
/// };
///
/// // Check for OpenSSH CVEs
/// let findings = correlate("SSH-2.0-OpenSSH_8.0", &svc);
/// ```
pub fn correlate(banner: &str, svc: &ServiceTarget) -> Vec<Finding> {
    correlate_with_rules(banner, svc, &builtin_rules())
}

#[cfg(test)]
mod tests {
    use super::*;
    use gossan_core::{HostTarget, Protocol};
    use std::net::IpAddr;

    fn service(port: u16) -> ServiceTarget {
        ServiceTarget {
            host: HostTarget {
                ip: IpAddr::from([127, 0, 0, 1]),
                domain: Some("example.com".into()),
            },
            port,
            protocol: Protocol::Tcp,
            banner: None,
            tls: port == 443,
        }
    }

    #[test]
    fn correlate_matches_apache_critical_rule() {
        let findings = correlate("Server: Apache/2.4.49", &service(80));
        assert!(findings
            .iter()
            .any(|f| f.title().contains("CVE-2021-41773")));
    }

    #[test]
    fn correlate_matches_redis_banner_and_injects_target_host() {
        let findings = correlate("+PONG", &service(6379));
        let finding = findings
            .iter()
            .find(|f| f.title().contains("CVE-2022-0543"))
            .unwrap();
        assert_eq!(finding.severity(), Severity::Critical);
        assert!(finding
            .exploit_hint()
            .as_deref()
            .unwrap()
            .contains("127.0.0.1:6379"));
    }

    #[test]
    fn correlate_is_case_insensitive() {
        let findings = correlate("SSH-2.0-OPENSSH_8.0", &service(22));
        assert!(findings
            .iter()
            .any(|f| f.title().contains("CVE-2023-38408")));
    }

    #[test]
    fn correlate_returns_empty_for_unknown_banner() {
        assert!(correlate("totally-unknown-service", &service(9999)).is_empty());
    }

    #[test]
    fn correlate_truncates_banner_evidence() {
        let banner = "A".repeat(200) + " apache/2.4.49";
        let findings = correlate(&banner, &service(80));
        let finding = findings.first().unwrap();
        let Evidence::Banner { raw } = &finding.evidence()[0] else {
            panic!("expected banner evidence");
        };
        assert!(raw.len() <= MAX_BANNER_EVIDENCE_CHARS);
    }

    #[test]
    fn builtin_rules_are_nonempty() {
        assert!(
            builtin_rules().len() > 20,
            "should have 20+ built-in CVE rules"
        );
    }

    /// Anti-rig: `builtin_rules()` must return the same cached Vec on
    /// every call (OnceLock guarantee).  This prevents the allocation
    /// storm from before where each call allocated 200+ Strings.
    #[test]
    fn builtin_rules_are_cached_same_pointer() {
        let r1 = builtin_rules() as *const Vec<CveRule>;
        let r2 = builtin_rules() as *const Vec<CveRule>;
        assert_eq!(
            r1, r2,
            "builtin_rules() must return the same static pointer (OnceLock cached)"
        );
    }

    /// The count of built-in rules must be stable between calls (idempotent cache).
    #[test]
    fn builtin_rules_count_is_stable() {
        let n1 = builtin_rules().len();
        let n2 = builtin_rules().len();
        assert_eq!(n1, n2, "rule count must be stable between calls");
    }

    #[test]
    fn community_rules_load_from_toml() {
        let dir = std::env::temp_dir().join("gossan_cve_test");
        let _ = std::fs::create_dir_all(&dir);
        std::fs::write(
            dir.join("test.toml"),
            r#"
[[rule]]
pattern = "custom-service/1.0"
cve = "CVE-9999-0001"
cvss = 8.0
severity = "high"
description = "Custom service (test vulnerability)."
"#,
        )
        .unwrap();
        let rules = load_community_rules(&dir);
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].cve, "CVE-9999-0001");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn community_rules_merged_with_builtins() {
        let dir = std::env::temp_dir().join("gossan_cve_merge_test");
        let _ = std::fs::create_dir_all(&dir);
        std::fs::write(
            dir.join("custom.toml"),
            r#"
[[rule]]
pattern = "frobnicator/3.0"
cve = "CVE-9999-0002"
cvss = 6.5
severity = "medium"
description = "Frobnicator 3.0 (test)."
"#,
        )
        .unwrap();
        let all = all_rules(Some(&dir));
        assert!(all.len() > builtin_rules().len());
        assert!(all.iter().any(|r| r.cve == "CVE-9999-0002"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn malformed_community_file_is_skipped() {
        let dir = std::env::temp_dir().join("gossan_cve_bad_test");
        let _ = std::fs::create_dir_all(&dir);
        std::fs::write(dir.join("broken.toml"), "this is not valid [[rule]]").unwrap();
        let rules = load_community_rules(&dir);
        assert!(
            rules.is_empty(),
            "malformed file should be skipped gracefully"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn shipped_community_rules_file_parses() {
        // Sanity check: the community rules TOML file shipped in the repo
        // (`rules/cve/community-2025.toml`) loads without errors and
        // contributes meaningful rule count beyond the builtins.
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let repo_root = std::path::Path::new(manifest_dir)
            .parent()
            .and_then(std::path::Path::parent)
            .expect("portscan crate is two levels under the repo root");
        let rules_dir = repo_root.join("rules").join("cve");
        if !rules_dir.exists() {
            // The repo layout may differ in vendored builds.
            return;
        }
        let community = load_community_rules(&rules_dir);
        assert!(
            community.len() >= 70,
            "expected ≥70 community rules from rules/cve/, got {}",
            community.len()
        );
        assert!(community.iter().any(|r| r.cve == "CVE-2021-44228"));
        assert!(community.iter().any(|r| r.cve == "CVE-2024-23897"));
        // CVE-2024-6387 range lives in builtin.toml (compiled-in), not community.
        assert!(
            builtin_rules().iter().any(|r| r.cve == "CVE-2024-6387"),
            "regreSSHion range must ship in builtin rules"
        );
        // Built-in + community combined should land at ≥100.
        let total = all_rules(Some(&rules_dir)).len();
        // Semantic-range collapse reduces exact-pattern enumeration count;
        // keep a floor that still proves community TOML is loading.
        assert!(
            total >= 90,
            "expected ≥90 total CVE rules (built-in + community), got {total}"
        );
    }

    #[test]
    fn correlate_with_custom_rules() {
        let custom = vec![CveRule {
            pattern: "myapp/2.0".into(),
            cve: "CVE-9999-0003".into(),
            cvss: 9.0,
            severity: Severity::Critical,
            description: "MyApp 2.0, test.".into(),
            exploit: Some("curl http://TARGET/exploit".into()),
            product: None,
            min_version: None,
            max_version: None,
            fixed_version: None,
        }];
        let findings = correlate_with_rules("Server: MyApp/2.0", &service(8080), &custom);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title().contains("CVE-9999-0003"));
        assert!(findings[0]
            .exploit_hint()
            .as_deref()
            .unwrap()
            .contains("127.0.0.1:8080"));
    }

    #[test]
    fn correlate_empty_banner_returns_empty() {
        let custom = vec![CveRule {
            pattern: "test".into(),
            cve: "CVE-9999-0004".into(),
            cvss: 5.0,
            severity: Severity::Medium,
            description: "Test".into(),
            exploit: None,
            product: None,
            min_version: None,
            max_version: None,
            fixed_version: None,
        }];
        let findings = correlate_with_rules("", &service(80), &custom);
        assert!(findings.is_empty());
    }

    #[test]
    fn correlate_empty_rules_returns_empty() {
        let findings = correlate_with_rules("Server: Apache/2.4", &service(80), &[]);
        assert!(findings.is_empty());
    }

    #[test]
    fn correlate_unicode_banner_does_not_panic() {
        let custom = vec![CveRule {
            pattern: "apache".into(),
            cve: "CVE-9999-0005".into(),
            cvss: 5.0,
            severity: Severity::Medium,
            description: "Test".into(),
            exploit: None,
            product: None,
            min_version: None,
            max_version: None,
            fixed_version: None,
        }];
        let banner = "🚀 Server: Апаче/2.4 🔥";
        let findings = correlate_with_rules(banner, &service(80), &custom);
        // Should not panic; may or may not match depending on lowercasing
        let _ = findings;
    }

    #[test]
    fn correlate_very_long_banner_does_not_panic() {
        let custom = vec![CveRule {
            pattern: "openssh".into(),
            cve: "CVE-9999-0006".into(),
            cvss: 5.0,
            severity: Severity::Medium,
            description: "Test".into(),
            exploit: None,
            product: None,
            min_version: None,
            max_version: None,
            fixed_version: None,
        }];
        let banner = "A".repeat(100_000);
        let findings = correlate_with_rules(&banner, &service(22), &custom);
        assert!(findings.is_empty());
    }

    #[test]
    fn correlate_openssh_suffix_matching() {
        // openssh_ pattern should allow 'p' suffix but reject alphanumeric continuation
        let rule = vec![CveRule {
            pattern: "openssh_8.0".into(),
            cve: "CVE-9999-0007".into(),
            cvss: 5.0,
            severity: Severity::Medium,
            description: "Test".into(),
            exploit: None,
            product: None,
            min_version: None,
            max_version: None,
            fixed_version: None,
        }];
        let hit = correlate_with_rules("SSH-2.0-OpenSSH_8.0p1", &service(22), &rule);
        assert!(!hit.is_empty(), "should match OpenSSH_8.0p1");
        let miss = correlate_with_rules("SSH-2.0-OpenSSH_8.0a", &service(22), &rule);
        assert!(miss.is_empty(), "should not match OpenSSH_8.0a");
    }

    #[test]
    fn correlate_openssh_cve_2023_38408_semantic_range() {
        // OpenSSH 8.5 and 7.9 should match CVE-2023-38408 (fixed in 9.3p2).
        let hit_85 = correlate("SSH-2.0-OpenSSH_8.5p1", &service(22));
        assert!(
            hit_85.iter().any(|f| f.title().contains("CVE-2023-38408")),
            "OpenSSH 8.5p1 should match CVE-2023-38408"
        );

        let hit_79 = correlate("SSH-2.0-OpenSSH_7.9", &service(22));
        assert!(
            hit_79.iter().any(|f| f.title().contains("CVE-2023-38408")),
            "OpenSSH 7.9 should match CVE-2023-38408"
        );

        // OpenSSH 9.3p2 is the fixed release and must not match.
        let miss_93p2 = correlate("SSH-2.0-OpenSSH_9.3p2", &service(22));
        assert!(
            !miss_93p2.iter().any(|f| f.title().contains("CVE-2023-38408")),
            "OpenSSH 9.3p2 should not match CVE-2023-38408"
        );
    }

    #[test]
    fn correlate_openssh_cve_2024_6387_semantic_range() {
        // regreSSHion: vulnerable in [8.5, 9.8); previously only 8.5 and 9.7 exact patterns fired.
        let hit_86 = correlate("SSH-2.0-OpenSSH_8.6p1", &service(22));
        assert!(
            hit_86.iter().any(|f| f.title().contains("CVE-2024-6387")),
            "OpenSSH 8.6p1 should match CVE-2024-6387"
        );
        let hit_90 = correlate("SSH-2.0-OpenSSH_9.0", &service(22));
        assert!(
            hit_90.iter().any(|f| f.title().contains("CVE-2024-6387")),
            "OpenSSH 9.0 should match CVE-2024-6387"
        );
        let hit_97 = correlate("SSH-2.0-OpenSSH_9.7p1", &service(22));
        assert!(
            hit_97.iter().any(|f| f.title().contains("CVE-2024-6387")),
            "OpenSSH 9.7p1 should match CVE-2024-6387"
        );
        let miss_98 = correlate("SSH-2.0-OpenSSH_9.8p1", &service(22));
        assert!(
            !miss_98.iter().any(|f| f.title().contains("CVE-2024-6387")),
            "OpenSSH 9.8p1 should not match CVE-2024-6387"
        );
        let miss_84 = correlate("SSH-2.0-OpenSSH_8.4p1", &service(22));
        assert!(
            !miss_84.iter().any(|f| f.title().contains("CVE-2024-6387")),
            "OpenSSH 8.4p1 is below min_version and must not match CVE-2024-6387"
        );
    }

    #[test]
    fn correlate_openssl_cve_2022_3602_semantic_range() {
        let hit = correlate("OpenSSL/3.0.4", &service(443));
        assert!(
            hit.iter().any(|f| f.title().contains("CVE-2022-3602")),
            "OpenSSL 3.0.4 should match SPOOKYSSL"
        );
        let hit_space = correlate("Server uses OpenSSL 3.0.2", &service(443));
        assert!(
            hit_space.iter().any(|f| f.title().contains("CVE-2022-3602")),
            "space-separated OpenSSL 3.0.2 banner should match"
        );
        let miss = correlate("OpenSSL/3.0.7", &service(443));
        assert!(
            !miss.iter().any(|f| f.title().contains("CVE-2022-3602")),
            "OpenSSL 3.0.7 should not match SPOOKYSSL"
        );
        let miss_old = correlate("OpenSSL/1.1.1", &service(443));
        assert!(
            !miss_old.iter().any(|f| f.title().contains("CVE-2022-3602")),
            "OpenSSL 1.1.1 is outside SPOOKYSSL range"
        );
    }

    #[test]
    fn correlate_nginx_cve_2021_23017_semantic_range() {
        let hit_119 = correlate("Server: nginx/1.19.0", &service(80));
        assert!(
            hit_119.iter().any(|f| f.title().contains("CVE-2021-23017")),
            "nginx 1.19.0 should match CVE-2021-23017"
        );
        let hit_116 = correlate("Server: nginx/1.16.1", &service(80));
        assert!(
            hit_116.iter().any(|f| f.title().contains("CVE-2021-23017")),
            "nginx 1.16.1 should match CVE-2021-23017"
        );
        let miss = correlate("Server: nginx/1.20.1", &service(80));
        assert!(
            !miss.iter().any(|f| f.title().contains("CVE-2021-23017")),
            "nginx 1.20.1 should not match CVE-2021-23017"
        );
    }

    #[test]
    fn version_rule_matches_requires_range_constraints() {
        let unconstrained = CveRule {
            pattern: "openssh".into(),
            cve: "CVE-9999-NORANGE".into(),
            cvss: 9.0,
            severity: Severity::Critical,
            description: "product without range must not match all versions".into(),
            exploit: None,
            product: Some("openssh".into()),
            min_version: None,
            max_version: None,
            fixed_version: None,
        };
        assert!(
            !version_rule_matches(&[8, 5, 1], &unconstrained),
            "product rule with no min/max/fixed must fail closed"
        );
    }

    #[test]
    fn parse_semver_handles_portable_suffix() {
        assert_eq!(parse_semver("8.5p1"), Some(vec![8, 5, 1]));
        assert_eq!(parse_semver("9.3p2"), Some(vec![9, 3, 2]));
        assert_eq!(parse_semver("8.5"), Some(vec![8, 5]));
    }

    #[test]
    fn cmp_semver_treats_missing_components_as_zero() {
        assert_eq!(cmp_semver(&[8, 5], &[8, 5, 1]), std::cmp::Ordering::Less);
        assert_eq!(cmp_semver(&[9, 3], &[9, 3, 2]), std::cmp::Ordering::Less);
    }

    #[test]
    fn version_rule_matches_respects_fixed_version() {
        let rule = CveRule {
            pattern: "openssh".into(),
            cve: "CVE-2023-38408".into(),
            cvss: 9.8,
            severity: Severity::Critical,
            description: "OpenSSH < 9.3p2".into(),
            exploit: None,
            product: Some("openssh".into()),
            min_version: None,
            max_version: None,
            fixed_version: Some("9.3p2".into()),
        };
        assert!(version_rule_matches(&[8, 5, 1], &rule));
        assert!(version_rule_matches(&[9, 3, 1], &rule));
        assert!(!version_rule_matches(&[9, 3, 2], &rule));
        assert!(!version_rule_matches(&[9, 4], &rule));
    }

    #[test]
    fn version_rule_matches_invalid_constraints_fail_closed() {
        // Any declared min/max/fixed_version that does not parse as a semver
        // vector must be treated as no-match, not silently unconstrained.
        let base_rule = || CveRule {
            pattern: "openssh".into(),
            cve: "CVE-9999-SEMCLO".into(),
            cvss: 9.0,
            severity: Severity::Critical,
            description: "test".into(),
            exploit: None,
            product: Some("openssh".into()),
            min_version: None,
            max_version: None,
            fixed_version: None,
        };

        let mut with_bad_min = base_rule();
        with_bad_min.min_version = Some("not-a-version".into());
        assert!(!version_rule_matches(&[8, 5, 1],
            &with_bad_min),
            "unparseable min_version must be no-match");

        let mut with_bad_max = base_rule();
        with_bad_max.max_version = Some("".into());
        assert!(!version_rule_matches(&[8, 5, 1],
            &with_bad_max),
            "unparseable max_version must be no-match");

        let mut with_bad_fixed = base_rule();
        with_bad_fixed.fixed_version = Some("1.2.3.4.5.6.7.8".into());
        assert!(!version_rule_matches(&[8, 5, 1],
            &with_bad_fixed),
            "unparseable fixed_version must be no-match");
    }

    #[test]
    fn community_rules_with_invalid_semver_constraints_are_skipped() {
        let dir = std::env::temp_dir().join("gossan_cve_semver_skip_test");
        let _ = std::fs::create_dir_all(&dir);
        std::fs::write(
            dir.join("invalid_semver.toml"),
            r#"
[[rule]]
pattern = "badapp/1.0"
cve = "CVE-9999-BAD1"
cvss = 8.0
severity = "high"
description = "Bad semver rule."
product = "badapp"
fixed_version = "not-a-version"

[[rule]]
pattern = "goodapp/1.0"
cve = "CVE-9999-GOOD1"
cvss = 8.0
severity = "high"
description = "Good semver rule."
product = "goodapp"
fixed_version = "2.0.0"
"#,
        )
        .unwrap();
        let rules = load_community_rules(&dir);
        assert_eq!(rules.len(), 1, "only the valid rule should be kept");
        assert_eq!(rules[0].cve, "CVE-9999-GOOD1");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn correlate_openssl_heartbleed_letter_check() {
        let rule = vec![CveRule {
            pattern: "openssl/1.0.1".into(),
            cve: "CVE-2014-0160".into(),
            cvss: 7.5,
            severity: Severity::High,
            description: "Heartbleed".into(),
            exploit: None,
            product: None,
            min_version: None,
            max_version: None,
            fixed_version: None,
        }];
        let hit = correlate_with_rules("OpenSSL/1.0.1f", &service(443), &rule);
        assert!(!hit.is_empty(), "should match 1.0.1f");
        let miss = correlate_with_rules("OpenSSL/1.0.1g", &service(443), &rule);
        assert!(miss.is_empty(), "should not match 1.0.1g");
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use gossan_core::{HostTarget, Protocol};
    use proptest::prelude::*;
    use std::net::IpAddr;

    fn service(port: u16) -> ServiceTarget {
        ServiceTarget {
            host: HostTarget {
                ip: IpAddr::from([127, 0, 0, 1]),
                domain: Some("example.com".into()),
            },
            port,
            protocol: Protocol::Tcp,
            banner: None,
            tls: port == 443,
        }
    }

    proptest! {
        #[test]
        fn correlate_never_panics(
            banner in "[\x20-\x7e]{0,200}",
            pattern in "[a-z0-9/_.]{0,30}",
        ) {
            let rules = vec![CveRule {
                pattern,
                cve: "CVE-9999-PROP".into(),
                cvss: 5.0,
                severity: Severity::Medium,
                description: "prop test".into(),
                exploit: None,
                product: None,
                min_version: None,
                max_version: None,
                fixed_version: None,
            }];
            let _ = correlate_with_rules(&banner, &service(80), &rules);
        }

        #[test]
        fn correlate_empty_pattern_never_panics(banner in "[\x20-\x7e]{0,200}") {
            let rules = vec![CveRule {
                pattern: String::new(),
                cve: "CVE-9999-PROP".into(),
                cvss: 5.0,
                severity: Severity::Medium,
                description: "prop test".into(),
                exploit: None,
                product: None,
                min_version: None,
                max_version: None,
                fixed_version: None,
            }];
            let _ = correlate_with_rules(&banner, &service(80), &rules);
        }
    }
}
