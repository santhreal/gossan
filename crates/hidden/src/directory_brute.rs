//! Directory brute-force probe.
//!
//! Enumerates common paths and extensions to discover hidden directories
//! and files. Uses 404 baseline fingerprinting to reduce false positives.
//! Wordlist tier is selected via [`gossan_core::WordlistTier`]:
//!   - **Fast** (default): top ~100 highest-value paths.
//!   - **Standard**: Tier B file on disk (~365 paths) if present, else full.
//!   - **Full**: complete embedded wordlist (~1160 paths).

use futures::StreamExt as _;
use gossan_core::{Target, WordlistTier};
use reqwest::Client;
use secfinding::{Evidence, Finding, Severity};

/// Top-100 highest-value paths (admin, config, actuator, env, etc.).
const FAST_WORDLIST: &str = include_str!("top100_wordlist.txt");

/// Full directory wordlist embedded at compile time.
const DEFAULT_WORDLIST: &str = include_str!("directory_wordlist.txt");

/// Tier B wordlist path (relative to executable or CWD).
const TIER_B_PATHS: &[&str] = &[
    "data/tier_b_wordlist.txt",
    "crates/hidden/data/tier_b_wordlist.txt",
];

/// Default extensions to test for each path root.
const DEFAULT_EXTENSIONS: &[&str] = &[
    "", ".php", ".js", ".json", ".bak", ".txt", ".zip", ".tar.gz", ".sql", ".xml", ".old", ".save",
    ".swp", ".~", ".orig", ".copy", ".rar", ".7z", ".gz", ".tgz", ".bz2", ".tar", ".log",
    ".config", ".yml", ".yaml", ".cfg", ".ini", ".db", ".sqlite", ".sqlite3", ".mdb", ".dbf",
    ".csv", ".xls", ".xlsx", ".pdf", ".doc", ".docx",
];

/// Default interesting HTTP status codes.
const DEFAULT_STATUSES: &[u16] = &[200, 204, 301, 302, 307, 308, 401, 403, 405, 500];

/// Load the directory wordlist for the given tier.
///
/// A custom path always overrides the tier. When no custom path is
/// supplied, the tier selects between fast (top-100), standard (Tier B
/// file or full fallback), and full (embedded ~1160 paths).
pub fn load_wordlist(custom_path: Option<&str>) -> Vec<String> {
    load_wordlist_tiered(custom_path, &WordlistTier::default())
}

/// Load the directory wordlist with an explicit tier.
pub fn load_wordlist_tiered(custom_path: Option<&str>, tier: &WordlistTier) -> Vec<String> {
    let mut words: Vec<String> = Vec::new();

    // Try custom path first
    if let Some(path) = custom_path {
        match std::fs::read_to_string(path) {
            Ok(content) => {
                words.extend(parse_wordlist(&content));
                if !words.is_empty() {
                    tracing::info!(
                        count = words.len(),
                        path = path,
                        "loaded custom directory wordlist"
                    );
                    return words;
                }
                tracing::warn!(
                    path = path,
                    "custom directory wordlist is empty; falling back to tier"
                );
            }
            Err(e) => {
                tracing::warn!(
                    path = path,
                    error = %e,
                    "failed to read custom directory wordlist; falling back to tier"
                );
            }
        }
    }

    match tier {
        WordlistTier::Fast => {
            words.extend(parse_wordlist(FAST_WORDLIST));
            tracing::info!(
                count = words.len(),
                "using fast (top-100) directory wordlist"
            );
        }
        WordlistTier::Full => {
            words.extend(parse_wordlist(DEFAULT_WORDLIST));
            tracing::info!(
                count = words.len(),
                "using full directory wordlist"
            );
        }
        WordlistTier::Standard => {
            // Try Tier B paths
            for path in TIER_B_PATHS {
                match std::fs::read_to_string(path) {
                    Ok(content) => {
                        words.extend(parse_wordlist(&content));
                        if !words.is_empty() {
                            tracing::info!(
                                count = words.len(),
                                path = path,
                                "loaded Tier B directory wordlist"
                            );
                            return words;
                        }
                    }
                    Err(e) => {
                        tracing::debug!(
                            path = path,
                            error = %e,
                            "Tier B directory wordlist not found or unreadable; trying next path"
                        );
                    }
                }
            }
            // Fallback to full list
            words.extend(parse_wordlist(DEFAULT_WORDLIST));
            tracing::info!(
                count = words.len(),
                "using built-in directory wordlist fallback"
            );
        }
    }
    words
}

fn parse_wordlist(content: &str) -> Vec<String> {
    // Strip a leading `/` if present so callers can concatenate the
    // word onto a base URL without producing `https://host//word`.
    // Filters comments + dedups.
    let mut seen = std::collections::HashSet::new();
    content
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.strip_prefix('/').unwrap_or(l).to_string())
        .filter(|l| !l.is_empty())
        .filter(|l| seen.insert(l.clone()))
        .collect()
}

/// Resolve extensions to use: custom config overrides, otherwise defaults.
pub fn extensions(custom: &[String]) -> Vec<String> {
    if custom.is_empty() {
        DEFAULT_EXTENSIONS.iter().map(|s| s.to_string()).collect()
    } else {
        custom.to_vec()
    }
}

/// Resolve interesting status codes: custom config overrides, otherwise defaults.
pub fn status_codes(custom: &[u16]) -> Vec<u16> {
    if custom.is_empty() {
        DEFAULT_STATUSES.to_vec()
    } else {
        custom.to_vec()
    }
}

pub async fn probe(
    client: &Client,
    target: &Target,
    wordlist: &[String],
    extensions: &[String],
    status_codes: &[u16],
    baseline: Option<&crate::soft404::BaselineFingerprint>,
    rate_limiter: &std::sync::Arc<crate::HostRateLimiter>,
    host: &str,
) -> Vec<Finding> {
    let Target::Web(asset) = target else {
        return vec![];
    };
    let base = asset.url.as_str().trim_end_matches('/');

    let client = client.clone();
    let findings: Vec<Finding> = futures::stream::iter(0..wordlist.len())
        .map(|i| {
            let client = client.clone();
            let rl = std::sync::Arc::clone(rate_limiter);
            let host_str = host.to_string();
            async move {
                let path = &wordlist[i];
                let path = if path.starts_with('/') {
                    path.clone()
                } else {
                    format!("/{}", path)
                };
                let mut path_findings = Vec::new();
                for ext in extensions {
                    let url = format!("{}{}{}", base, path, ext);
                    rl.wait_for_host(&host_str).await;
                    let Ok(resp) = client.get(&url).send().await else {
                        tracing::warn!(url = %url, "directory_brute: probe send failed");
                        continue;
                    };
                    let status = resp.status().as_u16();
                    rl.observe_status(&host_str, status).await;

                    if !status_codes.contains(&status) {
                        continue;
                    }

                    let content_type = resp
                        .headers()
                        .get("content-type")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                        .to_ascii_lowercase();
                    let content_length = resp.content_length();

                    let bytes = match crate::soft404::read_limited(resp, crate::MAX_BODY_BYTES).await {
                        Some(b) => b,
                        None => {
                            // Oversized body (or stream error). Do not silently drop
                            // large non-HTML discoveries such as .zip/.tar.gz backups.
                            let is_html = content_type.contains("text/html")
                                || content_type.contains("application/xhtml");
                            if status == 200 && !is_html {
                                let safe_path = crate::path_sanitize::sanitize_url_path(&path);
                                let safe_ext = crate::path_sanitize::sanitize_url_path(ext);
                                let size_note = content_length
                                    .map(|n| format!("{n} bytes (Content-Length)"))
                                    .unwrap_or_else(|| {
                                        format!("exceeds {} byte read cap", crate::MAX_BODY_BYTES)
                                    });
                                if let Some(f) = Finding::builder(
                                    "hidden",
                                    target.domain().unwrap_or("?"),
                                    severity_for_status(status),
                                )
                                .title(format!(
                                    "Hidden path discovered: {}{}",
                                    safe_path, safe_ext
                                ))
                                .detail(format!(
                                    "The path {}{} returned HTTP {} with Content-Type '{}'                                      ({size_note}). Body exceeded the scanner read cap so                                      content was not fully fetched; this may be a backup or                                      archive exposure.",
                                    safe_path, safe_ext, status, content_type
                                ))
                                .evidence(Evidence::HttpResponse {
                                    status,
                                    headers: vec![
                                        ("content-type".into(), content_type.clone().into()),
                                    ],
                                    body_excerpt: Some(
                                        format!("[body omitted: {size_note}]").into(),
                                    ),
                                })
                                .tag("hidden")
                                .tag("directory-brute")
                                .tag("exposure")
                                .tag("size-capped")
                                .kind(secfinding::FindingKind::FileDiscovery)
                                .build_or_log()
                                {
                                    path_findings.push(f);
                                }
                            } else {
                                tracing::warn!(
                                    "directory-brute body read failed or exceeded cap at {} (status={}, content-type={}); skipping",
                                    url, status, content_type
                                );
                            }
                            continue;
                        }
                    };

                    if crate::soft404::is_likely_404(status, &bytes, baseline, false) {
                        continue;
                    }

                    let body_preview = String::from_utf8_lossy(&bytes);
                    let mut chars = body_preview.chars();
                    let excerpt: String = chars.by_ref().take(200).collect();
                    let excerpt = if chars.next().is_some() {
                        format!("{}...", excerpt)
                    } else {
                        excerpt
                    };

                    let safe_path = crate::path_sanitize::sanitize_url_path(&path);
                    let safe_ext = crate::path_sanitize::sanitize_url_path(ext);

                    if let Some(f) = Finding::builder("hidden", target.domain().unwrap_or("?"), severity_for_status(status))
                        .title(format!("Hidden path discovered: {}{}", safe_path, safe_ext))
                        .detail(format!(
                            "The path {}{} returned HTTP {} ({} bytes). This may expose administrative interfaces, backups, or undocumented API endpoints.",
                            safe_path, safe_ext, status, bytes.len()
                        ))
                        .evidence(Evidence::HttpResponse {
                            status,
                            headers: vec![],
                            body_excerpt: Some((excerpt).into()),
                        })
                        .tag("hidden")
                        .tag("directory-brute")
                        .tag(match status {
                            401 | 403 => "auth-required",
                            500 => "server-error",
                            _ => "exposure",
                        })
                        .kind(secfinding::FindingKind::FileDiscovery)
                        .build_or_log()
                    {
                        path_findings.push(f);
                    }

                    // Keep probing other extensions after redirects/auth walls;
                    // only stop early on a clear content exposure.
                    if should_stop_extension_probe(status) {
                        break;
                    }
                }
                path_findings
            }
        })
        .buffer_unordered(16)
        .flat_map(futures::stream::iter)
        .collect()
        .await;

    findings
}

fn severity_for_status(status: u16) -> Severity {
    match status {
        200 | 204 => Severity::High,
        401 | 403 => Severity::Medium,
        500 => Severity::Low,
        _ => Severity::Info,
    }
}

/// Whether finding one status should stop probing further extensions for this path.
fn should_stop_extension_probe(status: u16) -> bool {
    matches!(status, 200 | 204)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_wordlist_filters_comments_and_empty() {
        let input = "# comment\n\n/admin\n/api\n/api\n";
        let words = parse_wordlist(input);
        assert_eq!(words, vec!["admin", "api"]);
    }

    #[test]
    fn stop_extension_probe_only_on_content_exposure() {
        assert!(should_stop_extension_probe(200));
        assert!(should_stop_extension_probe(204));
        assert!(!should_stop_extension_probe(301));
        assert!(!should_stop_extension_probe(403));
        assert!(!should_stop_extension_probe(401));
        assert!(!should_stop_extension_probe(500));
    }

    #[test]
    fn extensions_default_is_nonempty() {
        let exts = extensions(&[]);
        assert!(exts.contains(&".php".to_string()));
        assert!(exts.contains(&".bak".to_string()));
        assert!(exts.contains(&".yaml".to_string()));
    }

    #[test]
    fn status_codes_default_covers_common() {
        let codes = status_codes(&[]);
        assert!(codes.contains(&200));
        assert!(codes.contains(&401));
        assert!(codes.contains(&500));
    }

    #[test]
    fn severity_for_status_matches_expectations() {
        assert_eq!(severity_for_status(200), Severity::High);
        assert_eq!(severity_for_status(401), Severity::Medium);
        assert_eq!(severity_for_status(500), Severity::Low);
        assert_eq!(severity_for_status(301), Severity::Info);
    }

    #[test]
    fn parse_wordlist_strips_leading_slash() {
        let input = "/admin\n/api\n";
        let words = parse_wordlist(input);
        assert_eq!(words, vec!["admin", "api"]);
    }

    #[test]
    fn parse_wordlist_deduplicates_entries() {
        let input = "admin\nadmin\nadmin\n";
        let words = parse_wordlist(input);
        assert_eq!(words.len(), 1);
        assert_eq!(words[0], "admin");
    }

    #[test]
    fn extensions_returns_custom_when_provided() {
        let custom = vec![".custom".to_string()];
        let exts = extensions(&custom);
        assert_eq!(exts, custom);
    }

    #[test]
    fn status_codes_returns_custom_when_provided() {
        let custom = vec![201, 418];
        let codes = status_codes(&custom);
        assert_eq!(codes, custom);
    }

    #[test]
    fn severity_for_status_maps_204_to_high() {
        assert_eq!(severity_for_status(204), Severity::High);
    }

    /// Adversarial: empty wordlist must return empty vec.
    #[test]
    fn parse_wordlist_empty() {
        let words = parse_wordlist("");
        assert!(words.is_empty());
    }

    /// Adversarial: wordlist with only comments and whitespace.
    #[test]
    fn parse_wordlist_only_comments_and_whitespace() {
        let input = "# comment\n\n   \n# another comment\n";
        let words = parse_wordlist(input);
        assert!(words.is_empty());
    }

    /// Adversarial: extreme-length wordlist must not panic.
    #[test]
    fn parse_wordlist_extreme_length() {
        let input = (0..100_000).map(|i| format!("word{}", i)).collect::<Vec<_>>().join("\n");
        let words = parse_wordlist(&input);
        assert_eq!(words.len(), 100_000);
    }

    /// Adversarial: path traversal strings in wordlist must be preserved
    /// (parse_wordlist does not sanitize (it only strips leading slashes)).
    #[test]
    fn parse_wordlist_path_traversal_preserved() {
        let input = "../../../etc/passwd\n..\\windows\\system32\n";
        let words = parse_wordlist(input);
        assert_eq!(words, vec!["../../../etc/passwd", "..\\windows\\system32"]);
    }

    #[test]
    fn fast_tier_loads_fewer_than_full() {
        let fast = load_wordlist_tiered(None, &WordlistTier::Fast);
        let full = load_wordlist_tiered(None, &WordlistTier::Full);
        assert!(!fast.is_empty(), "fast wordlist must not be empty");
        assert!(!full.is_empty(), "full wordlist must not be empty");
        assert!(
            fast.len() < full.len(),
            "fast tier ({}) must be smaller than full ({})",
            fast.len(),
            full.len()
        );
    }

    #[test]
    fn fast_tier_contains_high_value_paths() {
        let fast = load_wordlist_tiered(None, &WordlistTier::Fast);
        assert!(fast.iter().any(|w| w == "admin"), "fast must contain admin");
        assert!(fast.iter().any(|w| w == "config"), "fast must contain config");
        assert!(
            fast.iter().any(|w| w == "actuator"),
            "fast must contain actuator"
        );
    }

    #[test]
    fn full_tier_contains_standard_directories() {
        let full = load_wordlist_tiered(None, &WordlistTier::Full);
        assert!(
            full.iter().any(|w| w == "admin"),
            "full must contain admin"
        );
        assert!(
            full.iter().any(|w| w == "backup"),
            "full must contain backup"
        );
        assert!(
            full.len() > 500,
            "full tier must have >500 entries, got {}",
            full.len()
        );
    }

    /// Property tests for wordlist parsing.
    #[cfg(test)]
    mod proptests {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #[test]
            fn prop_parse_wordlist_never_panics(input in "\\PC*") {
                let _ = parse_wordlist(&input);
            }

            #[test]
            fn prop_parse_wordlist_no_empty_entries(input in "\\PC*") {
                let words = parse_wordlist(&input);
                prop_assert!(words.iter().all(|w| !w.is_empty()));
            }

            #[test]
            fn prop_parse_wordlist_no_exact_single_leading_slash(input in "\\PC*") {
                let words = parse_wordlist(&input);
                // strip_prefix('/') removes exactly one leading '/', so the
                // resulting word never equals the original line with a single
                // leading slash intact. Multiple slashes can remain (e.g. // → /).
                for word in &words {
                    prop_assert!(!word.starts_with("//"));
                }
            }

            #[test]
            fn prop_extensions_roundtrip_non_empty(exts in proptest::collection::vec("[a-z]+", 1..20)) {
                let exts_str: Vec<String> = exts.into_iter().map(|s| format!(".{}", s)).collect();
                let result = extensions(&exts_str);
                prop_assert_eq!(result, exts_str);
            }

            #[test]
            fn prop_status_codes_roundtrip_non_empty(codes in proptest::collection::vec(100u16..600, 1..20)) {
                let result = status_codes(&codes);
                prop_assert_eq!(result, codes);
            }
        }
    }
}
