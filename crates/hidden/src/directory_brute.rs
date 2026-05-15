//! Directory brute-force probe.
//!
//! Enumerates common paths and extensions to discover hidden directories
//! and files. Uses 404 baseline fingerprinting to reduce false positives.
//! Wordlist is loaded from a Tier B file (SecLists-derived) by default,
//! falling back to a small built-in list.

use gossan_core::Target;
use reqwest::Client;
use secfinding::{Evidence, Finding, Severity};

/// Default directory wordlist embedded at compile time (emergency fallback).
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

/// Load the directory wordlist: Tier B file first, then built-in fallback.
pub fn load_wordlist(custom_path: Option<&str>) -> Vec<String> {
    let mut words: Vec<String> = Vec::new();

    // Try custom path first
    if let Some(path) = custom_path {
        if let Ok(content) = std::fs::read_to_string(path) {
            words.extend(parse_wordlist(&content));
            if !words.is_empty() {
                tracing::info!(
                    count = words.len(),
                    path = path,
                    "loaded custom directory wordlist"
                );
                return words;
            }
        }
    }

    // Try Tier B paths
    for path in TIER_B_PATHS {
        if let Ok(content) = std::fs::read_to_string(path) {
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
    }

    // Fallback to built-in list
    words.extend(parse_wordlist(DEFAULT_WORDLIST));
    tracing::info!(
        count = words.len(),
        "using built-in directory wordlist fallback"
    );
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
) -> Vec<Finding> {
    let Target::Web(asset) = target else {
        return vec![];
    };
    let base = asset.url.as_str().trim_end_matches('/');
    let mut findings = Vec::new();

    for path in wordlist {
        let path = if path.starts_with('/') {
            path.clone()
        } else {
            format!("/{}", path)
        };
        for ext in extensions {
            let url = format!("{}{}{}", base, path, ext);
            let Ok(resp) = client.get(&url).send().await else {
                continue;
            };
            let status = resp.status().as_u16();

            if !status_codes.contains(&status) {
                continue;
            }

            let bytes = match crate::soft404::read_limited(resp, crate::MAX_BODY_BYTES).await {
                Some(b) => b,
                None => continue,
            };

            if crate::soft404::is_likely_404(status, &bytes, baseline, false) {
                continue;
            }

            let body_preview = String::from_utf8_lossy(&bytes);
            let excerpt = if body_preview.len() > 200 {
                format!("{}...", &body_preview[..200])
            } else {
                body_preview.to_string()
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
                findings.push(f);
            }

            // Only report one extension variant per path to avoid spam
            break;
        }
    }

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
}
