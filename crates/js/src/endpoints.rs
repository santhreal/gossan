//! API endpoint extraction from JavaScript source code.
//!
//! Uses a set of regex patterns to identify string literals that look like
//! API paths (e.g. starting with `/api/`, `/v1/`, etc.) and common
//! AJAX/fetch/axios call patterns.
//!
//! Extracted paths are returned as `Endpoint` structs which can be
//! converted into findings.

use gossan_core::{HostTarget, Protocol, ServiceTarget, Target, WebAssetTarget};
use regex::Regex;
use secfinding::{Evidence, FindingBuilder, Severity};
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::sync::OnceLock;
/// `Endpoint`.

#[derive(Debug, Clone)]
pub struct Endpoint {
    pub path: String,
    pub js_url: String,
    pub line: usize,
}

impl Endpoint {
    pub fn into_finding(&self, target: &Target) -> FindingBuilder {
        crate::finding_builder(
            target,
            Severity::Info,
            format!("JS endpoint: {}", self.path),
            "API path extracted from JavaScript, may reveal undocumented endpoints.",
        )
        .evidence(Evidence::JsSnippet {
            url: std::sync::Arc::from(self.js_url.as_str()),
            line: self.line,
            snippet: std::sync::Arc::from(self.path.as_str()),
        })
        .tag("js-endpoint")
    }

    pub fn as_target(&self) -> Option<Target> {
        if !(self.path.starts_with("http://") || self.path.starts_with("https://")) {
            return None;
        }
        let url = url::Url::parse(&self.path).ok()?;
        let host = url.host_str()?;
        let tls = url.scheme().eq_ignore_ascii_case("https");
        let port = url.port_or_known_default()?;

        let host_target = if let Ok(ip) = IpAddr::from_str(host) {
            HostTarget { ip, domain: None }
        } else {
            // DNS is not resolved at extraction time; UNSPECIFIED marks an
            // unresolved domain host the same way the CLI pipeline does.
            HostTarget {
                ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                domain: Some(host.to_string()),
            }
        };

        Some(Target::Web(Box::new(WebAssetTarget {
            url,
            service: ServiceTarget {
                host: host_target,
                port,
                protocol: Protocol::Tcp,
                banner: None,
                tls,
            },
            tech: vec![],
            status: 0,
            title: None,
            favicon_hash: None,
            body_hash: None,
            forms: vec![],
            params: vec![],
        })))
    }

    /// Like [`as_target`], but only returns a pivot target when the host
    /// shares the seed's registrable (eTLD+1) domain. Third-party CDNs /
    /// payment APIs remain findings without expanding scan scope.
    ///
    /// Literal IP URLs are not auto-queued: they are out-of-band pivots
    /// that need an explicit scope decision elsewhere.
    pub fn as_target_in_scope(&self, seed_host: &str) -> Option<Target> {
        let candidate = self.as_target()?;
        let cand_host = match &candidate {
            Target::Web(w) => w
                .service
                .host
                .domain
                .as_deref()
                .or_else(|| w.url.host_str())?,
            Target::Domain(d) => d.domain.as_str(),
            // IP pivots stay out of auto-queue.
            Target::Host(_) => return None,
            _ => return None,
        };
        if IpAddr::from_str(cand_host).is_ok() {
            return None;
        }
        let seed_reg = gossan_core::domain::registrable(seed_host)?;
        let cand_reg = gossan_core::domain::registrable(cand_host)?;
        if seed_reg.eq_ignore_ascii_case(&cand_reg) {
            Some(candidate)
        } else {
            None
        }
    }
}

struct Pat {
    re: Regex,
    group: usize,
}

fn patterns() -> &'static [Pat] {
    static P: OnceLock<Vec<Pat>> = OnceLock::new();
    P.get_or_init(|| {
        // (pattern, capture group index)
        let specs: &[(&str, usize)] = &[
            // String literal paths starting with API prefixes
            (r#"["'`](/(?:api|v\d+|graphql|rest|rpc|internal|admin|auth|user|account|data|search|webhook|health|metrics|status|bff|trpc|dashboard|manage|svc|console)[^"'`\s<>{}\[\]]{0,200})["'`]"#, 1),
            // fetch() calls
            (r#"fetch\(["'`]([^"'`\s<>{}\[\]]{1,200})["'`]"#, 1),
            // axios.get/post/etc
            (r#"\.get\(["'`]([^"'`\s<>{}\[\]]{1,200})["'`]"#, 1),
            (r#"\.post\(["'`]([^"'`\s<>{}\[\]]{1,200})["'`]"#, 1),
            (r#"\.put\(["'`]([^"'`\s<>{}\[\]]{1,200})["'`]"#, 1),
            (r#"\.delete\(["'`]([^"'`\s<>{}\[\]]{1,200})["'`]"#, 1),
            // URL constructor
            (r#"new\s+URL\(["'`]([^"'`\s<>{}\[\]]{1,200})["'`]"#, 1),
        ];

        specs
            .iter()
            .filter_map(|(p, g)| {
                match Regex::new(p) {
                    Ok(re) => Some(Pat { re, group: *g }),
                    Err(e) => {
                        tracing::error!("invalid hardcoded JS regex pattern: {e}");
                        None
                    }
                }
            })
            .collect()
    })
}

/// Extract API endpoints from JavaScript content.
pub fn extract(js_url: &str, body: &str) -> Vec<Endpoint> {
    let mut endpoints = Vec::new();
    let mut seen = std::collections::HashSet::new();

    // Precompute line-start positions for O(1) line-number lookup.
    // Each entry is the byte offset of the first character on that line
    // (1-based, so line 1 starts at 0).
    let line_starts: Vec<usize> = std::iter::once(0)
        .chain(body.match_indices('\n').map(|(i, _)| i.saturating_add(1)))
        .collect();

    for pat in patterns() {
        for cap in pat.re.captures_iter(body) {
            if let Some(m) = cap.get(pat.group) {
                let path = m.as_str();
                if seen.contains(path) || path.len() < 2 {
                    continue;
                }

                // Binary search for the line number (1-based).
                let line = match line_starts.binary_search(&m.start()) {
                    Ok(idx) => idx.saturating_add(1),
                    Err(idx) => idx,
                };

                endpoints.push(Endpoint {
                    path: path.to_string(),
                    js_url: js_url.to_string(),
                    line,
                });
                seen.insert(path.to_string());
            }
        }
    }

    endpoints
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths(body: &str) -> Vec<String> {
        extract("https://example.com/app.js", body)
            .into_iter()
            .map(|e| e.path)
            .collect()
    }

    fn lines(body: &str) -> std::collections::HashMap<String, usize> {
        extract("https://example.com/app.js", body)
            .into_iter()
            .map(|e| (e.path, e.line))
            .collect()
    }

    // ── Positive extraction cases ─────────────────────────────────────────

    #[test]
    fn fetch_call_extracts_path() {
        let js = r#"fetch("/api/v1/users");"#;
        let got = paths(js);
        assert!(got.contains(&"/api/v1/users".to_string()));
    }

    #[test]
    fn axios_get_extracts_path() {
        let js = r#"axios.get("/gateway/auth");"#;
        let got = paths(js);
        assert!(got.contains(&"/gateway/auth".to_string()));
    }

    #[test]
    fn string_literal_with_api_prefix_extracts() {
        let js = r#"const path = "/bff/orders";"#;
        let got = paths(js);
        assert!(got.contains(&"/bff/orders".to_string()));
    }

    #[test]
    fn trpc_literal_extracts() {
        let js = r#""/trpc/router.user.list""#;
        let got = paths(js);
        assert!(got.contains(&"/trpc/router.user.list".to_string()));
    }

    #[test]
    fn dashboard_admin_literal_extracts() {
        let js = r#""/dashboard/admin""#;
        let got = paths(js);
        assert!(got.contains(&"/dashboard/admin".to_string()));
    }

    #[test]
    fn manage_settings_literal_extracts() {
        let js = r#""/manage/settings""#;
        let got = paths(js);
        assert!(got.contains(&"/manage/settings".to_string()));
    }

    #[test]
    fn svc_payments_literal_extracts() {
        let js = r#""/svc/payments""#;
        let got = paths(js);
        assert!(got.contains(&"/svc/payments".to_string()));
    }

    #[test]
    fn console_logs_literal_extracts() {
        let js = r#""/console/logs""#;
        let got = paths(js);
        assert!(got.contains(&"/console/logs".to_string()));
    }

    #[test]
    fn axios_post_put_delete_extract() {
        let js = r#"
            axios.post("/api/create");
            axios.put("/api/update");
            axios.delete("/api/remove");
        "#;
        let got = paths(js);
        assert!(got.contains(&"/api/create".to_string()));
        assert!(got.contains(&"/api/update".to_string()));
        assert!(got.contains(&"/api/remove".to_string()));
    }

    #[test]
    fn new_url_constructor_extracts() {
        let js = r#"const u = new URL("/internal/config");"#;
        let got = paths(js);
        assert!(got.contains(&"/internal/config".to_string()));
    }

    #[test]
    fn url_with_query_params_extracts_full_string() {
        let js = r#"fetch("/api/v1/users?limit=10");"#;
        let got = paths(js);
        assert!(got.contains(&"/api/v1/users?limit=10".to_string()));
    }

    // ── Negative / adversarial cases ──────────────────────────────────────

    #[test]
    fn relative_path_without_leading_slash_not_extracted_by_prefix_pattern() {
        // The prefix pattern requires a leading slash.
        let js = r#"const x = "api/v1/users";"#;
        let got = paths(js);
        assert!(
            !got.contains(&"api/v1/users".to_string()),
            "relative path without leading slash must not be extracted: {got:?}"
        );
    }

    #[test]
    fn bare_json_status_key_is_false_positive_guarded() {
        let js = r#"{ "status": "ok" }"#;
        let got = paths(js);
        assert!(
            !got.contains(&"/status".to_string()),
            "JSON key 'status' must NOT produce false positive: {got:?}"
        );
    }

    #[test]
    fn empty_body_yields_nothing() {
        assert!(paths("").is_empty());
    }

    #[test]
    fn plain_js_no_endpoints() {
        let js = "var x = 1; function foo() { return 42; }";
        assert!(paths(js).is_empty());
    }

    #[test]
    fn dedup_prevents_duplicates() {
        let js = r#"
            fetch("/api/dup");
            fetch("/api/dup");
            axios.get("/api/dup");
        "#;
        let eps = extract("u", js);
        assert_eq!(
            eps.iter().filter(|e| e.path == "/api/dup").count(),
            1,
            "duplicate path must appear exactly once"
        );
    }

    #[test]
    fn line_numbers_are_one_based() {
        let js = "\nfetch(\"/api/a\");\n\naxios.get(\"/api/b\");";
        let map = lines(js);
        assert_eq!(map.get("/api/a"), Some(&2));
        assert_eq!(map.get("/api/b"), Some(&4));
    }

    #[test]
    fn path_shorter_than_two_chars_is_ignored() {
        // The code rejects paths with len < 2; single-char paths are dropped.
        let js = r#"fetch("/");"#;
        let got = paths(js);
        assert!(!got.contains(&"/".to_string()), "single-char path must be ignored");
    }

    #[test]
    fn two_char_path_in_fetch_is_extracted() {
        let js = r#"fetch("/x");"#;
        let got = paths(js);
        assert!(got.contains(&"/x".to_string()), "two-char path passes len >= 2 check");
    }

    #[test]
    fn as_target_in_scope_keeps_same_registrable() {
        let ep = Endpoint {
            path: "https://api.example.com/v1/x".into(),
            js_url: "https://app.example.com/app.js".into(),
            line: 1,
        };
        assert!(ep.as_target_in_scope("app.example.com").is_some());
        assert!(ep.as_target_in_scope("example.com").is_some());
    }

    #[test]
    fn as_target_in_scope_rejects_third_party_cdn() {
        let ep = Endpoint {
            path: "https://maps.googleapis.com/maps/api/js".into(),
            js_url: "https://app.example.com/app.js".into(),
            line: 1,
        };
        assert!(ep.as_target().is_some());
        assert!(ep.as_target_in_scope("app.example.com").is_none());
        assert!(ep.as_target_in_scope("example.com").is_none());
    }

    #[test]
    fn as_target_in_scope_rejects_ip_pivot() {
        let ep = Endpoint {
            path: "https://10.0.0.5/internal".into(),
            js_url: "https://app.example.com/app.js".into(),
            line: 1,
        };
        assert!(ep.as_target().is_some());
        assert!(ep.as_target_in_scope("app.example.com").is_none());
    }

    #[test]
    fn as_target_resolves_http_url_to_web() {
        let ep = Endpoint {
            path: "https://api.example.com:8443/v1/users".to_string(),
            js_url: "u".into(),
            line: 1,
        };
        match ep.as_target() {
            Some(Target::Web(w)) => {
                assert_eq!(w.url.as_str(), "https://api.example.com:8443/v1/users");
                assert_eq!(w.service.host.domain.as_deref(), Some("api.example.com"));
                assert_eq!(w.service.port, 8443);
                assert!(w.service.tls);
            }
            other => panic!("expected Web, got {other:?}"),
        }
    }

    #[test]
    fn as_target_returns_none_for_relative_path() {
        let ep = Endpoint {
            path: "/api/users".to_string(),
            js_url: "u".into(),
            line: 1,
        };
        assert!(ep.as_target().is_none());
    }

    #[test]
    fn as_target_rejects_non_http_schemes() {
        for bad in ["javascript:alert(1)", "data:text/html,<script>"] {
            let ep = Endpoint {
                path: bad.to_string(),
                js_url: "u".into(),
                line: 1,
            };
            assert!(ep.as_target().is_none(), "{bad} must not produce a target");
        }
    }

    #[test]
    fn as_target_resolves_ip_url_to_web_target() {
        let ep = Endpoint {
            path: "https://1.2.3.4/api".to_string(),
            js_url: "u".into(),
            line: 1,
        };
        match ep.as_target() {
            Some(Target::Web(w)) => {
                assert_eq!(w.url.as_str(), "https://1.2.3.4/api");
                assert_eq!(w.service.host.ip.to_string(), "1.2.3.4");
                assert!(w.service.host.domain.is_none());
                assert_eq!(w.service.port, 443);
                assert!(w.service.tls);
            }
            other => panic!("expected Web, got {other:?}"),
        }
    }

    #[test]
    fn as_target_http_scheme_also_resolves() {
        let ep = Endpoint {
            path: "http://internal.corp.example.com/api".to_string(),
            js_url: "u".into(),
            line: 1,
        };
        match ep.as_target() {
            Some(Target::Web(w)) => {
                assert_eq!(
                    w.service.host.domain.as_deref(),
                    Some("internal.corp.example.com")
                );
                assert_eq!(w.service.port, 80);
                assert!(!w.service.tls);
                assert_eq!(w.url.path(), "/api");
            }
            other => panic!("expected Web, got {other:?}"),
        }
    }

    // ── Boundary: single-char path rejected ──────────────────────────────

    #[test]
    fn path_exactly_one_char_rejected() {
        // The guard is `path.len() < 2` → single-byte paths dropped.
        for bad in ["/", "x"] {
            let js = format!("fetch(\"{bad}\");");
            let got = paths(&js);
            assert!(
                !got.contains(&bad.to_string()),
                "path {bad:?} with len=1 must be dropped"
            );
        }
    }

    // ── Line numbers: first line ──────────────────────────────────────────

    #[test]
    fn endpoint_on_first_line_has_line_one() {
        let js = r#"fetch("/api/first");"#;
        let map = lines(js);
        assert_eq!(map.get("/api/first"), Some(&1));
    }

    // ── Dedup: same path from two patterns only appears once ──────────────

    #[test]
    fn path_extracted_by_two_different_patterns_deduped() {
        // "/api/dupe" can be caught by both the string literal pattern AND fetch().
        let js = r#"const p = "/api/dupe"; fetch("/api/dupe");"#;
        let eps = extract("u", js);
        assert_eq!(
            eps.iter().filter(|e| e.path == "/api/dupe").count(),
            1,
            "same path from multiple pattern matches must appear exactly once"
        );
    }

    // ── Adversarial: injected newlines in path ────────────────────────────

    #[test]
    fn path_with_embedded_newline_not_extracted() {
        // Regex stops at the quote boundary; a newline inside the string literal
        // would be a syntax error in real JS, the regex character class
        // `[^"'` + \s...]` includes `\s` which covers newlines.
        let js = "fetch(\"/api/line\ninjection\");";
        let eps = extract("u", js);
        // The match should not cross the embedded newline.
        assert!(
            !eps.iter().any(|e| e.path.contains('\n')),
            "newline must not be included in extracted path"
        );
    }

    // ── Adversarial / DoS protection ──────────────────────────────────────

    #[test]
    fn large_file_with_many_matches_completes_quickly() {
        // Build a 500 KB body with 50_000 lines, each containing a match.
        // With the old O(n²) line counting this would take ~5 s;
        // with binary-search line starts it should be < 2 s.
        let line = "fetch(\"/api/x\");\n";
        let repeat = 50_000;
        let body = line.repeat(repeat);
        let start = std::time::Instant::now();
        let eps = extract("https://example.com/app.js", &body);
        let elapsed = start.elapsed();
        assert_eq!(
            eps.len(),
            1,
            "dedup should collapse all identical paths"
        );
        assert!(
            elapsed.as_millis() < 2_000,
            "extract must complete in <2 s on 50k-line input, took {elapsed:?}"
        );
    }

    #[test]
    fn empty_body_yields_no_endpoints() {
        assert!(extract("u", "").is_empty());
    }

    #[test]
    fn multibyte_utf8_before_match() {
        // The match start byte index must not split a multi-byte char.
        let js = "🎉🎉🎉 fetch(\"/api/emoji\");";
        let eps = extract("u", js);
        assert!(eps.iter().any(|e| e.path == "/api/emoji"));
    }

    #[test]
    fn path_at_very_last_line() {
        let js = "\n\n\nfetch(\"/api/last\");";
        let eps = extract("u", js);
        assert_eq!(eps[0].line, 4);
    }

    #[test]
    fn adversarial_nested_quotes() {
        let js = r#"fetch("/api/`${foo}`");"#;
        // The regex should not cross the back-tick boundary.
        let eps = extract("u", js);
        assert!(
            !eps.iter().any(|e| e.path.contains("`${foo}`")),
            "must not cross quote boundaries"
        );
    }

    // ── proptest property tests ───────────────────────────────────────────

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn extract_never_panics(body in "\\PC{0,4096}") {
            let _ = extract("https://example.com/app.js", &body);
        }

        #[test]
        fn extract_line_numbers_are_valid(body in "\\PC{0,4096}") {
            let eps = extract("https://example.com/app.js", &body);
            for ep in &eps {
                // line must be >= 1 and <= number of lines + 1
                let line_count = body.lines().count().max(1);
                prop_assert!(ep.line >= 1 && ep.line <= line_count.saturating_add(1));
            }
        }

        #[test]
        fn extract_results_are_deduped(body in "\\PC{0,4096}") {
            let eps = extract("https://example.com/app.js", &body);
            let mut seen = std::collections::HashSet::new();
            for ep in &eps {
                prop_assert!(seen.insert(ep.path.clone()), "duplicate path found: {}", ep.path);
            }
        }

        #[test]
        fn extract_paths_have_min_length(body in "\\PC{0,4096}") {
            let eps = extract("https://example.com/app.js", &body);
            for ep in &eps {
                prop_assert!(
                    ep.path.len() >= 2,
                    "path '{}' is shorter than 2 bytes",
                    ep.path
                );
            }
        }

        #[test]
        fn as_target_never_panics(path in "\\PC{0,256}") {
            let ep = Endpoint {
                path,
                js_url: "u".into(),
                line: 1,
            };
            let _ = ep.as_target();
        }
    }
}
