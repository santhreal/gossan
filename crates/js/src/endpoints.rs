//! Extract API endpoint patterns from JavaScript source.
//! Covers string literals, fetch(), axios, XHR, superagent, template literals.

use gossan_core::Target;
use regex::Regex;
use secfinding::{Evidence, Finding, Severity};
use std::sync::OnceLock;

pub struct Endpoint {
    pub path: String,
    pub js_url: String,
    pub line: usize,
}

impl Endpoint {
    pub fn into_finding(self, target: Target) -> Finding {
        crate::finding_builder(
            &target,
            Severity::Info,
            format!("JS endpoint: {}", self.path),
            "API path extracted from JavaScript — may reveal undocumented endpoints.",
        )
        .evidence(Evidence::JsSnippet {
            url: self.js_url,
            line: self.line,
            snippet: self.path.clone(),
        })
        .tag("js-endpoint")
        .build()
        .expect("finding builder: required fields are set")
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
            (r#"["'`](/(?:api|v\d+|graphql|rest|rpc|internal|admin|auth|user|account|data|search|webhook|health|metrics|status)[^"'`\s<>{}\[\]]{0,200})["'`]"#, 1),
            // fetch() calls
            (r#"fetch\s*\(\s*["'`]([^"'`\s]{5,200})["'`]"#, 1),
            // axios.get/post/put/patch/delete
            (r#"axios\s*\.\s*(?:get|post|put|patch|delete|head|options)\s*\(\s*["'`]([^"'`\s]{5,200})["'`]"#, 1),
            // axios({ url: "..." })
            (r#"\burl\s*:\s*["'`]([/][^"'`\s]{4,200})["'`]"#, 1),
            // XMLHttpRequest.open("GET", "/path")
            (r#"\.open\s*\(\s*["'][A-Z]+["']\s*,\s*["'`]([^"'`\s]{5,200})["'`]"#, 1),
            // superagent: request.get("/path")
            (r#"\brequest\s*\.\s*(?:get|post|put|delete|patch)\s*\(\s*["'`]([^"'`\s]{5,200})["'`]"#, 1),
            // Template literals with API prefix: `/api/${...}/users`
            (r#"`(/(?:api|v\d+|graphql|rest|admin|auth)[^`\s<>]{0,200})`"#, 1),
        ];

        specs.iter()
            .filter_map(|(pat, group)| Regex::new(pat).ok().map(|re| Pat { re, group: *group }))
            .collect()
    })
}

pub fn extract(js_url: &str, body: &str) -> Vec<Endpoint> {
    let mut seen = std::collections::HashSet::new();
    let mut results = Vec::new();

    for (line_no, line) in body.lines().enumerate() {
        for pat in patterns() {
            for cap in pat.re.captures_iter(line) {
                if let Some(m) = cap.get(pat.group) {
                    let path = m.as_str().to_string();
                    // Skip static assets and noise
                    if path.len() < 4
                        || path.contains("..")
                        || path.ends_with(".js")
                        || path.ends_with(".css")
                        || path.ends_with(".png")
                        || path.ends_with(".jpg")
                        || path.ends_with(".svg")
                        || path.ends_with(".woff")
                        || path.ends_with(".ico")
                    {
                        continue;
                    }
                    if seen.insert(path.clone()) {
                        results.push(Endpoint {
                            path,
                            js_url: js_url.to_string(),
                            line: line_no + 1,
                        });
                    }
                }
            }
        }
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;
    use gossan_core::{DiscoverySource, DomainTarget, Severity, Target};

    #[test]
    fn extract_finds_fetch_and_axios_endpoints() {
        let body = r#"
            fetch("/api/users");
            axios.get("/graphql");
        "#;
        let endpoints = extract("https://example.com/app.js", body);
        let paths: Vec<_> = endpoints.iter().map(|e| e.path.as_str()).collect();
        assert!(paths.contains(&"/api/users"));
        assert!(paths.contains(&"/graphql"));
    }

    #[test]
    fn extract_deduplicates_and_skips_static_assets() {
        let body = r#"
            fetch("/api/users");
            fetch("/api/users");
            fetch("/static/app.js");
        "#;
        let endpoints = extract("https://example.com/app.js", body);
        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0].path, "/api/users");
    }

    #[test]
    fn endpoint_into_finding_preserves_path_as_snippet() {
        let finding = Endpoint {
            path: "/api/users".into(),
            js_url: "https://example.com/app.js".into(),
            line: 12,
        }
        .into_finding(Target::Domain(DomainTarget {
            domain: "example.com".into(),
            source: DiscoverySource::Seed,
        }));

        assert_eq!(finding.severity, Severity::Info);
        assert!(finding.title.contains("/api/users"));
    }

    // ── Adversarial edge cases ──────────────────────────────────────────────

    #[test]
    fn extract_empty_body() {
        assert!(extract("test.js", "").is_empty());
    }

    #[test]
    fn extract_minified_single_line() {
        let body = r#"var a=1;fetch("/api/v2/users");var b=axios.get("/rest/data");"#;
        let paths: Vec<_> = extract("app.min.js", body)
            .iter()
            .map(|e| e.path.clone())
            .collect();
        assert!(paths.contains(&"/api/v2/users".to_string()));
        assert!(paths.contains(&"/rest/data".to_string()));
    }

    #[test]
    fn extract_xhr_open() {
        let body = r#"xhr.open("POST", "/api/submit");"#;
        let paths: Vec<_> = extract("app.js", body)
            .iter()
            .map(|e| e.path.clone())
            .collect();
        assert!(paths.contains(&"/api/submit".to_string()));
    }

    #[test]
    fn extract_template_literal() {
        let body = r#"const url = `/api/v1/${userId}/profile`;"#;
        let endpoints = extract("app.js", body);
        assert!(
            !endpoints.is_empty(),
            "should extract endpoint from template literal"
        );
    }

    #[test]
    fn skips_path_traversal_attempts() {
        let body = r#"fetch("/api/../../../etc/passwd");"#;
        let endpoints = extract("app.js", body);
        let has_traversal = endpoints.iter().any(|e| e.path.contains(".."));
        assert!(!has_traversal, "should skip paths containing .. traversal");
    }

    #[test]
    fn handles_huge_js_no_panic() {
        let big = format!(r#"fetch("/api/endpoint");{}"#, "x".repeat(2_000_000));
        let endpoints = extract("big.js", &big);
        assert!(!endpoints.is_empty());
    }

    #[test]
    fn extract_url_config_pattern() {
        let body = r#"
            const config = {
                url: "/admin/settings",
                method: "POST"
            };
        "#;
        let paths: Vec<_> = extract("app.js", body)
            .iter()
            .map(|e| e.path.clone())
            .collect();
        assert!(paths.contains(&"/admin/settings".to_string()));
    }

    #[test]
    fn line_numbers_are_one_indexed() {
        let body = "line1\nline2\nfetch(\"/api/test\");\nline4\n";
        let endpoints = extract("app.js", body);
        assert!(!endpoints.is_empty());
        assert_eq!(endpoints[0].line, 3, "line numbers should be 1-indexed");
    }

    #[test]
    fn extract_superagent_pattern() {
        let body = r#"request.post("/api/v3/submit");"#;
        let paths: Vec<_> = extract("app.js", body)
            .iter()
            .map(|e| e.path.clone())
            .collect();
        assert!(paths.contains(&"/api/v3/submit".to_string()));
    }
}
