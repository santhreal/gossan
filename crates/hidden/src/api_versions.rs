//! API version path enumeration.
//!
//! Modern APIs version their endpoints. Older versions are often:
//!   - Deployed with weaker authentication
//!   - Missing security patches applied to the current version
//!   - Not behind the WAF rules protecting v1+
//!   - Returning more verbose errors / debug output
//!
//! We probe a matrix of version prefixes × common API roots.
//! A 2xx or auth-required (401/403) response on a version path that
//! differs from the baseline indicates an active older API version.

use gossan_core::Target;
use reqwest::Client;
use secfinding::{Evidence, Finding, Severity};

// Version prefixes ordered by age (older = more likely vulnerable)
const VERSION_PATHS: &[&str] = &[
    "/v0",
    "/v00",
    "/v1",
    "/v1.0",
    "/v1.1",
    "/v2",
    "/v2.0",
    "/v3",
    "/api/v0",
    "/api/v1",
    "/api/v2",
    "/api/v3",
    "/api/v1.0",
    "/api/v1.1",
    "/api/v2.0",
    "/api/v0.1",
];

// Paths that suggest a non-production / shadow API
const SHADOW_PATHS: &[(&str, &str, Severity)] = &[
    ("/dev", "Development API endpoint", Severity::High),
    ("/development", "Development API endpoint", Severity::High),
    ("/staging", "Staging API endpoint", Severity::High),
    ("/stage", "Staging API endpoint", Severity::High),
    ("/beta", "Beta API endpoint", Severity::Medium),
    ("/alpha", "Alpha API endpoint", Severity::Medium),
    ("/internal", "Internal API endpoint", Severity::High),
    ("/private", "Private API endpoint", Severity::High),
    ("/debug", "Debug API endpoint", Severity::High),
    ("/test", "Test API endpoint", Severity::Medium),
    ("/sandbox", "Sandbox API endpoint", Severity::Medium),
    ("/preview", "Preview API endpoint", Severity::Low),
    ("/canary", "Canary release endpoint", Severity::Low),
    ("/api-test", "API test endpoint", Severity::Medium),
    ("/api-dev", "API dev endpoint", Severity::High),
    ("/api-internal", "Internal API endpoint", Severity::High),
];

pub async fn probe(client: &Client, target: &Target) -> anyhow::Result<Vec<Finding>> {
    let Target::Web(asset) = target else {
        return Ok(vec![]);
    };
    let base = asset.url.as_str().trim_end_matches('/');
    let mut findings = Vec::new();

    // First establish baseline: what does a guaranteed-missing path return?
    // Transport failure must abort enumeration — never silently assume 404
    // (that would treat SPA catch-all 200s as "new" active versions).
    let baseline_404 = match client
        .get(format!("{}/this-path-should-never-exist-9z3k2p", base))
        .send()
        .await
    {
        Ok(r) => r.status().as_u16(),
        Err(e) => {
            tracing::warn!(
                "api_versions baseline probe failed; aborting version/shadow enumeration: base={} error={}",
                base,
                e
            );
            return Ok(findings);
        }
    };

    // Version endpoint enumeration
    let mut found_versions: Vec<(String, u16, String)> = Vec::new();

    for path in VERSION_PATHS {
        let url = format!("{}{}", base, path);
        let Ok(resp) = client.get(&url).send().await else {
            tracing::warn!(url = %url, "api_versions: version path probe send failed");
            continue;
        };
        let status = resp.status().as_u16();
        let content_type = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let www_authenticate = resp
            .headers()
            .get(reqwest::header::WWW_AUTHENTICATE)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);

        // Skip if same as baseline (catchall 200 or consistent 404)
        if status == baseline_404 {
            continue;
        }
        if !is_active_status(status) {
            continue;
        }

        let body = gossan_core::net::bounded_text(resp, crate::MAX_BODY_BYTES)
            .await?;
        let body_excerpt: String = body.chars().take(crate::MAX_BODY_EXCERPT_CHARS).collect::<String>().into();

        // Must look like an API response, not a generic error page
        let looks_like_api = looks_like_api_response(
            &body_excerpt,
            status,
            content_type.as_deref(),
            www_authenticate.as_deref(),
        );

        if looks_like_api {
            found_versions.push((path.to_string(), status, body_excerpt));
        }
    }

    // Emit one finding listing all found old versions
    if !found_versions.is_empty() {
        let version_list: Vec<String> = found_versions
            .iter()
            .map(|(p, s, _)| format!("{} → HTTP {}", p, s))
            .collect();

        let oldest = found_versions
            .first()
            .map(|(p, _, _)| p.as_str())
            .unwrap_or("/v0");
        let (first_path, first_status, first_body) = &found_versions[0];

        gossan_core::try_push_finding(
            crate::exposure_finding(
                target,
                Severity::High,
                format!(
                    "API version enumeration: {} old version{} active",
                    found_versions.len(),
                    if found_versions.len() == 1 { "" } else { "s" }
                ),
                format!(
                    "Older API versions are reachable alongside the current version. \
                         Old versions frequently lack authentication improvements, rate limiting, \
                         and security patches applied to the current version. \
                         Found: {}",
                    version_list.join(", ")
                ),
            )
            .evidence(Evidence::HttpResponse {
                status: *first_status,
                headers: vec![("active-path".into(), first_path.clone().into())],
                body_excerpt: Some(first_body.clone().into()),
            })
            .tag("api-version")
            .tag("exposure")
            .exploit_hint(format!(
                "# Test authentication bypass on older version:\n\
                 curl -s '{base}{oldest}/users'  # may return data without auth\n\
                 curl -s '{base}{oldest}/admin'  # admin endpoints sometimes unprotected\n\
                 # Compare responses with current version:\n\
                 diff <(curl -s '{base}/v1/users') <(curl -s '{base}{oldest}/users')"
            )),
            &mut findings,
        );
    }

    // Shadow / non-production endpoint detection
    for (path, description, severity) in SHADOW_PATHS {
        let url = format!("{}{}", base, path);
        let Ok(resp) = client.get(&url).send().await else {
            tracing::warn!(url = %url, "api_versions: shadow endpoint probe send failed");
            continue;
        };
        let status = resp.status().as_u16();

        if status == baseline_404 || !is_active_status(status) {
            continue;
        }

        let body = gossan_core::net::bounded_text(resp, crate::MAX_BODY_BYTES)
            .await?;
        let excerpt: String = body.chars().take(crate::MAX_BODY_EXCERPT_CHARS).collect::<String>().into();

        let is_interesting = is_interesting_shadow_response(&excerpt, status);

        if is_interesting {
            gossan_core::try_push_finding(
                crate::exposure_finding(
                    target,
                    *severity,
                    format!("{} exposed: {}", description, path),
                    format!(
                        "The {} path at {}{} returned HTTP {}. \
                             Non-production environments typically have weaker auth, \
                             verbose errors, disabled WAF rules, and expose internal endpoints \
                             not available in production.",
                        description, base, path, status
                    ),
                )
                .evidence(Evidence::HttpResponse {
                    status,
                    headers: vec![],
                    body_excerpt: Some((excerpt).into()),
                })
                .tag("api-version")
                .tag("shadow-api")
                .tag("exposure")
                .exploit_hint(format!(
                    "# Explore shadow environment:\n\
                     ffuf -u '{base}{path}/FUZZ' -w api_wordlist.txt -mc 200,401,403"
                )),
                &mut findings,
            );
        }
    }

    Ok(findings)
}

fn is_active_status(status: u16) -> bool {
    matches!(status, 200..=299 | 401 | 403)
}

fn json_shaped_body(body_excerpt: &str) -> bool {
    let trimmed = body_excerpt.trim_start();
    trimmed.starts_with('{') || trimmed.starts_with('[')
}

fn content_type_is_json(content_type: Option<&str>) -> bool {
    content_type
        .map(|ct| {
            let lower = ct.to_ascii_lowercase();
            lower.contains("application/json") || lower.contains("+json")
        })
        .unwrap_or(false)
}

/// API proof for version paths: JSON body/content-type for 2xx; auth walls
/// need WWW-Authenticate or JSON — bare 401/403 alone is not enough.
fn looks_like_api_response(
    body_excerpt: &str,
    status: u16,
    content_type: Option<&str>,
    www_authenticate: Option<&str>,
) -> bool {
    let jsonish = json_shaped_body(body_excerpt) || content_type_is_json(content_type);
    if (200..=299).contains(&status) {
        return jsonish;
    }
    if status == 401 || status == 403 {
        let has_www_auth = www_authenticate
            .map(|v| !v.trim().is_empty())
            .unwrap_or(false);
        return has_www_auth || jsonish;
    }
    false
}

/// Unit-testable baseline gate: transport Err aborts (None), never defaults to 404.
fn baseline_status_from_probe(result: Result<u16, String>) -> Option<u16> {
    match result {
        Ok(status) => Some(status),
        Err(e) => {
            tracing::warn!(
                "api_versions baseline probe failed; aborting enumeration: error={}",
                e
            );
            None
        }
    }
}

fn is_interesting_shadow_response(excerpt: &str, status: u16) -> bool {
    excerpt.trim_start().starts_with('{')
        || excerpt.contains("debug")
        || excerpt.contains("stack")
        || excerpt.contains("error")
        || status == 401
        || status == 403
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn active_status_recognizes_success_and_auth_gates() {
        for status in [200, 204, 401, 403] {
            assert!(is_active_status(status), "status {status} should be active");
        }
        for status in [301, 404, 500] {
            assert!(
                !is_active_status(status),
                "status {status} should not be active"
            );
        }
    }

    #[test]
    fn looks_like_api_response_accepts_json_bodies() {
        assert!(looks_like_api_response("{\"message\":\"ok\"}", 200, None, None));
        assert!(looks_like_api_response("[{\"id\":1}]", 200, None, None));
    }

    #[test]
    fn looks_like_api_response_rejects_bare_auth_status_without_evidence() {
        assert!(!looks_like_api_response("", 401, None, None));
        assert!(!looks_like_api_response("", 403, None, None));
    }

    #[test]
    fn looks_like_api_response_accepts_auth_with_www_authenticate() {
        assert!(looks_like_api_response("", 401, None, Some("Bearer realm=\"api\"")));
        assert!(looks_like_api_response("", 403, None, Some("Basic realm=\"api\"")));
    }

    #[test]
    fn looks_like_api_response_accepts_auth_with_json_body() {
        assert!(looks_like_api_response("{\"error\":\"unauthorized\"}", 401, None, None));
        assert!(looks_like_api_response("{\"error\":\"forbidden\"}", 403, Some("application/json"), None));
    }

    #[test]
    fn looks_like_api_response_rejects_html_with_api_version_words() {
        let html = "<html><body>Welcome to our API version portal</body></html>";
        assert!(!looks_like_api_response(html, 200, Some("text/html"), None));
        assert!(!looks_like_api_response(html, 200, None, None));
    }

    #[test]
    fn looks_like_api_response_accepts_application_json_without_braces() {
        // Content-Type alone can prove API for 2xx (e.g. empty 204 JSON endpoints)
        assert!(looks_like_api_response("", 204, Some("application/json"), None));
        assert!(looks_like_api_response("ok", 200, Some("application/vnd.api+json"), None));
    }

    #[test]
    fn baseline_status_from_probe_aborts_on_err() {
        assert_eq!(baseline_status_from_probe(Ok(404)), Some(404));
        assert_eq!(baseline_status_from_probe(Ok(200)), Some(200));
        assert_eq!(
            baseline_status_from_probe(Err("connection reset".into())),
            None,
            "transport Err must abort, never default to 404"
        );
    }

    #[test]
    fn looks_like_api_response_rejects_plain_html() {
        assert!(!looks_like_api_response("<html>hello</html>", 200, None, None));
    }

    #[test]
    fn interesting_shadow_response_detects_debug_keywords() {
        assert!(is_interesting_shadow_response("debug stack trace", 200));
        assert!(is_interesting_shadow_response("{\"error\":\"nope\"}", 200));
    }

    #[test]
    fn interesting_shadow_response_uses_auth_status_as_signal() {
        assert!(is_interesting_shadow_response("not much here", 401));
        assert!(is_interesting_shadow_response("not much here", 403));
    }

    #[test]
    fn constants_cover_expected_version_and_shadow_paths() {
        assert!(VERSION_PATHS.contains(&"/v0"));
        assert!(VERSION_PATHS.contains(&"/api/v2.0"));
        assert!(SHADOW_PATHS.iter().any(|(path, _, _)| *path == "/debug"));
        assert!(SHADOW_PATHS
            .iter()
            .any(|(path, _, _)| *path == "/api-internal"));
    }

    #[test]
    fn version_paths_cover_v0_and_api_v3() {
        assert!(VERSION_PATHS.contains(&"/v0"));
        assert!(VERSION_PATHS.contains(&"/api/v3"));
    }

    #[test]
    fn shadow_paths_include_dev_and_staging() {
        assert!(SHADOW_PATHS.iter().any(|(p, _, _)| *p == "/dev"));
        assert!(SHADOW_PATHS.iter().any(|(p, _, _)| *p == "/staging"));
    }

    #[test]
    fn looks_like_api_response_accepts_version_keyword() {
        assert!(looks_like_api_response("{\"version\":\"1.0\"}", 200, None, None));
    }

    #[test]
    fn looks_like_api_response_accepts_api_keyword() {
        assert!(looks_like_api_response("{\"api\":\"v2\"}", 200, None, None));
    }

    #[test]
    fn is_interesting_shadow_response_detects_error_json() {
        assert!(is_interesting_shadow_response("{\"error\":\"not found\"}", 200));
    }

    #[test]
    fn version_paths_include_v00() {
        assert!(VERSION_PATHS.contains(&"/v00"));
    }

    #[test]
    fn version_paths_include_api_v01() {
        assert!(VERSION_PATHS.contains(&"/api/v0.1"));
    }

    #[test]
    fn shadow_paths_include_beta() {
        assert!(SHADOW_PATHS.iter().any(|(p, _, _)| *p == "/beta"));
    }

    #[test]
    fn shadow_paths_include_alpha() {
        assert!(SHADOW_PATHS.iter().any(|(p, _, _)| *p == "/alpha"));
    }

    #[test]
    fn is_active_status_rejects_301() {
        assert!(!is_active_status(301));
    }

    #[test]
    fn is_active_status_accepts_all_2xx() {
        for status in [200, 201, 202, 203, 204, 205, 206, 207, 208, 226] {
            assert!(is_active_status(status), "status {status} should be active");
        }
    }

    #[test]
    fn is_active_status_rejects_3xx() {
        for status in [300, 301, 302, 303, 304, 305, 307, 308] {
            assert!(!is_active_status(status), "status {status} should not be active");
        }
    }

    #[test]
    fn is_active_status_rejects_4xx_except_401_403() {
        for status in [400, 402, 404, 405, 406, 407, 408, 409, 410, 411, 412, 413, 414, 415, 416, 417, 418, 421, 422, 423, 424, 425, 426, 428, 429, 431, 451] {
            assert!(!is_active_status(status), "status {status} should not be active");
        }
    }

    #[test]
    fn is_active_status_rejects_all_5xx() {
        for status in [500, 501, 502, 503, 504, 505, 506, 507, 508, 510, 511] {
            assert!(!is_active_status(status), "status {status} should not be active");
        }
    }

    #[test]
    fn is_active_status_rejects_nonstandard() {
        assert!(!is_active_status(0));
        assert!(!is_active_status(1));
        assert!(!is_active_status(999));
    }

    #[test]
    fn looks_like_api_response_plain_html_false() {
        assert!(!looks_like_api_response("<html>hello</html>", 200, None, None));
    }

    #[test]
    fn looks_like_api_response_xml_false() {
        assert!(!looks_like_api_response("<?xml version='1.0'?><root></root>", 200, None, None));
    }

    #[test]
    fn looks_like_api_response_text_false() {
        assert!(!looks_like_api_response("just some text", 200, None, None));
    }

    #[test]
    fn looks_like_api_response_empty_401_without_www_auth_false() {
        assert!(!looks_like_api_response("", 401, None, None));
    }

    #[test]
    fn looks_like_api_response_empty_403_without_www_auth_false() {
        assert!(!looks_like_api_response("", 403, None, None));
    }

    #[test]
    fn looks_like_api_response_json_array_true() {
        assert!(looks_like_api_response("[{\"id\":1}]", 200, None, None));
    }

    #[test]
    fn looks_like_api_response_json_with_message_true() {
        assert!(looks_like_api_response("{\"message\":\"ok\"}", 200, None, None));
    }

    #[test]
    fn looks_like_api_response_json_with_error_true() {
        assert!(looks_like_api_response("{\"error\":\"nope\"}", 200, None, None));
    }

    #[test]
    fn looks_like_api_response_json_with_version_true() {
        assert!(looks_like_api_response("{\"version\":\"1.0\"}", 200, None, None));
    }

    #[test]
    fn looks_like_api_response_json_with_api_true() {
        assert!(looks_like_api_response("{\"api\":\"v2\"}", 200, None, None));
    }

    #[test]
    fn is_interesting_shadow_response_debug_keyword() {
        assert!(is_interesting_shadow_response("debug mode enabled", 200));
    }

    #[test]
    fn is_interesting_shadow_response_stack_keyword() {
        assert!(is_interesting_shadow_response("stack trace here", 200));
    }

    #[test]
    fn is_interesting_shadow_response_error_json() {
        assert!(is_interesting_shadow_response("{\"error\":\"not found\"}", 200));
    }

    #[test]
    fn is_interesting_shadow_response_plain_text_false() {
        assert!(!is_interesting_shadow_response("hello world", 200));
    }

    #[test]
    fn is_interesting_shadow_response_401_empty_true() {
        assert!(is_interesting_shadow_response("", 401));
    }

    #[test]
    fn is_interesting_shadow_response_403_empty_true() {
        assert!(is_interesting_shadow_response("", 403));
    }

    #[test]
    fn version_paths_include_v1_1() {
        assert!(VERSION_PATHS.contains(&"/v1.1"));
    }

    #[test]
    fn version_paths_include_v2_0() {
        assert!(VERSION_PATHS.contains(&"/v2.0"));
    }

    #[test]
    fn shadow_paths_include_sandbox() {
        assert!(SHADOW_PATHS.iter().any(|(p, _, _)| *p == "/sandbox"));
    }

    #[test]
    fn shadow_paths_include_preview() {
        assert!(SHADOW_PATHS.iter().any(|(p, _, _)| *p == "/preview"));
    }

    #[test]
    fn shadow_paths_include_canary() {
        assert!(SHADOW_PATHS.iter().any(|(p, _, _)| *p == "/canary"));
    }
}
