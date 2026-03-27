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

    // First establish baseline: what does the root API return?
    // We consider a path "active" if it returns 2xx, 401, or 403
    // (400 might mean wrong method/content-type, but 404 = not found)
    let baseline_404 = if let Ok(r) = client
        .get(format!("{}/this-path-should-never-exist-9z3k2p", base))
        .send()
        .await
    {
        r.status().as_u16()
    } else {
        404
    };

    // Version endpoint enumeration
    let mut found_versions: Vec<(String, u16, String)> = Vec::new();

    for path in VERSION_PATHS {
        let url = format!("{}{}", base, path);
        let Ok(resp) = client.get(&url).send().await else {
            continue;
        };
        let status = resp.status().as_u16();

        // Skip if same as baseline (catchall 200 or consistent 404)
        if status == baseline_404 {
            continue;
        }
        if !is_active_status(status) {
            continue;
        }

        let body = resp.text().await.unwrap_or_default();
        let body_excerpt: String = body.chars().take(200).collect();

        // Must look like an API response, not a generic error page
        let looks_like_api = looks_like_api_response(&body_excerpt, status);

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

        findings.push(
            crate::finding_builder(
                target,
                Severity::High,
                format!(
                    "API version enumeration — {} old version{} active",
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
                headers: vec![("active-path".into(), first_path.clone())],
                body_excerpt: Some(first_body.clone()),
            })
            .tag("api-version")
            .tag("exposure")
            .exploit_hint(format!(
                "# Test authentication bypass on older version:\n\
                 curl -s '{base}{oldest}/users'  # may return data without auth\n\
                 curl -s '{base}{oldest}/admin'  # admin endpoints sometimes unprotected\n\
                 # Compare responses with current version:\n\
                 diff <(curl -s '{base}/v1/users') <(curl -s '{base}{oldest}/users')"
            ))
            .build()
            .expect("finding builder: required fields are set"),
        );
    }

    // Shadow / non-production endpoint detection
    for (path, description, severity) in SHADOW_PATHS {
        let url = format!("{}{}", base, path);
        let Ok(resp) = client.get(&url).send().await else {
            continue;
        };
        let status = resp.status().as_u16();

        if status == baseline_404 || !is_active_status(status) {
            continue;
        }

        let body = resp.text().await.unwrap_or_default();
        let excerpt: String = body.chars().take(200).collect();

        let is_interesting = is_interesting_shadow_response(&excerpt, status);

        if is_interesting {
            findings.push(
                crate::finding_builder(
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
                    body_excerpt: Some(excerpt),
                })
                .tag("api-version")
                .tag("shadow-api")
                .tag("exposure")
                .exploit_hint(format!(
                    "# Explore shadow environment:\n\
                     ffuf -u '{base}{path}/FUZZ' -w api_wordlist.txt -mc 200,401,403"
                ))
                .build()
                .expect("finding builder: required fields are set"),
            );
        }
    }

    Ok(findings)
}

fn is_active_status(status: u16) -> bool {
    matches!(status, 200..=299 | 401 | 403)
}

fn looks_like_api_response(body_excerpt: &str, status: u16) -> bool {
    body_excerpt.trim_start().starts_with('{')
        || body_excerpt.trim_start().starts_with('[')
        || body_excerpt.contains("\"message\"")
        || body_excerpt.contains("\"error\"")
        || body_excerpt.contains("\"version\"")
        || body_excerpt.contains("\"api\"")
        || status == 401
        || status == 403
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
        assert!(looks_like_api_response("{\"message\":\"ok\"}", 200));
        assert!(looks_like_api_response("[{\"id\":1}]", 200));
    }

    #[test]
    fn looks_like_api_response_accepts_auth_status_without_body() {
        assert!(looks_like_api_response("", 401));
        assert!(looks_like_api_response("", 403));
    }

    #[test]
    fn looks_like_api_response_rejects_plain_html() {
        assert!(!looks_like_api_response("<html>hello</html>", 200));
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
}
