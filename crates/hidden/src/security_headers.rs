//! Security header checks: HSTS, X-Frame-Options, X-Content-Type-Options, etc.

use gossan_core::Target;
use reqwest::Client;
use secfinding::{Evidence, Finding, Severity};

/// Check for missing or weak security headers on HTTPS endpoints.
pub async fn probe(client: &Client, target: &Target) -> anyhow::Result<Vec<Finding>> {
    let Target::Web(asset) = target else {
        return Ok(vec![]);
    };

    // Only check HTTPS endpoints
    if asset.url.scheme() != "https" {
        return Ok(vec![]);
    }

    let mut findings = Vec::new();
    let base = asset.url.as_str();

    let Ok(resp) = client.get(base).send().await else {
        return Ok(findings);
    };

    let headers = resp.headers();
    let status = resp.status().as_u16();

    // ── HSTS (Strict-Transport-Security) ────────────────────────────────
    let hsts = headers
        .get("strict-transport-security")
        .and_then(|v| v.to_str().ok());

    match hsts {
        None => {
            gossan_core::try_push_finding(
                crate::misconfig_finding(
                    target,
                    Severity::Medium,
                    "Missing HSTS header",
                    "The HTTPS endpoint does not set Strict-Transport-Security.                      Users can be downgraded to HTTP via SSL stripping attacks.                      Fix: add `Strict-Transport-Security: max-age=31536000; includeSubDomains`.",
                )
                .evidence(Evidence::HttpResponse {
                    status,
                    headers: vec![],
                    body_excerpt: None,
                })
                .tag("hsts")
                .tag("web")
                .tag("headers"),
                &mut findings,
            );
        }
        Some(val) => {
            // Check for weak max-age (< 6 months = 15768000 seconds)
            let max_age = val
                .split(';')
                .find_map(|part| {
                    let part = part.trim().to_lowercase();
                    part.strip_prefix("max-age=")
                        .and_then(|v| v.trim().parse::<u64>().ok())
                })
                .unwrap_or(0);

            if max_age < 15_768_000 {
                gossan_core::try_push_finding(
                    crate::misconfig_finding(
                        target,
                        Severity::Low,
                        "Weak HSTS max-age",
                        format!(
                            "HSTS max-age is {max_age} seconds ({:.1} days).                              Recommended minimum is 15768000 (6 months).                              Fix: increase max-age to at least 31536000 (1 year).",
                            max_age as f64 / 86400.0
                        ),
                    )
                    .evidence(Evidence::HttpResponse {
                        status,
                        headers: vec![("strict-transport-security".into(), val.to_string().into())],
                        body_excerpt: None,
                    })
                    .tag("hsts")
                    .tag("web")
                    .tag("headers"),
                    &mut findings,
                );
            }
        }
    }

    // ── X-Frame-Options ─────────────────────────────────────────────────
    if headers.get("x-frame-options").is_none()
        && headers.get("content-security-policy")
            .and_then(|v| v.to_str().ok())
            .map_or(true, |csp| !csp.contains("frame-ancestors"))
    {
        gossan_core::try_push_finding(
            crate::misconfig_finding(
                target,
                Severity::Low,
                "Missing clickjacking protection",
                "Neither X-Frame-Options nor CSP frame-ancestors is set.                  The page can be embedded in iframes on attacker-controlled sites.                  Fix: add `X-Frame-Options: DENY` or `Content-Security-Policy: frame-ancestors 'none'`.",
            )
            .evidence(Evidence::HttpResponse {
                status,
                headers: vec![],
                body_excerpt: None,
            })
            .tag("clickjacking")
            .tag("web")
            .tag("headers"),
            &mut findings,
        );
    }

    // ── X-Content-Type-Options ──────────────────────────────────────────
    if headers.get("x-content-type-options").is_none() {
        gossan_core::try_push_finding(
            crate::misconfig_finding(
                target,
                Severity::Info,
                "Missing X-Content-Type-Options: nosniff",
                "The server does not set X-Content-Type-Options: nosniff.                  Browsers may MIME-sniff responses, potentially executing uploaded                  files as scripts. Fix: add `X-Content-Type-Options: nosniff`.",
            )
            .evidence(Evidence::HttpResponse {
                status,
                headers: vec![],
                body_excerpt: None,
            })
            .tag("mime-sniffing")
            .tag("web")
            .tag("headers"),
            &mut findings,
        );
    }

    Ok(findings)
}
