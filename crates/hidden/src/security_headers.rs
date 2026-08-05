//! Security header checks: HSTS, X-Frame-Options, X-Content-Type-Options, etc.

use gossan_core::Target;
use reqwest::Client;
use secfinding::{Evidence, Finding, Severity};

/// True when CSP includes a `frame-ancestors` directive (case-insensitive).
fn csp_has_frame_ancestors(csp: &str) -> bool {
    csp.to_ascii_lowercase().contains("frame-ancestors")
}

/// True when neither X-Frame-Options nor CSP frame-ancestors is present.
fn missing_clickjacking_protection(
    has_x_frame_options: bool,
    csp: Option<&str>,
) -> bool {
    if has_x_frame_options {
        return false;
    }
    match csp {
        Some(val) => !csp_has_frame_ancestors(val),
        None => true,
    }
}

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

    let resp = match client.get(base).send().await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("security_headers: request failed url={base} error={e}");
            return Ok(findings);
        }
    };

    let headers = resp.headers();
    let status = resp.status().as_u16();

    // ── HSTS (Strict-Transport-Security) ────────────────────────────────
    let hsts = headers
        .get("strict-transport-security")
        .and_then(|v| match v.to_str() {
            Ok(s) => Some(s),
            Err(e) => {
                tracing::warn!("security_headers: invalid HSTS header bytes error={e}");
                None
            }
        });

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

    // ── X-Frame-Options / CSP frame-ancestors (case-insensitive) ─────────
    let csp = headers
        .get("content-security-policy")
        .and_then(|v| match v.to_str() {
            Ok(s) => Some(s),
            Err(e) => {
                tracing::warn!("security_headers: invalid CSP header bytes error={e}");
                None
            }
        });
    if missing_clickjacking_protection(headers.get("x-frame-options").is_some(), csp) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csp_has_frame_ancestors_case_insensitive() {
        assert!(csp_has_frame_ancestors("frame-ancestors 'none'"));
        assert!(csp_has_frame_ancestors("Frame-Ancestors 'none'"));
        assert!(csp_has_frame_ancestors("FRAME-ANCESTORS 'self'"));
        assert!(csp_has_frame_ancestors(
            "default-src 'self'; Frame-Ancestors 'none'; script-src 'self'"
        ));
        assert!(!csp_has_frame_ancestors("default-src 'self'"));
        assert!(!csp_has_frame_ancestors(""));
    }

    /// Adversarial: mixed-case Frame-Ancestors must count as clickjacking protection.
    #[test]
    fn frame_ancestors_mixed_case_not_missing_clickjacking() {
        assert!(!missing_clickjacking_protection(
            false,
            Some("Frame-Ancestors 'none'")
        ));
        assert!(!missing_clickjacking_protection(
            false,
            Some("default-src 'self'; FRAME-ANCESTORS 'self'")
        ));
        assert!(missing_clickjacking_protection(false, Some("default-src 'self'")));
        assert!(missing_clickjacking_protection(false, None));
        assert!(!missing_clickjacking_protection(true, None));
        assert!(!missing_clickjacking_protection(
            true,
            Some("Frame-Ancestors 'none'")
        ));
    }
}
