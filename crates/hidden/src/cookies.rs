//! Cookie security attribute analysis.
//!
//! Fetches the target homepage and inspects every Set-Cookie header for:
//!   - Missing Secure flag (cookie sent over HTTP)
//!   - Missing HttpOnly flag (XSS can steal cookie)
//!   - Missing / weak SameSite attribute (CSRF vector)
//!   - Session cookies with excessively long Max-Age / Expires
//!
//! Only session-looking cookies are reported (contains "sess", "auth", "token",
//! "jwt", "id", "user" — ignoring analytics/tracking cookies).

use gossan_core::Target;
use reqwest::Client;
use secfinding::{Evidence, Finding, Severity};

pub async fn probe(client: &Client, target: &Target) -> anyhow::Result<Vec<Finding>> {
    let Target::Web(asset) = target else {
        return Ok(vec![]);
    };
    let base = asset.url.as_str();
    let mut findings = Vec::new();

    let resp = client.get(base).send().await?;
    let headers = resp.headers().clone();

    // Collect all Set-Cookie header values
    let cookies: Vec<String> = headers
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok().map(|s| s.to_string()))
        .collect();

    for cookie_str in &cookies {
        let lower = cookie_str.to_lowercase();

        // Only flag cookies that look session-related
        let name = cookie_str
            .split('=')
            .next()
            .unwrap_or("")
            .trim()
            .to_lowercase();
        let is_session_cookie = name.contains("sess")
            || name.contains("auth")
            || name.contains("token")
            || name.contains("jwt")
            || name.contains("sid")
            || name.contains("user")
            || name.contains("login")
            || name.contains("uid")
            || name.contains("access")
            || name.contains("refresh")
            || name.contains("remember");

        if !is_session_cookie {
            continue;
        }

        // Missing Secure flag
        if !lower.contains("; secure") && !lower.starts_with("secure") {
            findings.push(
                crate::finding_builder(
                    target,
                    Severity::Medium,
                    format!(
                        "Cookie '{}' missing Secure flag",
                        cookie_str.split('=').next().unwrap_or("?")
                    ),
                    format!(
                        "Session cookie is transmitted over HTTP as well as HTTPS. \
                             Network-layer attackers (MITM, coffee shop) can steal the session. \
                             Cookie: {}",
                        &cookie_str.chars().take(100).collect::<String>()
                    ),
                )
                .evidence(Evidence::HttpResponse {
                    status: resp.status().as_u16(),
                    headers: vec![("set-cookie".into(), cookie_str.chars().take(120).collect())],
                    body_excerpt: None,
                })
                .tag("cookie")
                .tag("session")
                .tag("web")
                .build()
                .expect("finding builder: required fields are set"),
            );
        }

        // Missing HttpOnly flag
        if !lower.contains("httponly") {
            findings.push(
                crate::finding_builder(
                    target,
                    Severity::Medium,
                    format!(
                        "Cookie '{}' missing HttpOnly flag",
                        cookie_str.split('=').next().unwrap_or("?")
                    ),
                    format!(
                        "Session cookie is accessible via document.cookie — any XSS vulnerability \
                             can steal it. Add HttpOnly to prevent JS access. \
                             Cookie: {}",
                        &cookie_str.chars().take(100).collect::<String>()
                    ),
                )
                .evidence(Evidence::HttpResponse {
                    status: resp.status().as_u16(),
                    headers: vec![("set-cookie".into(), cookie_str.chars().take(120).collect())],
                    body_excerpt: None,
                })
                .tag("cookie")
                .tag("session")
                .tag("web")
                .tag("xss")
                .build()
                .expect("finding builder: required fields are set"),
            );
        }

        // Missing or weak SameSite
        if !lower.contains("samesite") {
            findings.push(
                crate::finding_builder(
                    target,
                    Severity::Low,
                    format!(
                        "Cookie '{}' missing SameSite attribute",
                        cookie_str.split('=').next().unwrap_or("?")
                    ),
                    format!(
                        "No SameSite attribute — cookie is sent on cross-origin requests, \
                             enabling classic CSRF attacks on state-changing endpoints. \
                             Use SameSite=Strict or SameSite=Lax. \
                             Cookie: {}",
                        &cookie_str.chars().take(100).collect::<String>()
                    ),
                )
                .evidence(Evidence::HttpResponse {
                    status: resp.status().as_u16(),
                    headers: vec![("set-cookie".into(), cookie_str.chars().take(120).collect())],
                    body_excerpt: None,
                })
                .tag("cookie")
                .tag("csrf")
                .tag("web")
                .build()
                .expect("finding builder: required fields are set"),
            );
        } else if lower.contains("samesite=none") && !lower.contains("; secure") {
            // SameSite=None without Secure is rejected by browsers but worth flagging
            findings.push(
                crate::finding_builder(
                    target,
                    Severity::Low,
                    format!(
                        "Cookie '{}' SameSite=None without Secure",
                        cookie_str.split('=').next().unwrap_or("?")
                    ),
                    "SameSite=None requires the Secure flag or browsers will reject the cookie. \
                     This is a misconfiguration that can cause auth failures.",
                )
                .tag("cookie")
                .tag("web")
                .build()
                .expect("finding builder: required fields are set"),
            );
        }
    }

    Ok(findings)
}
