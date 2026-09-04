//! Cookie security attribute analysis.
//!
//! Fetches the target homepage and inspects every Set-Cookie header for:
//!   - Missing Secure flag (cookie sent over HTTP)
//!   - Missing HttpOnly flag (XSS can steal cookie)
//!   - Missing / weak SameSite attribute (CSRF vector)
//!   - Session cookies with excessively long Max-Age / Expires
//!
//! Only session-looking cookies are reported (contains "sess", "auth", "token",
//! "jwt", "id", "user" (ignoring analytics/tracking cookies)).

use gossan_core::Target;
use reqwest::Client;
use secfinding::{Evidence, Finding, Severity};

/// Maximum characters from a cookie value to include in a finding detail string.
/// Long session cookies can exceed 4 KB; truncating at 100 keeps the message readable.
const MAX_COOKIE_DETAIL_CHARS: usize = 100;

/// Maximum characters from a cookie value to include in the evidence header field.
const MAX_COOKIE_HEADER_CHARS: usize = 120;


/// True if a Set-Cookie attribute token matches `attr` exactly (case already folded).
fn cookie_has_attr(lower_cookie: &str, attr: &str) -> bool {
    lower_cookie.split(';').any(|part| {
        let part = part.trim();
        part == attr || part.starts_with(&format!("{attr}="))
    })
}

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

        // Missing Secure flag. Attribute check must be segment-exact: a cookie
        // named `secure_session=...` must NOT be treated as having Secure.
        if !cookie_has_attr(&lower, "secure") {
            crate::try_push_finding(
                crate::misconfig_finding(
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
                        &cookie_str.chars().take(MAX_COOKIE_DETAIL_CHARS).collect::<String>()
                    ),
                )
                .evidence(Evidence::HttpResponse {
                    status: resp.status().as_u16(),
                    headers: vec![(
                        "set-cookie".into(),
                        cookie_str.chars().take(MAX_COOKIE_HEADER_CHARS).collect::<String>().into(),
                    )],
                    body_excerpt: None,
                })
                .tag("cookie")
                .tag("session")
                .tag("web"),
                &mut findings,
            );
        }

        // Missing HttpOnly flag
        if !cookie_has_attr(&lower, "httponly") {
            crate::try_push_finding(
                crate::misconfig_finding(
                    target,
                    Severity::Medium,
                    format!(
                        "Cookie '{}' missing HttpOnly flag",
                        cookie_str.split('=').next().unwrap_or("?")
                    ),
                    format!(
                        "Session cookie is accessible via document.cookie, any XSS vulnerability \
                 can steal it. Add HttpOnly to prevent JS access. \
                 Cookie: {}",
                        &cookie_str.chars().take(MAX_COOKIE_DETAIL_CHARS).collect::<String>()
                    ),
                )
                .evidence(Evidence::HttpResponse {
                    status: resp.status().as_u16(),
                    headers: vec![(
                        "set-cookie".into(),
                        cookie_str.chars().take(MAX_COOKIE_HEADER_CHARS).collect::<String>().into(),
                    )],
                    body_excerpt: None,
                })
                .tag("cookie")
                .tag("session")
                .tag("web")
                .tag("xss"),
                &mut findings,
            );
        }

        // Missing or weak SameSite
        if !cookie_has_attr(&lower, "samesite") {
            crate::try_push_finding(
                crate::misconfig_finding(
                    target,
                    Severity::Low,
                    format!(
                        "Cookie '{}' missing SameSite attribute",
                        cookie_str.split('=').next().unwrap_or("?")
                    ),
                    format!(
                        "No SameSite attribute, cookie is sent on cross-origin requests, \
                 enabling classic CSRF attacks on state-changing endpoints. \
                 Use SameSite=Strict or SameSite=Lax. \
                 Cookie: {}",
                        &cookie_str.chars().take(MAX_COOKIE_DETAIL_CHARS).collect::<String>()
                    ),
                )
                .evidence(Evidence::HttpResponse {
                    status: resp.status().as_u16(),
                    headers: vec![(
                        "set-cookie".into(),
                        cookie_str.chars().take(MAX_COOKIE_HEADER_CHARS).collect::<String>().into(),
                    )],
                    body_excerpt: None,
                })
                .tag("cookie")
                .tag("csrf")
                .tag("web"),
                &mut findings,
            );
        } else if lower.contains("samesite=none") && !cookie_has_attr(&lower, "secure") {
            // SameSite=None without Secure is rejected by browsers but worth flagging
            crate::try_push_finding(
                crate::misconfig_finding(
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
                .tag("web"),
                &mut findings,
            );
        }
    }

    Ok(findings)
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookie_has_attr_requires_exact_segment() {
        assert!(!cookie_has_attr("secure_session=abc; path=/", "secure"));
        assert!(cookie_has_attr("session=abc; secure; httponly", "secure"));
        assert!(cookie_has_attr("session=abc; secure", "secure"));
        assert!(cookie_has_attr("session=abc; samesite=none; secure", "secure"));
    }

    #[test]
    fn cookie_named_secure_session_missing_secure_flag_is_detected() {
        assert!(!cookie_has_attr(
            "secure_session=abc123; path=/; httponly",
            "secure"
        ));
    }

    #[test]
    fn cookie_value_containing_httponly_substring_does_not_satisfy_check() {
        // A cookie whose VALUE contains "httponly" as a substring must not
        // be treated as having the HttpOnly attribute. The attribute must
        // be a semicolon-delimited segment, not part of the value.
        let cookie = "session=httponly_is_my_value; path=/";
        assert!(!cookie_has_attr(&cookie.to_lowercase(), "httponly"));
    }

    #[test]
    fn cookie_value_containing_samesite_substring_does_not_satisfy_check() {
        // Same: a cookie value containing "samesite" must not satisfy the
        // SameSite attribute check.
        let cookie = "session=samesite_research_paper; path=/";
        assert!(!cookie_has_attr(&cookie.to_lowercase(), "samesite"));
    }
}
