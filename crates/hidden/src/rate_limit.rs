//! Rate limit probe.
//!
//! Sends a burst of 12 requests to common authentication endpoints and
//! checks whether the server enforces any throttling (429, Retry-After,
//! increasing latency, or CAPTCHA challenges).
//!
//! No rate limiting on auth endpoints = credential brute force / stuffing
//! is trivially feasible without any friction.
//!
//! We test: POST /login, /api/login, /api/auth, /auth/token, /sign-in, etc.
//! with deliberately invalid credentials so we don't accidentally auth.

use gossan_core::Target;
use reqwest::Client;
use secfinding::{Evidence, Finding, Severity};
use std::time::Instant;

const AUTH_PATHS: &[&str] = &[
    "/login",
    "/signin",
    "/sign-in",
    "/api/login",
    "/api/signin",
    "/api/auth",
    "/api/auth/login",
    "/api/v1/login",
    "/api/v1/auth",
    "/api/v1/auth/login",
    "/auth/login",
    "/auth/token",
    "/user/login",
    "/users/login",
    "/account/login",
    "/session",
    "/sessions",
    "/token",
    "/oauth/token",
];

const BURST_COUNT: usize = 12;

// Statuses that, if consistent across a *complete* burst, indicate no
// HTTP-level rate limiting.  429/503 are treated as explicit throttling.
const RATE_LIMIT_ACCEPTED_STATUSES: &[u16] = &[400, 401, 403, 422, 200];

/// Returns true only when every request in the burst returned a response and all
/// responses are identical non-throttling statuses.  Incomplete bursts (e.g.
/// connection drops or timeouts, which are themselves common rate-limiting
/// reactions) must not be reported as "no rate limiting".
fn burst_suggests_no_rate_limit(statuses: &[u16]) -> bool {
    if statuses.len() != BURST_COUNT {
        return false;
    }
    let got_429 = statuses.contains(&429);
    let got_503 = statuses.contains(&503);
    let all_same = statuses.windows(2).all(|w| w[0] == w[1]);
    let first_status = statuses[0];
    !got_429 && !got_503 && all_same && RATE_LIMIT_ACCEPTED_STATUSES.contains(&first_status)
}

/// Detect a soft throttle by a late-request latency spike relative to the
/// burst average.
fn latency_increases(latencies: &[u128]) -> bool {
    if latencies.is_empty() {
        return false;
    }
    let avg = latencies.iter().sum::<u128>() / latencies.len() as u128;
    let last = latencies[latencies.len() - 1];
    last > avg * 3
}

// Dummy credentials that will never succeed but look realistic
const DUMMY_JSON: &str =
    r#"{"username":"probe-rate-limit@invalid.test","password":"!RateLimitProbe99"}"#;
const DUMMY_FORM: &str = "username=probe-rate-limit%40invalid.test&password=%21RateLimitProbe99";

pub async fn probe(client: &Client, target: &Target) -> anyhow::Result<Vec<Finding>> {
    let Target::Web(asset) = target else {
        return Ok(vec![]);
    };
    let base = asset.url.as_str().trim_end_matches('/');
    let mut findings = Vec::new();

    let soft404_base = crate::soft404::establish(client, base).await;

    // Find the first auth endpoint that returns something interesting
    // (400/401/422 on bad creds = auth endpoint found; 404 = skip)
    let mut endpoint: Option<(String, bool)> = None; // (url, is_json)

    for path in AUTH_PATHS {
        let url = format!("{}{}", base, path);

        // Try JSON first
        if let Ok(resp) = client
            .post(&url)
            .header("content-type", "application/json")
            .body(DUMMY_JSON)
            .send()
            .await
        {
            let s = resp.status().as_u16();
            if matches!(s, 400 | 401 | 403 | 422 | 429 | 200) {
                // If it returns 200/etc., confirm it's not a soft-404 catch-all
                let Some(bytes) =
                    crate::soft404::read_limited(resp, crate::MAX_BODY_BYTES).await
                else {
                    tracing::warn!(
                        "auth-endpoint body read failed or exceeded cap at {}; skipping soft-404 check",
                        url
                    );
                    continue;
                };
                if !crate::soft404::is_likely_404(s, &bytes, soft404_base.as_ref(), false) {
                    endpoint = Some((url, true));
                    break;
                }
            }
        }

        // Try form-encoded
        if let Ok(resp) = client
            .post(&url)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(DUMMY_FORM)
            .send()
            .await
        {
            let s = resp.status().as_u16();
            if matches!(s, 400 | 401 | 403 | 422 | 200) {
                let Some(bytes) =
                    crate::soft404::read_limited(resp, crate::MAX_BODY_BYTES).await
                else {
                    tracing::warn!(
                        "auth-endpoint body read failed or exceeded cap at {}; skipping soft-404 check",
                        url
                    );
                    continue;
                };
                if !crate::soft404::is_likely_404(s, &bytes, soft404_base.as_ref(), false) {
                    endpoint = Some((url, false));
                    break;
                }
            }
        }
    }

    let Some((auth_url, is_json)) = endpoint else {
        return Ok(findings);
    };

    // Extract just the path component for the title (scheme/port vary across
    // web targets; including them makes deduplication miss duplicates).
    let auth_path = reqwest::Url::parse(&auth_url)
        .map(|u| u.path().to_string())
        .unwrap_or_else(|_| auth_url.clone());

    // First request already hit a rate limit, good server
    if let Ok(resp) = client
        .post(&auth_url)
        .header(
            "content-type",
            if is_json {
                "application/json"
            } else {
                "application/x-www-form-urlencoded"
            },
        )
        .body(if is_json { DUMMY_JSON } else { DUMMY_FORM })
        .send()
        .await
    {
        if resp.status().as_u16() == 429 {
            return Ok(findings); // already rate limited, don't report
        }
    }

    // Fire the burst
    let body = if is_json { DUMMY_JSON } else { DUMMY_FORM };
    let ctype = if is_json {
        "application/json"
    } else {
        "application/x-www-form-urlencoded"
    };

    let mut statuses = Vec::new();
    let mut latencies = Vec::new();
    let t0 = Instant::now();

    for _ in 0..BURST_COUNT {
        let req_start = Instant::now();
        let resp = client
            .post(&auth_url)
            .header("content-type", ctype)
            .body(body)
            .send()
            .await;
        match resp {
            Ok(r) => {
                latencies.push(req_start.elapsed().as_millis());
                statuses.push(r.status().as_u16());
            }
            Err(e) => {
                tracing::warn!(
                    url = %auth_url,
                    error = %e,
                    "rate-limit burst request failed; excluding from burst sample"
                );
            }
        }
    }

    let _total_ms = t0.elapsed().as_millis();

    if statuses.is_empty() {
        return Ok(findings);
    }

    let last_status = *statuses.last().unwrap_or(&0);
    let first_status = statuses[0];

    // No rate limiting detected only when the full burst completed and all
    // responses are consistent non-throttling statuses.
    if burst_suggests_no_rate_limit(&statuses) {
        let avg_lat: u128 = latencies.iter().sum::<u128>() / latencies.len() as u128;
        let last_lat = *latencies.last().unwrap_or(&0);
        let lat_increase = latency_increases(&latencies); // 3× slowdown = soft throttle

        if lat_increase {
            gossan_core::try_push_finding(
                crate::misconfig_finding(
                    target,
                    Severity::Low,
                    format!(
                        "Auth endpoint soft rate limiting (latency increase): {}",
                        auth_path
                    ),
                    format!(
                        "{} responds with increasing latency under load (avg {}ms → last {}ms) \
                             but no HTTP 429. Some throttling exists but may be bypassable with \
                             distributed requests or IP rotation.",
                        auth_url, avg_lat, last_lat
                    ),
                )
                .tag("rate-limit")
                .tag("brute-force")
                .tag("web"),
                &mut findings,
            );
        } else {
            // Hard finding: no rate limiting at all
            gossan_core::try_push_finding(
                crate::misconfig_finding(
                    target,
                    Severity::High,
                    format!("No rate limiting on authentication endpoint: {}", auth_path),
                    format!(
                        "{} returned HTTP {} for all {} rapid login attempts with no \
                             throttling, 429, or increasing latency. An attacker can perform \
                             unlimited credential brute force or stuffing attacks at full network \
                             speed: thousands of attempts per second from a single IP.",
                        auth_url, first_status, BURST_COUNT
                    ),
                )
                .evidence(Evidence::HttpResponse {
                    status: last_status,
                    headers: vec![
                        ("requests-sent".into(), BURST_COUNT.to_string().into()),
                        ("all-returned".into(), first_status.to_string().into()),
                    ],
                    body_excerpt: Some(
                        format!("All {} responses: HTTP {}", BURST_COUNT, first_status).into(),
                    ),
                })
                .tag("rate-limit")
                .tag("brute-force")
                .tag("web")
                .exploit_hint(format!(
                    "# Credential stuffing (no rate limit):\n\
                     hydra -L users.txt -P passwords.txt -s 443 -S {} http-post-form \\\n  \
                     '{}:username=^USER^&password=^PASS^:F=401' -t 50",
                    base.split("://").nth(1).unwrap_or(base),
                    auth_url
                )),
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
    fn auth_paths_include_login() {
        assert!(AUTH_PATHS.contains(&"/login"));
        assert!(AUTH_PATHS.contains(&"/api/login"));
    }

    #[test]
    fn auth_paths_include_oauth_token() {
        assert!(AUTH_PATHS.contains(&"/oauth/token"));
    }

    #[test]
    fn auth_paths_count_is_reasonable() {
        assert!(
            AUTH_PATHS.len() >= 10,
            "expected >=10 auth paths, got {}",
            AUTH_PATHS.len()
        );
    }

    #[test]
    fn dummy_json_contains_probe_username() {
        assert!(DUMMY_JSON.contains("probe-rate-limit@invalid.test"));
    }

    #[test]
    fn dummy_form_contains_probe_username() {
        assert!(DUMMY_FORM.contains("probe-rate-limit%40invalid.test"));
    }

    #[test]
    fn auth_paths_include_session() {
        assert!(AUTH_PATHS.contains(&"/session"));
        assert!(AUTH_PATHS.contains(&"/sessions"));
    }

    #[test]
    fn auth_paths_include_token() {
        assert!(AUTH_PATHS.contains(&"/token"));
    }

    #[test]
    fn dummy_json_has_password() {
        assert!(DUMMY_JSON.contains("!RateLimitProbe99"));
    }

    #[test]
    fn dummy_form_has_password() {
        assert!(DUMMY_FORM.contains("%21RateLimitProbe99"));
    }

    #[test]
    fn auth_paths_count_exceeds_fifteen() {
        assert!(AUTH_PATHS.len() > 15, "expected >15 auth paths, got {}", AUTH_PATHS.len());
    }

    #[test]
    fn incomplete_burst_is_not_no_rate_limit() {
        // Old behaviour: an 11-response burst of identical 401s would be
        // reported as "no rate limiting".  Connection drops/timeouts are
        // themselves a rate-limiting signal, so incomplete bursts are
        // inconclusive.
        let statuses = vec![401; BURST_COUNT - 1];
        assert!(!burst_suggests_no_rate_limit(&statuses));
    }

    #[test]
    fn complete_burst_all_401_suggests_no_rate_limit() {
        let statuses = vec![401; BURST_COUNT];
        assert!(burst_suggests_no_rate_limit(&statuses));
    }

    #[test]
    fn complete_burst_with_429_is_not_unlimited() {
        let mut statuses = vec![401; BURST_COUNT - 1];
        statuses.push(429);
        assert!(!burst_suggests_no_rate_limit(&statuses));
    }

    #[test]
    fn complete_burst_all_200_suggests_no_rate_limit() {
        let statuses = vec![200; BURST_COUNT];
        assert!(burst_suggests_no_rate_limit(&statuses));
    }

    #[test]
    fn mixed_statuses_are_not_unlimited() {
        let statuses = vec![401, 401, 401, 401, 403, 401, 401, 401, 401, 401, 401, 401];
        assert!(!burst_suggests_no_rate_limit(&statuses));
    }

    #[test]
    fn empty_burst_is_not_unlimited() {
        assert!(!burst_suggests_no_rate_limit(&[]));
    }

    #[test]
    fn latency_increases_detects_late_spike() {
        let latencies = vec![10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 500];
        assert!(latency_increases(&latencies));
    }

    #[test]
    fn latency_increases_false_when_flat() {
        let latencies = vec![10; BURST_COUNT];
        assert!(!latency_increases(&latencies));
    }

    #[test]
    fn latency_increases_false_for_empty() {
        assert!(!latency_increases(&[]));
    }
}
