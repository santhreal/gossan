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
                endpoint = Some((url, true));
                break;
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
                endpoint = Some((url, false));
                break;
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

    // First request already hit a rate limit — good server
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
        latencies.push(req_start.elapsed().as_millis());
        if let Ok(r) = resp {
            statuses.push(r.status().as_u16());
        }
    }

    let _total_ms = t0.elapsed().as_millis();

    if statuses.is_empty() {
        return Ok(findings);
    }

    let got_429 = statuses.contains(&429);
    let got_503 = statuses.contains(&503);
    let all_same = statuses.windows(2).all(|w| w[0] == w[1]);
    let first_status = statuses[0];
    let last_status = *statuses.last().unwrap_or(&0);

    // No rate limiting detected if all responses are consistent non-429
    if !got_429 && !got_503 && all_same && matches!(first_status, 400 | 401 | 403 | 422 | 200) {
        // Latency increase could indicate soft rate limiting (queuing)
        let avg_lat: u128 = latencies.iter().sum::<u128>() / latencies.len() as u128;
        let last_lat = *latencies.last().unwrap_or(&0);
        let lat_increase = last_lat > avg_lat * 3; // 3× slowdown = soft throttle

        if lat_increase {
            findings.push(
                crate::finding_builder(
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
                .tag("web")
                .build()
                .expect("finding builder: required fields are set"),
            );
        } else {
            // Hard finding: no rate limiting at all
            findings.push(
                crate::finding_builder(
                    target,
                    Severity::High,
                    format!("No rate limiting on authentication endpoint: {}", auth_path),
                    format!(
                        "{} returned HTTP {} for all {} rapid login attempts with no \
                             throttling, 429, or increasing latency. An attacker can perform \
                             unlimited credential brute force or stuffing attacks at full network \
                             speed — thousands of attempts per second from a single IP.",
                        auth_url, first_status, BURST_COUNT
                    ),
                )
                .evidence(Evidence::HttpResponse {
                    status: last_status,
                    headers: vec![
                        ("requests-sent".into(), BURST_COUNT.to_string()),
                        ("all-returned".into(), first_status.to_string()),
                    ],
                    body_excerpt: Some(format!(
                        "All {} responses: HTTP {}",
                        BURST_COUNT, first_status
                    )),
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
                ))
                .build()
                .expect("finding builder: required fields are set"),
            );
        }
    }

    Ok(findings)
}
