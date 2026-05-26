//! End-to-end proof against a LOCAL deliberately-vulnerable web app.
//!
//! This is the test that proves the product works the way an operator
//! runs it: the REAL `gossan` binary, driven over the CLI, against a
//! live HTTP server that plants concrete, well-known vulnerabilities.
//! Every planted vuln has a positive assertion (gossan MUST find it);
//! a parallel CLEAN server proves precision (gossan must stay quiet on
//! a properly-configured site). The harness pins the JSON contract
//! (exit 0, parseable findings array).
//!
//! The server binds an ephemeral port; this only works because the
//! standalone web commands now honour an explicit port + treat an
//! operator-directed endpoint as web (`parse_seed_endpoint` /
//! `is_web` banner)  -  the exact fixes for a real :8443 target that
//! "found nothing".

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::Command;
use std::thread;
use std::time::Duration;

fn cli_bin() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_gossan"))
}

// Realistic, non-placeholder secrets. These must EXACTLY match the
// shape each keyhog detector requires, or the (correctly precise)
// engine will not fire and the planted vuln silently goes undetected
// while a multi-needle assert still passes on a sibling secret  - 
// masking the gap. Two historical fixture defects this caught:
//   * GitHub classic PAT is `ghp_` + EXACTLY 36 alnum; the old value
//     had 35 body chars → never matched.
//   * keyhog's placeholder allowlist rejects any credential containing
//     "fake"; the old GOOGLE_API literally embedded "fake" → never
//     matched.
// Lengths/charsets below are pinned to the real detector regexes.
const GH_PAT: &str = "ghp_aB3dE6gH9jK2mN5pQ8sT1vW4xZ7bC0dE3fGh"; // ghp_ + 36
const SLACK_BOT: &str = "xoxb-2483649234567-2483649234999-aBcDeFgHiJkLmNoPqRsTuVwX";
const STRIPE_LIVE: &str = "sk_live_4eC39HqLyjWDarjtT1zdp7dcIADENT";
const AWS_AKID: &str = "AKIA5XYZ7QJ3KLMN4PQR";
const GOOGLE_API: &str = "AIzaSyB9xQ2Kv7Lm3Np5Rt8Wd0Zc1Ab4Ef6Gh9j"; // AIza + 35, no "fake"

/// Vulnerable-app routes. `(status, content_type, body)`.
fn vuln_body(path: &str, method: &str, query: &str) -> (u16, &'static str, String) {
    if query.contains("473*337") || query.contains("473%2A337") {
        return (200, "text/html", "computed result: 159401 done".into());
    }
    match (method, path) {
        ("GET", "/") => (
            200,
            "text/html",
            format!(
                "<!doctype html><html><head><title>Acme</title>\
                 <meta name=\"generator\" content=\"WordPress 6.1.1\">\
                 <link rel=\"modulepreload\" href=\"/static/spa-bundle.js\"></head><body>\
                 <script>window.__CFG={{ghToken:\"{GH_PAT}\",aws:\"{AWS_AKID}\",\
                 api:\"/api/v2/internal/users\"}};</script>\
                 <script id=\"__NEXT_DATA__\" type=\"application/json\">\
                 {{\"props\":{{\"slackToken\":\"{SLACK_BOT}\"}}}}</script>\
                 <div data-stripe-key=\"{STRIPE_LIVE}\"></div>\
                 <script src=\"/static/app.js\"></script>\
                 <form action=\"/login\" method=\"post\">\
                 <input name=\"username\" type=\"text\">\
                 <input name=\"password\" type=\"password\">\
                 <input name=\"csrf\" type=\"hidden\"></form>\
                 <a href=\"/admin\">admin</a><a href=\"/dashboard?id=1\">d</a></body></html>"
            ),
        ),
        ("GET", "/static/app.js") => (
            200,
            "application/javascript",
            format!(
                "const STRIPE=\"{STRIPE_LIVE}\";const SLACK=\"{SLACK_BOT}\";\
                 const G=\"{GOOGLE_API}\";\
                 export const api=(p)=>fetch('/api/v2/internal/'+p);\
                 fetch('/api/admin/secrets');fetch('/internal/metrics');\
                 //# sourceMappingURL=app.js.map"
            ),
        ),
        ("GET", "/static/app.js.map") => (
            200,
            "application/json",
            "{\"version\":3,\"sources\":[\"src/secret_config.ts\"],\
             \"sourcesContent\":[\"export const DB='postgres://app:Sup3rPw@db'\"]}".into(),
        ),
        // RECALL (CONTINUATION-2 chain, proven e2e): a modern-SPA vendor
        // chunk wired ONLY via `<link rel=modulepreload>` (no
        // `<script src>`), minified onto effectively one line, ~4.4 MB  - 
        // larger than the old 4 MiB JS read cap. The GitLab PAT
        // (`glpat-`, a detector used NOWHERE else in this fixture) and
        // the `/api/v9/billing/export-all` template-literal endpoint sit
        // AFTER the 4 MiB boundary, far from any placeholder token.
        // Pre-fix every link in this chain dropped it: modulepreload
        // chunks were never fetched, the bundle was truncated at 4 MiB,
        // the template-literal `fetch(`${...}/path`)` shape was invisible
        // to the endpoint regex, and keyhog treated the whole one-line
        // bundle as a placeholder-prefixed string and suppressed the
        // key. A `glpat`/`gitlab` finding here can ONLY come from this
        // deep chunk  -  it proves all four fixes through the real binary.
        ("GET", "/static/spa-bundle.js") => {
            // 12 bytes/rep × 380_000 ≈ 4.56 MB of benign filler, then the
            // meaningful tail. No placeholder words within 96 B of the
            // key; no token-shaped runs in the filler.
            let filler = ";var _pad=0;".repeat(380_000);
            (
                200,
                "application/javascript",
                format!(
                    "/*spa*/{filler}\nconst API=window.__API||'';\
                     fetch(`${{API}}/api/v9/billing/export-all`);\
                     const billingClient={{token:\"glpat-DeepBundlePast4MbAbCdEf12\"}};\
                     /*end*/"
                ),
            )
        }
        ("GET", "/.git/config") => (
            200,
            "text/plain",
            "[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\
             \turl = https://github.com/acme/internal-secrets.git\n".into(),
        ),
        ("GET", "/.git/HEAD") => (200, "text/plain", "ref: refs/heads/main\n".into()),
        // The endpoint the inline `<script>` advertises  -  LIVE and
        // unauthenticated. A legendary scanner pivots from the JS string
        // to actually probing it.
        ("GET", "/api/v2/internal/users") => (
            200,
            "application/json",
            "{\"users\":[{\"id\":1,\"email\":\"admin@acme.test\",\"role\":\"superadmin\"}]}".into(),
        ),
        // RECALL: GraphQL on a non-standard path many real APIs use.
        ("POST", "/api/v3/gql") => (
            200,
            "application/json",
            if query.contains("INTROSPECT") {
                "{\"data\":{\"__schema\":{\"queryType\":{\"name\":\"Query\"},\
                 \"types\":[{\"name\":\"Secret\"}]}}}".into()
            } else {
                "{\"data\":{\"__typename\":\"Query\"}}".into()
            },
        ),
        // RECALL: Spring's default OpenAPI path.
        ("GET", "/v3/api-docs") => (
            200,
            "application/json",
            "{\"openapi\":\"3.0.1\",\"info\":{\"title\":\"svc\"},\"paths\":{}}".into(),
        ),
        ("GET", "/.env") => (
            200,
            "text/plain",
            format!(
                "APP_ENV=production\nDB_PASSWORD=Sup3rS3cretDbPw_2024\n\
                 GITHUB_TOKEN={GH_PAT}\nSTRIPE_KEY={STRIPE_LIVE}\n"
            ),
        ),
        ("GET", "/.env.bak") => (200, "text/plain", "OLD_KEY=deadbeef\n".into()),
        ("GET", "/config.php.bak") => (
            200,
            "text/plain",
            "<?php $db_pass='Sup3rS3cret'; // backup".into(),
        ),
        ("GET", "/robots.txt") => (
            200,
            "text/plain",
            "User-agent: *\nDisallow: /\nDisallow: /admin\n\
             User-agent: Googlebot\nDisallow: /api/private\n\
             Sitemap: http://127.0.0.1/sitemap.xml\n".into(),
        ),
        ("GET", "/swagger.json")
        | ("GET", "/openapi.json")
        | ("GET", "/v2/api-docs")
        | ("GET", "/api-docs") => (
            200,
            "application/json",
            "{\"openapi\":\"3.0.0\",\"info\":{\"title\":\"Acme Internal API\",\
             \"version\":\"1\"},\"paths\":{\"/users\":{\"get\":{}}}}".into(),
        ),
        ("GET", "/actuator/env") => (
            200,
            "application/json",
            "{\"activeProfiles\":[\"prod\"],\"propertySources\":\
             [{\"name\":\"systemEnvironment\",\"properties\":\
             {\"DB_PASSWORD\":{\"value\":\"Sup3rS3cret\"}}}]}".into(),
        ),
        ("GET", "/server-status") => (
            200,
            "text/html",
            "<h1>Apache Server Status</h1><pre>Requests currently being \
             processed: 3\nCPU Usage: u2.1</pre>".into(),
        ),
        ("POST", "/graphql") | ("POST", "/api/graphql") => (
            200,
            "application/json",
            if query.contains("INTROSPECT") {
                "{\"data\":{\"__schema\":{\"queryType\":{\"name\":\"Query\"},\
                 \"types\":[{\"name\":\"User\",\"fields\":[{\"name\":\"id\"},\
                 {\"name\":\"passwordHash\"}]}]}}}".into()
            } else {
                "{\"data\":{\"__typename\":\"Query\"}}".into()
            },
        ),
        _ => (
            500,
            "text/html",
            "<h1>Server Error</h1><pre>Traceback (most recent call last):\n  \
             File \"/srv/app/main.py\", line 42, in handle\n    \
             raise RuntimeError(secret)\nRuntimeError: db at 10.0.0.5\n</pre>"
                .into(),
        ),
    }
}

/// CLEAN, properly-configured site (precision oracle): full security
/// headers, no leaks, hard 404s, exact-match CORS, no secrets.
fn clean_body(path: &str, _m: &str, _q: &str) -> (u16, &'static str, String) {
    match path {
        "/" => (
            200,
            "text/html",
            "<!doctype html><html><head><title>Safe</title></head>\
             <body><h1>hello</h1><script src=\"/s.js\"></script></body></html>"
                .into(),
        ),
        "/s.js" => (
            200,
            "application/javascript",
            "export const ok=()=>fetch('/api/health');".into(),
        ),
        "/robots.txt" => (200, "text/plain", "User-agent: *\nAllow: /\n".into()),
        // Everything else is a hard 404 with a plain body (no soft-200,
        // no stack trace, no .git/.env).
        _ => (404, "text/plain", "Not Found".into()),
    }
}

fn start_app(vuln: bool, secure_headers: bool) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            thread::spawn(move || handle(&mut s, vuln, secure_headers));
        }
    });
    thread::sleep(Duration::from_millis(60));
    format!("127.0.0.1:{}", addr.port())
}

fn handle(s: &mut TcpStream, vuln: bool, secure_headers: bool) {
    s.set_read_timeout(Some(Duration::from_secs(5))).ok();
    let mut buf = [0u8; 16384];
    let n = match s.read(&mut buf) {
        Ok(n) if n > 0 => n,
        _ => return,
    };
    let req = String::from_utf8_lossy(&buf[..n]);
    let start = req.lines().next().unwrap_or("");
    let mut it = start.split_whitespace();
    let method = it.next().unwrap_or("GET").to_string();
    let raw = it.next().unwrap_or("/").to_string();
    let (path, query) = match raw.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (raw.clone(), String::new()),
    };
    let mut origin = String::new();
    for l in req.lines() {
        if let Some(v) = l.strip_prefix("Origin: ").or(l.strip_prefix("origin: ")) {
            origin = v.trim().to_string();
        }
    }
    let q = if req.contains("__schema") {
        format!("{query} INTROSPECT")
    } else {
        query
    };
    let (status, ctype, body) = if vuln {
        vuln_body(&path, &method, &q)
    } else {
        clean_body(&path, &method, &q)
    };

    // OPTIONS → advertise dangerous methods on the vuln app.
    let (status, body, extra_allow) = if vuln && method == "OPTIONS" {
        (200u16, String::new(), "Allow: GET,POST,PUT,DELETE,TRACE,OPTIONS\r\n".to_string())
    } else {
        (status, body, String::new())
    };

    let reason = match status {
        200 => "OK",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "OK",
    };
    let mut headers = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {ctype}\r\n\
         Content-Length: {}\r\nConnection: close\r\n{extra_allow}",
        body.len()
    );
    if vuln {
        headers.push_str("Server: Apache/2.4.49 (Unix)\r\nX-Powered-By: PHP/8.1.2\r\n");
        // Insecure cookie (no HttpOnly/Secure/SameSite).
        headers.push_str("Set-Cookie: SESSIONID=abc123def456; Path=/\r\n");
    } else {
        headers.push_str("Server: nginx\r\n");
    }
    if secure_headers {
        headers.push_str(
            "Content-Security-Policy: default-src 'self'\r\n\
             Strict-Transport-Security: max-age=63072000; includeSubDomains\r\n\
             X-Frame-Options: DENY\r\nX-Content-Type-Options: nosniff\r\n\
             Referrer-Policy: no-referrer\r\n\
             Permissions-Policy: geolocation=()\r\n",
        );
    }
    if !origin.is_empty() {
        if vuln {
            // Reflect ANY origin + allow credentials (textbook ATO).
            headers.push_str(&format!(
                "Access-Control-Allow-Origin: {origin}\r\n\
                 Access-Control-Allow-Credentials: true\r\n"
            ));
        } else {
            // Exact-match allowlist only  -  safe.
            headers.push_str("Access-Control-Allow-Origin: https://safe.example\r\n");
        }
    }
    headers.push_str("\r\n");
    let _ = s.write_all(headers.as_bytes());
    let _ = s.write_all(body.as_bytes());
    let _ = s.flush();
}

/// A server whose ROOT is an auth wall: it answers `/` with **403
/// Forbidden** but still ships the full SPA shell  -  an inline
/// `<script>` config carrying a real `ghp_` token and a bundle
/// `<script src>`. This is overwhelmingly common on real bug-bounty
/// targets (login-walled apps that still serve the built front-end).
/// Pre-fix the js analyzer did `if !status.is_success() { return [] }`
/// and found NOTHING here  -  the literal "scanned a real target, found
/// nothing" failure. Isolated single-route server so a pass proves the
/// non-2xx body is actually analysed, not some other page.
fn start_auth_wall_app() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            thread::spawn(move || {
                s.set_read_timeout(Some(Duration::from_secs(5))).ok();
                let mut buf = [0u8; 8192];
                if matches!(s.read(&mut buf), Ok(n) if n > 0) {
                    let body = format!(
                        "<!doctype html><html><head><title>Login</title></head>\
                         <body><h1>403  -  sign in to continue</h1>\
                         <script>window.__BOOT={{ghToken:\"{GH_PAT}\",\
                         api:\"/api/v2/internal/users\"}};</script>\
                         <script src=\"/static/bundle.js\"></script></body></html>"
                    );
                    let resp = format!(
                        "HTTP/1.1 403 Forbidden\r\nContent-Type: text/html\r\n\
                         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = s.write_all(resp.as_bytes());
                    let _ = s.flush();
                }
            });
        }
    });
    thread::sleep(Duration::from_millis(60));
    format!("127.0.0.1:{}", addr.port())
}

/// Serialises the actual gossan subprocess across the whole test
/// binary. Each test here spawns a FULL scanner process (its own
/// internal async concurrency) against an in-process thread-per-conn
/// HTTP server. Run N of those at once (`cargo test` defaults
/// test-threads to the core count) and the scanner processes saturate
/// the box while the tiny server threads starve  -  connections time
/// out and tests fail *non-deterministically* on machine load, not on
/// engine behaviour. That makes the keystone unable to "document why
/// it can't fail". Holding this lock across `.output()` (which blocks
/// until the child exits) means exactly one scan runs at a time at ANY
/// `--test-threads`; server spawn / assertions still parallelise.
/// Poison is recovered (a single failing assertion must not cascade a
/// PoisonError onto every other test and hide the real signal).
fn scan_gate() -> std::sync::MutexGuard<'static, ()> {
    static GATE: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    GATE.get_or_init(|| std::sync::Mutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn run_gossan(cmd: &str, target: &str) -> (bool, Vec<serde_json::Value>) {
    let _serialized = scan_gate();
    let out = Command::new(cli_bin())
        .args([cmd, target, "--format", "json", "--min-severity", "info"])
        .env("GOSSAN_HIDDEN_TARGET_BUDGET_SECS", "35")
        .env("GOSSAN_HIDDEN_PROBE_BUDGET_SECS", "12")
        // Keep `scan` bounded against 127.0.0.1 (no real subdomains/DNS
        // to find) so the e2e is fast and deterministic.
        .env("GOSSAN_SUBDOMAIN_BUDGET_SECS", "8")
        .env("GOSSAN_PHASE_BUDGET_SECS", "40")
        // The planted app is DELIBERATELY on 127.0.0.1  -  this harness
        // is the exact legitimate "I am intentionally targeting a
        // local app" case the SSRF/own-machine guard's opt-in exists
        // for. Production users get the safe default-deny (proven by
        // `scan_default_deny_refuses_private_target`, which does NOT
        // set this).
        .env("GOSSAN_ALLOW_PRIVATE_TARGETS", "1")
        .output()
        .expect("spawn gossan");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let findings = serde_json::from_str::<serde_json::Value>(stdout.trim())
        .ok()
        .map(collect_findings)
        .unwrap_or_default();
    (out.status.success(), findings)
}

fn collect_findings(v: serde_json::Value) -> Vec<serde_json::Value> {
    match v {
        serde_json::Value::Array(a) => a,
        serde_json::Value::Object(ref o) => {
            for k in ["findings", "results", "data", "items"] {
                if let Some(serde_json::Value::Array(a)) = o.get(k) {
                    return a.clone();
                }
            }
            vec![v]
        }
        _ => vec![],
    }
}

fn haystack(f: &[serde_json::Value]) -> String {
    f.iter()
        .map(|x| x.to_string().to_lowercase())
        .collect::<Vec<_>>()
        .join("\n")
}

fn assert_finds(f: &[serde_json::Value], needles: &[&str], what: &str) {
    let hay = haystack(f);
    assert!(
        needles.iter().any(|n| hay.contains(&n.to_lowercase())),
        "EXPECTED gossan to report {what}\n  any of: {needles:?}\n  \
         got {} finding(s):\n{}",
        f.len(),
        hay.chars().take(4000).collect::<String>()
    );
}

fn assert_absent(f: &[serde_json::Value], needles: &[&str], what: &str) {
    let hay = haystack(f);
    for n in needles {
        assert!(
            !hay.contains(&n.to_lowercase()),
            "PRECISION: gossan must NOT report {what} on a clean site \
             (matched {n:?})  -  false positive.\n{}",
            hay.chars().take(2000).collect::<String>()
        );
    }
}

// ───────────────────────── tech ──────────────────────────

#[test]
#[ignore = "W3-F009: gossan CLI e2e (headless/crawl/js) >60s; run with cargo test -- --ignored"]
fn tech_missing_security_headers() {
    let t = start_app(true, false);
    let (ok, f) = run_gossan("tech", &format!("http://{t}"));
    assert!(ok && !f.is_empty(), "tech must report on a header-naked server");
    assert_finds(
        &f,
        &["content-security-policy", "strict-transport-security",
          "x-frame-options", "x-content-type-options", "missing", "security header"],
        "missing security headers",
    );
}

#[test]
#[ignore = "W3-F009: gossan CLI e2e (headless/crawl/js) >60s; run with cargo test -- --ignored"]
fn tech_fingerprints_server_and_powered_by() {
    let t = start_app(true, false);
    let (ok, f) = run_gossan("tech", &format!("http://{t}"));
    assert!(ok);
    assert_finds(&f, &["apache", "php", "technology detected"],
                 "fingerprinted Apache / PHP");
}

#[test]
#[ignore = "W3-F009: gossan CLI e2e (headless/crawl/js) >60s; run with cargo test -- --ignored"]
fn tech_clean_site_no_missing_header_findings() {
    let t = start_app(false, true);
    let (ok, f) = run_gossan("tech", &format!("http://{t}"));
    assert!(ok, "tech must exit 0 on a clean site");
    assert_absent(
        &f,
        &["missing content-security-policy", "missing strict-transport-security",
          "missing x-frame-options"],
        "missing-header",
    );
}

#[test]
#[ignore = "W3-F009: gossan CLI e2e (headless/crawl/js) >60s; run with cargo test -- --ignored"]
fn tech_closed_port_clean_and_no_crash() {
    let (ok, f) = run_gossan("tech", "http://127.0.0.1:1");
    assert!(ok, "unreachable target must exit 0");
    assert!(f.is_empty(), "closed port → no findings");
}

// ───────────────────────── js ──────────────────────────

#[test]
#[ignore = "W3-F009: gossan CLI e2e (headless/crawl/js) >60s; run with cargo test -- --ignored"]
fn js_finds_secrets_inline_and_external() {
    let t = start_app(true, false);
    let (ok, f) = run_gossan("js", &format!("http://{t}"));
    assert!(ok);
    assert_finds(&f, &["secret", "token", "api key", "credential",
                       "ghp_", "sk_live", "xoxb-", "akia"],
                 "hardcoded secret in inline + external JS");
}

/// PROVING (false-negative class fixed): the SPA shell is served behind
/// a 403 auth wall. Pre-fix gossan bailed on the non-2xx status and
/// reported nothing; post-fix it analyses the body and recovers the
/// inline `ghp_` token. This isolated single-route server makes a pass
/// mean exactly that  -  the auth-walled body was analysed.
#[test]
#[ignore = "W3-F009: gossan CLI e2e (headless/crawl/js) >60s; run with cargo test -- --ignored"]
fn js_finds_secret_behind_403_auth_wall() {
    let t = start_auth_wall_app();
    let (ok, f) = run_gossan("js", &format!("http://{t}"));
    assert!(ok, "gossan must exit 0 against a 403 auth-wall target");
    assert_finds(
        &f,
        &["ghp_", "secret", "token", "credential"],
        "inline secret in a 403-auth-walled SPA shell",
    );
}

#[test]
#[ignore = "W3-F009: gossan CLI e2e (headless/crawl/js) >60s; run with cargo test -- --ignored"]
fn js_finds_endpoints() {
    let t = start_app(true, false);
    let (ok, f) = run_gossan("js", &format!("http://{t}"));
    assert!(ok);
    assert_finds(&f, &["/api/", "endpoint", "/internal/"],
                 "API endpoints extracted from JS");
}

/// PROVING (legendary discovery→attack pivot): an endpoint advertised
/// in the inline JS that is actually reachable must be reported as
/// LIVE, not merely listed. The vuln server serves
/// /api/v2/internal/users (200) and unknown paths 500 (so the
/// catch-all guard is satisfied).
#[test]
#[ignore = "W3-F009: gossan CLI e2e (headless/crawl/js) >60s; run with cargo test -- --ignored"]
fn js_pivots_and_flags_live_discovered_endpoint() {
    let t = start_app(true, false);
    let (ok, f) = run_gossan("js", &format!("http://{t}"));
    assert!(ok);
    assert_finds(
        &f,
        &["js-discovered endpoint is live", "endpoint is live"],
        "JS-discovered endpoint actively probed and confirmed live",
    );
}

/// PRECISION: the clean site advertises no extra endpoints and hard-
/// 404s the unknown  -  the pivot must not manufacture a LIVE finding.
#[test]
#[ignore = "W3-F009: gossan CLI e2e (headless/crawl/js) >60s; run with cargo test -- --ignored"]
fn js_clean_site_no_live_endpoint_findings() {
    let t = start_app(false, true);
    let (ok, f) = run_gossan("js", &format!("http://{t}"));
    assert!(ok);
    assert_absent(&f, &["endpoint is live"], "phantom live endpoint");
}

#[test]
#[ignore = "W3-F009: gossan CLI e2e (headless/crawl/js) >60s; run with cargo test -- --ignored"]
fn js_clean_site_no_secret_findings() {
    let t = start_app(false, true);
    let (ok, f) = run_gossan("js", &format!("http://{t}"));
    assert!(ok);
    // `glpat-` included: the clean site links no modulepreload chunk, so
    // a GitLab-PAT finding here would be a phantom (adversarial twin of
    // `js_finds_modulepreload_deep_bundle_secret_and_template_endpoint`).
    assert_absent(&f, &["sk_live", "ghp_", "xoxb-", "akia", "hardcoded", "glpat", "gitlab"],
                  "secret");
}

/// PROVING (CONTINUATION-2 recall chain, end-to-end through the real
/// `gossan` binary): the headline "ran on a real JS-heavy target, found
/// nothing" failure. The home page wires a ~4.4 MB minified vendor
/// chunk ONLY via `<link rel=modulepreload>`; a GitLab PAT (`glpat-`,
/// used nowhere else in this fixture so a hit is unambiguously from
/// this chunk) and a `/api/v9/billing/export-all` template-literal
/// endpoint sit past the old 4 MiB cap, far from any placeholder token.
/// A pass means ALL of: modulepreload chunks are fetched, the read cap
/// admits a >4 MiB bundle, the `fetch(`${x}/path`)` template shape is
/// extracted, and keyhog no longer suppresses a key in a one-line
/// minified bundle. Any failure here is a real engine gap to fix in the
/// engine  -  never by weakening this fixture (anti-rigging law).
#[test]
#[ignore = "W3-F009: gossan CLI e2e (headless/crawl/js) >60s; run with cargo test -- --ignored"]
fn js_finds_modulepreload_deep_bundle_secret_and_template_endpoint() {
    let t = start_app(true, false);
    let (ok, f) = run_gossan("js", &format!("http://{t}"));
    assert!(ok, "gossan must exit 0");
    assert_finds(
        &f,
        &["glpat", "gitlab"],
        "GitLab PAT past the 4 MiB cap in a modulepreload-only minified chunk",
    );
    assert_finds(
        &f,
        &["/api/v9/billing/export-all"],
        "template-literal endpoint `fetch(`${API}/api/v9/billing/export-all`)`",
    );
}

// ───────────────────────── hidden ──────────────────────────

#[test]
#[ignore = "W3-F009: gossan CLI e2e (headless/crawl/js) >60s; run with cargo test -- --ignored"]
fn hidden_finds_exposed_git() {
    let t = start_app(true, false);
    let (ok, f) = run_gossan("hidden", &format!("http://{t}"));
    assert!(ok && !f.is_empty(),
            "hidden must not be empty against an exposed app");
    assert_finds(&f, &[".git", "git config", "git repository", "version control"],
                 "exposed /.git");
}

#[test]
#[ignore = "W3-F009: gossan CLI e2e (headless/crawl/js) >60s; run with cargo test -- --ignored"]
fn hidden_finds_exposed_env() {
    let t = start_app(true, false);
    let (ok, f) = run_gossan("hidden", &format!("http://{t}"));
    assert!(ok);
    assert_finds(&f, &[".env", "environment file", "dotenv"], "exposed /.env");
}

#[test]
#[ignore = "W3-F009: gossan CLI e2e (headless/crawl/js) >60s; run with cargo test -- --ignored"]
fn hidden_finds_swagger() {
    let t = start_app(true, false);
    let (ok, f) = run_gossan("hidden", &format!("http://{t}"));
    assert!(ok);
    assert_finds(&f, &["swagger", "openapi", "api documentation", "api spec"],
                 "exposed swagger/OpenAPI");
}

#[test]
#[ignore = "W3-F009: gossan CLI e2e (headless/crawl/js) >60s; run with cargo test -- --ignored"]
fn hidden_finds_robots_disallowed_incl_agent_specific() {
    let t = start_app(true, false);
    let (ok, f) = run_gossan("hidden", &format!("http://{t}"));
    assert!(ok);
    assert_finds(&f, &["robots", "/admin", "/api/private", "disallow"],
                 "robots.txt disallowed paths incl. agent-specific");
}

#[test]
#[ignore = "W3-F009: gossan CLI e2e (headless/crawl/js) >60s; run with cargo test -- --ignored"]
fn hidden_finds_graphql_introspection() {
    let t = start_app(true, false);
    let (ok, f) = run_gossan("hidden", &format!("http://{t}"));
    assert!(ok);
    assert_finds(&f, &["graphql", "introspection"], "GraphQL introspection");
}

#[test]
#[ignore = "W3-F009: gossan CLI e2e (headless/crawl/js) >60s; run with cargo test -- --ignored"]
fn hidden_finds_cors_misconfig() {
    let t = start_app(true, false);
    let (ok, f) = run_gossan("hidden", &format!("http://{t}"));
    assert!(ok);
    assert_finds(&f, &["cors", "access-control", "arbitrary origin"],
                 "CORS reflect-with-credentials");
}

#[test]
#[ignore = "W3-F009: gossan CLI e2e (headless/crawl/js) >60s; run with cargo test -- --ignored"]
fn hidden_finds_error_disclosure() {
    let t = start_app(true, false);
    let (ok, f) = run_gossan("hidden", &format!("http://{t}"));
    assert!(ok);
    assert_finds(&f, &["traceback", "stack trace", "error disclosure", "disclosure"],
                 "Python stack-trace disclosure");
}

#[test]
#[ignore = "W3-F009: gossan CLI e2e (headless/crawl/js) >60s; run with cargo test -- --ignored"]
fn hidden_clean_site_is_quiet() {
    let t = start_app(false, true);
    let (ok, f) = run_gossan("hidden", &format!("http://{t}"));
    assert!(ok, "hidden must exit 0 on a clean site");
    // The clean server hard-404s everything and has no leaks; hidden
    // must NOT fabricate .git/.env/swagger/traceback findings.
    assert_absent(
        &f,
        &["git config", ".env file", "swagger", "traceback",
          "arbitrary origin reflected with credentials"],
        "exposed-resource",
    );
}

#[test]
#[ignore = "W3-F009: gossan CLI e2e (headless/crawl/js) >60s; run with cargo test -- --ignored"]
fn hidden_finds_backup_file() {
    let t = start_app(true, false);
    let (ok, f) = run_gossan("hidden", &format!("http://{t}"));
    assert!(ok);
    assert_finds(&f, &["backup", ".bak", "config.php", ".env.bak"],
                 "exposed backup file (config.php.bak / .env.bak)");
}

#[test]
#[ignore = "W3-F009: gossan CLI e2e (headless/crawl/js) >60s; run with cargo test -- --ignored"]
fn hidden_finds_spring_actuator_env() {
    let t = start_app(true, false);
    let (ok, f) = run_gossan("hidden", &format!("http://{t}"));
    assert!(ok);
    assert_finds(&f, &["actuator", "spring", "debug endpoint", "/actuator/env",
                       "environment"],
                 "exposed Spring /actuator/env");
}

#[test]
#[ignore = "W3-F009: gossan CLI e2e (headless/crawl/js) >60s; run with cargo test -- --ignored"]
fn hidden_finds_insecure_session_cookie() {
    let t = start_app(true, false);
    let (ok, f) = run_gossan("hidden", &format!("http://{t}"));
    assert!(ok);
    assert_finds(&f, &["cookie", "httponly", "secure", "samesite"],
                 "session cookie missing HttpOnly/Secure/SameSite");
}

#[test]
#[ignore = "W3-F009: gossan CLI e2e (headless/crawl/js) >60s; run with cargo test -- --ignored"]
fn hidden_finds_dangerous_http_methods() {
    let t = start_app(true, false);
    let (ok, f) = run_gossan("hidden", &format!("http://{t}"));
    assert!(ok);
    assert_finds(&f, &["trace", "method", "put", "delete", "allow"],
                 "dangerous HTTP methods advertised (TRACE/PUT/DELETE)");
}

// ───────────────────────── js source map ──────────────────────────

#[test]
#[ignore = "W3-F009: gossan CLI e2e (headless/crawl/js) >60s; run with cargo test -- --ignored"]
fn js_finds_source_map_leak() {
    let t = start_app(true, false);
    let (ok, f) = run_gossan("js", &format!("http://{t}"));
    assert!(ok);
    assert_finds(&f, &["source map", "sourcemap", "sourcescontent",
                       "secret_config", "original source"],
                 "exposed JS source map leaking original source");
}

// ───────────────────────── tech extra ──────────────────────────

#[test]
#[ignore = "W3-F009: gossan CLI e2e (headless/crawl/js) >60s; run with cargo test -- --ignored"]
fn tech_detects_wordpress_generator() {
    let t = start_app(true, false);
    let (ok, f) = run_gossan("tech", &format!("http://{t}"));
    assert!(ok);
    assert_finds(&f, &["wordpress"], "WordPress from <meta generator>");
}

// ───────────────────────── full scan ──────────────────────────

/// The headline command an operator actually runs. Must complete,
/// exit 0, and aggregate web-layer findings from the whole pipeline
/// against the live vuln app (not hang, not crash, not silent).
#[test]
#[ignore = "W3-F009: gossan CLI e2e (headless/crawl/js) >60s; run with cargo test -- --ignored"]
fn full_scan_completes_and_aggregates_findings() {
    let t = start_app(true, false);
    let (ok, f) = run_gossan("scan", &format!("http://{t}"));
    assert!(ok, "`gossan scan` must exit 0 on a reachable target");
    assert!(
        !f.is_empty(),
        "`gossan scan` against an exposed app must not be empty  -  \
         this is the literal 'full black box' report"
    );
    // The pipeline should surface at least the high-signal web vulns.
    let hay = haystack(&f);
    let categories = [
        hay.contains(".git") || hay.contains("git config"),
        hay.contains(".env") || hay.contains("environment file"),
        hay.contains("swagger") || hay.contains("openapi"),
        hay.contains("cors") || hay.contains("access-control"),
        hay.contains("secret") || hay.contains("ghp_") || hay.contains("sk_live"),
        hay.contains("missing") || hay.contains("security header"),
        hay.contains("apache") || hay.contains("php"),
    ];
    let hits = categories.iter().filter(|b| **b).count();
    assert!(
        hits >= 4,
        "`gossan scan` should aggregate ≥4 distinct vuln categories \
         from the pipeline, only matched {hits}:\n{}",
        hay.chars().take(4000).collect::<String>()
    );
}

#[test]
#[ignore = "W3-F009: gossan CLI e2e (headless/crawl/js) >60s; run with cargo test -- --ignored"]
fn full_scan_clean_site_low_noise() {
    let t = start_app(false, true);
    let (ok, f) = run_gossan("scan", &format!("http://{t}"));
    assert!(ok, "`gossan scan` must exit 0 on a clean site");
    // The WEB-LAYER scanners (the app surface) must not fabricate
    // CRITICAL/HIGH on a properly-configured static site. Host-level
    // scanners (portscan/dns/intel) are intentionally excluded: this
    // runs on a dev box where 127.0.0.1 legitimately has other real
    // services (e.g. mysql:3306)  -  portscan reporting those is a TRUE
    // positive about the host, not an app false positive.
    let web_scanners = ["techstack", "hidden", "js", "crawl", "cloud", "headless"];
    let web_highs: Vec<String> = f
        .iter()
        .filter(|x| {
            let scanner = x
                .get("scanner")
                .and_then(|s| s.as_str())
                .unwrap_or("");
            let sev = x
                .get("severity")
                .and_then(|s| s.as_str())
                .unwrap_or("")
                .to_lowercase();
            web_scanners.contains(&scanner) && (sev == "critical" || sev == "high")
        })
        .map(|x| x.to_string())
        .collect();
    assert!(
        web_highs.is_empty(),
        "clean site: web-layer scanners produced {} CRITICAL/HIGH \
         finding(s)  -  precision failure:\n{}",
        web_highs.len(),
        web_highs.join("\n").chars().take(3000).collect::<String>()
    );
}

// ─────────────── adversarial / recall (tier-3) ───────────────

/// EVASION: secrets bootstrapped in a `<script type="application/json">`
/// block (Next.js `__NEXT_DATA__`, Nuxt, Angular) and an HTML
/// `data-*` attribute  -  NOT a `text/javascript` script and NOT a .js
/// file. A scanner that only reads typed JS or external bundles misses
/// the modern SPA leak entirely. Fix #7's full-body inline scan must
/// still catch it.
#[test]
#[ignore = "W3-F009: gossan CLI e2e (headless/crawl/js) >60s; run with cargo test -- --ignored"]
fn js_finds_secret_in_json_script_and_data_attr() {
    let t = start_app(true, false);
    let (ok, f) = run_gossan("js", &format!("http://{t}"));
    assert!(ok);
    assert_finds(
        &f,
        &["xoxb-", "slack", "sk_live", "stripe", "secret", "token"],
        "secret in <script type=application/json> / data-* attribute",
    );
}

/// RECALL: a GraphQL endpoint on a non-standard path (`/api/v3/gql`).
/// Many real APIs do not sit at `/graphql`; the probe's path catalogue
/// must be broad enough or this is a silent miss on real targets.
#[test]
#[ignore = "W3-F009: gossan CLI e2e (headless/crawl/js) >60s; run with cargo test -- --ignored"]
fn hidden_finds_graphql_on_nonstandard_path() {
    let t = start_app(true, false);
    let (ok, f) = run_gossan("hidden", &format!("http://{t}"));
    assert!(ok);
    assert_finds(
        &f,
        &["graphql", "introspection"],
        "GraphQL introspection on a non-standard path",
    );
}

/// RECALL: Spring's default OpenAPI location `/v3/api-docs` (distinct
/// from `/swagger.json`). A Java shop's API docs must not be missed.
#[test]
#[ignore = "W3-F009: gossan CLI e2e (headless/crawl/js) >60s; run with cargo test -- --ignored"]
fn hidden_finds_openapi_on_spring_default_path() {
    let t = start_app(true, false);
    let (ok, f) = run_gossan("hidden", &format!("http://{t}"));
    assert!(ok);
    assert_finds(
        &f,
        &["swagger", "openapi", "api documentation", "api spec"],
        "OpenAPI spec at the Spring default /v3/api-docs",
    );
}

/// EVASION: `.git` exposed via `/.git/HEAD` while `/.git/config` may be
/// blocked by the web server  -  the probe must confirm the repo from
/// HEAD/refs, not only config.
#[test]
#[ignore = "W3-F009: gossan CLI e2e (headless/crawl/js) >60s; run with cargo test -- --ignored"]
fn hidden_finds_git_via_head_not_only_config() {
    let t = start_app(true, false);
    let (ok, f) = run_gossan("hidden", &format!("http://{t}"));
    assert!(ok);
    assert_finds(
        &f,
        &[".git", "git repository", "git config", "version control"],
        "exposed .git (HEAD/refs path)",
    );
}

// ───────────────── FULL `gossan scan` CASCADE (wiring) ──────────────
//
// Every test above drives a SINGLE module command (`gossan js|tech|
// hidden …`). None of them prove the orchestrator actually WIRES the
// modules together. `gossan scan <host:port>` must flow the seed
// through the real topological cascade:
//
//   seed Domain/Service → portscan(Service) → techstack(→Web)
//                       → js / hidden / crawl (consume Web)
//
// If ANY link is severed (a scanner `accepts()` drift, a phase-tier
// regression, an emit channel that drops) the web-app layer never
// receives a target and the scan "finds nothing"  -  the literal
// bug-bounty report. These tests fail the instant the pipeline is
// not fully wired end-to-end through the real binary.

/// PROVING (full-pipeline wiring): a bare `gossan scan host:port`
/// against the planted app MUST surface findings that can ONLY exist
/// if the cascade delivered a `Web` target to the web-app scanners  - 
/// a JS-layer secret/endpoint AND a hidden-layer artefact AND a
/// techstack signal, all reached via seed→Service→techstack→Web,
/// never via a direct `gossan js http://…` shortcut.
#[test]
#[ignore = "W3-F009: gossan CLI e2e (headless/crawl/js) >60s; run with cargo test -- --ignored"]
fn scan_full_cascade_surfaces_web_layer_findings() {
    let t = start_app(true, false);
    let (ok, f) = run_gossan("scan", &t);
    assert!(
        ok,
        "`gossan scan {t}` must exit 0 (got failure); the full pipeline \
         must never crash or hang on a reachable target"
    );
    assert!(
        !f.is_empty(),
        "`gossan scan` produced ZERO findings on a vuln app  -  the \
         cascade is severed (the exact 'ran on a real target, found \
         nothing' headline)"
    );
    // js layer reached via the cascade (a secret / advertised endpoint
    // that only the js scanner on a Web target produces).
    assert_finds(
        &f,
        &[
            "stripe", "slack", "google api", "secret", "sk_live",
            "xoxb", "/api/v2/internal", "sourcemap", "source map",
        ],
        "a JS-layer finding via the full scan cascade (js reached Web)",
    );
    // hidden layer reached via the cascade.
    assert_finds(
        &f,
        &[
            ".env", ".git", "git config", "swagger", "openapi",
            "actuator", "backup", "exposed",
        ],
        "a hidden-content finding via the full scan cascade",
    );
    // techstack ran on the synthesised web Service (its Web emission is
    // the cascade hinge that feeds js/hidden/crawl).
    assert_finds(
        &f,
        &[
            "wordpress", "security header", "content-security-policy",
            "x-frame-options", "strict-transport-security",
        ],
        "a techstack/header finding (the Service→Web cascade hinge)",
    );
}

/// ADVERSARIAL / PRECISION twin: the SAME full `gossan scan` against
/// the clean, hardened app must NOT invent the vuln-app's secrets or
/// exposed paths. Broadening the cascade must not broaden false
/// positives end-to-end.
#[test]
#[ignore = "W3-F009: gossan CLI e2e (headless/crawl/js) >60s; run with cargo test -- --ignored"]
fn scan_full_cascade_clean_site_is_precise() {
    let t = start_app(false, true);
    let (ok, f) = run_gossan("scan", &t);
    assert!(ok, "`gossan scan` on a clean site must exit 0");
    assert_absent(
        &f,
        &[
            "sk_live_", "xoxb-", "glpat-", "ghp_", "AKIA",
            "postgres://app:", "internal-secrets.git",
            "Sup3rS3cretDbPw", "DB_PASSWORD",
        ],
        "a planted secret / exposed-path string",
    );
}

/// The full pipeline must terminate cleanly and silently (no findings,
/// no hang, exit 0) on an unreachable target  -  a black-box hang here
/// is the same "does nothing" failure as a severed cascade.
#[test]
#[ignore = "W3-F009: gossan CLI e2e (headless/crawl/js) >60s; run with cargo test -- --ignored"]
fn scan_default_deny_refuses_private_target() {
    // NO `GOSSAN_ALLOW_PRIVATE_TARGETS`  -  production default. This is
    // the SSRF / own-machine / DNS-rebinding safety contract the
    // full-pipeline e2e SURFACED: `gossan scan 127.0.0.1:1` had been
    // port-scanning the runner's own box and reporting its
    // MySQL:3306 / SSH:22 / RDP:3389 as the "target's" findings. By
    // default gossan must refuse every internal/loopback target and
    // emit NOTHING  -  never the operator's own / internal services.
    let _serialized = scan_gate();
    for tgt in ["127.0.0.1:1", "10.0.0.1", "169.254.169.254", "192.168.1.1"] {
        let out = Command::new(cli_bin())
            .args(["scan", tgt, "--format", "json", "--min-severity", "info"])
            .env("GOSSAN_SUBDOMAIN_BUDGET_SECS", "4")
            .env("GOSSAN_PHASE_BUDGET_SECS", "20")
            .env_remove("GOSSAN_ALLOW_PRIVATE_TARGETS")
            .output()
            .expect("spawn gossan");
        assert!(
            out.status.success(),
            "`gossan scan {tgt}` must still exit 0 (refuse cleanly, not crash)"
        );
        let f = serde_json::from_str::<serde_json::Value>(
            String::from_utf8_lossy(&out.stdout).trim(),
        )
        .ok()
        .map(collect_findings)
        .unwrap_or_default();
        // 169.254.169.254 is the cloud metadata endpoint  -  the single
        // most dangerous SSRF pivot; it MUST yield nothing by default.
        assert!(
            f.is_empty(),
            "default-deny breached: `scan {tgt}` produced {} finding(s)  -  \
             gossan port-scanned an internal/own-machine address and \
             attributed its services to the target (SSRF/own-machine):\n{}",
            f.len(),
            haystack(&f).chars().take(1500).collect::<String>()
        );
    }

    // The dangerous LIVE case: a real vulnerable app actually
    // listening on loopback. `127.0.0.1:1` above is a dead port; this
    // proves the explicit-port SYNTHETIC-SERVICE path (which bypasses
    // portscan's peer_addr gate and feeds techstack→Web→js/hidden
    // directly) ALSO refuses an internal host by default  -  without it,
    // `gossan scan 10.0.0.5:8080` would web-scan internal infra and
    // dump its secrets.
    let t = start_app(true, false); // 127.0.0.1:<live port>, planted vulns
    let out = Command::new(cli_bin())
        .args(["scan", &t, "--format", "json", "--min-severity", "info"])
        .env("GOSSAN_SUBDOMAIN_BUDGET_SECS", "4")
        .env("GOSSAN_PHASE_BUDGET_SECS", "20")
        .env_remove("GOSSAN_ALLOW_PRIVATE_TARGETS")
        .output()
        .expect("spawn gossan");
    assert!(out.status.success(), "`gossan scan {t}` must exit 0");
    let f = serde_json::from_str::<serde_json::Value>(
        String::from_utf8_lossy(&out.stdout).trim(),
    )
    .ok()
    .map(collect_findings)
    .unwrap_or_default();
    assert!(
        f.is_empty(),
        "SSRF breach: `gossan scan {t}` (a LIVE internal app, no \
         opt-in) produced {} finding(s)  -  the synthetic-Service path \
         web-scanned loopback and exfiltrated the internal app's \
         surface by default:\n{}",
        f.len(),
        haystack(&f).chars().take(1500).collect::<String>()
    );
}

