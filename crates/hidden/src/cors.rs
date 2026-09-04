//! CORS misconfiguration detection.
//!
//! Tests the target for dangerous Cross-Origin Resource Sharing configurations:
//!
//! - **Origin reflection**: server blindly reflects any `Origin` header → full
//!   account takeover via cross-origin credential theft.
//! - **Null origin**: `Origin: null` is trusted → sandbox/data-URI exploits can
//!   read authenticated responses.
//! - **Wildcard with credentials**: `Access-Control-Allow-Origin: *` combined with
//!   `Access-Control-Allow-Credentials: true` → browsers block this, but the
//!   misconfiguration signals a confused developer who may fix it wrong.
//! - **Subdomain wildcard**: a prefix/suffix match (e.g., `evil-example.com` is
//!   accepted when `example.com` is the real origin) → attacker-controlled
//!   subdomain can steal data.
//! - **HTTP origin trusted on HTTPS site**: `http://example.com` is allowed on
//!   an `https://` endpoint → network MITM can inject JS to exfiltrate data
//!   cross-origin.
//!
//! Each probe sends a single request with a crafted `Origin` header and inspects
//! the `Access-Control-Allow-Origin` and `Access-Control-Allow-Credentials`
//! response headers.

use gossan_core::Target;
use reqwest::Client;
use secfinding::{Evidence, Finding, Severity};

/// CORS test origins (each targets a different misconfiguration class).
const EVIL_ORIGIN: &str = "https://evil.com";
const NULL_ORIGIN: &str = "null";

pub async fn probe(client: &Client, target: &Target) -> anyhow::Result<Vec<Finding>> {
    let Target::Web(asset) = target else {
        return Ok(vec![]);
    };
    let base = asset.url.as_str();
    let mut findings = Vec::new();

    // ── Test 1: arbitrary origin reflection ──────────────────────────────
    match client.get(base).header("Origin", EVIL_ORIGIN).send().await {
        Ok(resp) => {
            let acao = header_value(&resp, "access-control-allow-origin");
        let acac = header_value(&resp, "access-control-allow-credentials");
        let status = resp.status().as_u16();

        if acao.as_deref() == Some(EVIL_ORIGIN) {
            let credentials = acac.as_deref() == Some("true");
            let (severity, title, detail) = if credentials {
                (
                    Severity::Critical,
                    "CORS: arbitrary origin reflected with credentials",
                    "The server reflects any Origin header AND sends \
                     Access-Control-Allow-Credentials: true. An attacker on any domain \
                     can make authenticated cross-origin requests and read the response. \
                     this enables full account takeover via credential theft. \
                     Fix: validate Origin against an explicit allowlist.",
                )
            } else {
                (
                    Severity::High,
                    "CORS: arbitrary origin reflected",
                    "The server reflects any Origin header in Access-Control-Allow-Origin. \
                     While credentials are not explicitly allowed, this still exposes \
                     non-authenticated API responses to any origin. If the server later \
                     adds credentials support, it becomes Critical. \
                     Fix: validate Origin against an explicit allowlist.",
                )
            };

            findings.push(
                crate::misconfig_finding(target, severity, title, detail)
                    .evidence(Evidence::HttpResponse {
                        status,
                        headers: build_cors_evidence(&acao, &acac),
                        body_excerpt: None,
                    })
                    .tag("cors")
                    .tag("web")
                    .tag("misconfiguration")
                    .build()
                    .map_err(|e| anyhow::anyhow!(e))?,
            );
            }
        }
        Err(e) => {
            tracing::warn!(
                "CORS probe send failed: origin={} url={} error={}",
                EVIL_ORIGIN,
                base,
                e
            );
        }
    }

    // ── Test 2: null origin trusted ──────────────────────────────────────
    match client.get(base).header("Origin", NULL_ORIGIN).send().await {
        Ok(resp) => {
            let acao = header_value(&resp, "access-control-allow-origin");
        let acac = header_value(&resp, "access-control-allow-credentials");
        let status = resp.status().as_u16();

        if acao.as_deref() == Some("null") {
            let credentials = acac.as_deref() == Some("true");
            findings.push(
                crate::misconfig_finding(
                    target,
                    if credentials {
                        Severity::Critical
                    } else {
                        Severity::High
                    },
                    "CORS: null origin trusted",
                    format!(
                        "The server allows Origin: null{}. \
                         Sandboxed iframes, data: URIs, and file: pages send null origin. \
                         an attacker can craft a page that reads cross-origin responses. \
                         Fix: never trust null origin.",
                        if credentials { " with credentials" } else { "" }
                    ),
                )
                .evidence(Evidence::HttpResponse {
                    status,
                    headers: build_cors_evidence(&acao, &acac),
                    body_excerpt: None,
                })
                .tag("cors")
                .tag("web")
                .tag("misconfiguration")
                .build()
                .map_err(|e| anyhow::anyhow!(e))?,
            );
            }
        }
        Err(e) => {
            tracing::warn!(
                "CORS probe send failed: origin={} url={} error={}",
                NULL_ORIGIN,
                base,
                e
            );
        }
    }

    // ── Test 3: subdomain wildcard / prefix mismatch ─────────────────────
    // If the site is https://example.com, test if https://evil-example.com is accepted
    if let Some(domain) = target.domain() {
        let prefix_evil = format!("https://evil-{domain}");
        match client.get(base).header("Origin", &prefix_evil).send().await {
            Ok(resp) => {
                let acao = header_value(&resp, "access-control-allow-origin");
            let status = resp.status().as_u16();

            if acao.as_deref() == Some(prefix_evil.as_str()) {
                findings.push(
                    crate::misconfig_finding(
                        target,
                        Severity::High,
                        "CORS: prefix/suffix origin bypass",
                        format!(
                            "The server accepted '{prefix_evil}' as a trusted origin. \
                             This means the CORS validation uses a naive contains/endsWith \
                             check instead of exact matching. An attacker can register a \
                             lookalike domain to bypass CORS restrictions. \
                             Fix: use exact origin comparison, not substring matching."
                        ),
                    )
                    .evidence(Evidence::HttpResponse {
                        status,
                        headers: build_cors_evidence(&acao, &None),
                        body_excerpt: None,
                    })
                    .tag("cors")
                    .tag("web")
                    .tag("misconfiguration")
                    .build()
                    .map_err(|e| anyhow::anyhow!(e))?,
                );
                }
            }
            Err(e) => {
                tracing::warn!(
                    "CORS probe send failed: origin={} url={} error={}",
                    prefix_evil,
                    base,
                    e
                );
            }
        }
    }

    // ── Test 4: suffix origin bypass (regex wildcard) ───────────────────
    if let Some(domain) = target.domain() {
        let suffix_evil = format!("https://{}.evil.com", domain);
        match client.get(base).header("Origin", &suffix_evil).send().await {
            Ok(resp) => {
                let acao = header_value(&resp, "access-control-allow-origin");
            let status = resp.status().as_u16();
            if acao.as_deref() == Some(suffix_evil.as_str()) {
                findings.push(
                    crate::misconfig_finding(
                        target,
                        Severity::High,
                        "CORS: suffix origin bypass",
                        format!(
                            "The server accepted '{}' as a trusted origin. \
                             This means the CORS validation uses a naive contains/endsWith \
                             check instead of exact matching. An attacker can register a \
                             lookalike domain to bypass CORS restrictions. \
                             Fix: use exact origin comparison, not substring matching.",
                            suffix_evil
                        ),
                    )
                    .evidence(Evidence::HttpResponse {
                        status,
                        headers: build_cors_evidence(&acao, &None),
                        body_excerpt: None,
                    })
                    .tag("cors")
                    .tag("web")
                    .tag("misconfiguration")
                    .build()
                    .map_err(|e| anyhow::anyhow!(e))?,
                );
                }
            }
            Err(e) => {
                tracing::warn!(
                    "CORS probe send failed: origin={} url={} error={}",
                    suffix_evil,
                    base,
                    e
                );
            }
        }
    }

    // ── Test 5: HTTP origin trusted on HTTPS site ────────────────────────
    if base.starts_with("https://") {
        if let Some(domain) = target.domain() {
            let http_origin = format!("http://{domain}");
            match client.get(base).header("Origin", &http_origin).send().await {
                Ok(resp) => {
                    let acao = header_value(&resp, "access-control-allow-origin");
                let status = resp.status().as_u16();

                if acao.as_deref() == Some(http_origin.as_str()) {
                    findings.push(
                        crate::misconfig_finding(
                            target,
                            Severity::Medium,
                            "CORS: HTTP origin trusted on HTTPS endpoint",
                            format!(
                                "The HTTPS endpoint accepts 'http://{domain}' as a trusted \
                                 CORS origin. A network-level attacker (MITM) can inject \
                                 JavaScript on the HTTP origin to exfiltrate data from the \
                                 HTTPS endpoint cross-origin. \
                                 Fix: only allow HTTPS origins in CORS configuration."
                            ),
                        )
                        .evidence(Evidence::HttpResponse {
                            status,
                            headers: build_cors_evidence(&acao, &None),
                            body_excerpt: None,
                        })
                        .tag("cors")
                        .tag("web")
                        .tag("misconfiguration")
                        .build()
                        .map_err(|e| anyhow::anyhow!(e))?,
                    );
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        "CORS probe send failed: origin={} url={} error={}",
                        http_origin,
                        base,
                        e
                    );
                }
            }
        }
    }

    // ── Test 6: overly permissive methods ───────────────────────────────
    match client
        .request(reqwest::Method::OPTIONS, base)
        .header("Origin", EVIL_ORIGIN)
        .header("Access-Control-Request-Method", "DELETE")
        .send()
        .await
    {
        Ok(resp) => {
            let acam = header_value(&resp, "access-control-allow-methods");
        let status = resp.status().as_u16();

        if let Some(methods) = &acam {
            let methods_upper = methods.to_uppercase();
            let tokens: std::collections::HashSet<&str> =
                methods_upper.split(|c: char| c == ',' || c.is_whitespace()).collect();
            let dangerous_methods: Vec<&str> = ["DELETE", "PUT", "PATCH"]
                .iter()
                .filter(|m| tokens.contains(**m))
                .copied()
                .collect();
            // Fire when the server exposes a wildcard method list OR allows
            // two or more high-risk methods cross-origin. The explicit
            // parentheses pin the intended precedence (`&&` binds tighter
            // than `||` without them) so a future reader cannot misread the
            // condition.
            if (tokens.contains("*") && !dangerous_methods.is_empty())
                || dangerous_methods.len() >= 2
            {
                findings.push(
                    crate::misconfig_finding(
                        target,
                        Severity::Medium,
                        "CORS: dangerous methods allowed cross-origin",
                        format!(
                            "The server allows dangerous HTTP methods ({}) cross-origin.                              This may enable cross-origin data modification if credentials are also allowed.                              Fix: restrict Access-Control-Allow-Methods to only required methods.",
                            dangerous_methods.join(", ")
                        ),
                    )
                    .evidence(Evidence::HttpResponse {
                        status,
                        headers: vec![("access-control-allow-methods".into(), methods.clone().into())],
                        body_excerpt: None,
                    })
                    .tag("cors")
                    .tag("web")
                    .tag("misconfiguration")
                    .build()
                    .map_err(|e| anyhow::anyhow!(e))?,
                );
            }
        }
            }
        Err(e) => {
            tracing::warn!(
                "CORS OPTIONS probe send failed: origin={} url={} error={}",
                EVIL_ORIGIN,
                base,
                e
            );
        }
    }

    Ok(findings)
}

/// Extract a response header value as an owned string.
fn header_value(resp: &reqwest::Response, name: &str) -> Option<String> {
    resp.headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

/// Build evidence headers for CORS-related findings.
fn build_cors_evidence(
    acao: &Option<String>,
    acac: &Option<String>,
) -> Vec<(std::sync::Arc<str>, std::sync::Arc<str>)> {
    let mut headers = Vec::new();
    if let Some(val) = acao {
        headers.push((
            "access-control-allow-origin".into(),
            std::sync::Arc::<str>::from(val.as_str()),
        ));
    }
    if let Some(val) = acac {
        headers.push((
            "access-control-allow-credentials".into(),
            std::sync::Arc::<str>::from(val.as_str()),
        ));
    }
    headers
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_value_extracts_correctly() {
        let evidence = build_cors_evidence(&Some("https://evil.com".into()), &Some("true".into()));
        assert_eq!(evidence.len(), 2);
        assert_eq!(&*evidence[0].0, "access-control-allow-origin");
        assert_eq!(&*evidence[1].0, "access-control-allow-credentials");
    }

    #[test]
    fn evidence_handles_none() {
        let evidence = build_cors_evidence(&None, &None);
        assert!(evidence.is_empty());
    }

    #[test]
    fn evil_origin_is_https() {
        assert!(EVIL_ORIGIN.starts_with("https://"));
    }

    #[test]
    fn build_cors_evidence_only_acao() {
        let evidence = build_cors_evidence(&Some("*".into()), &None);
        assert_eq!(evidence.len(), 1);
        assert_eq!(&*evidence[0].0, "access-control-allow-origin");
        assert_eq!(&*evidence[0].1, "*");
    }

    #[test]
    fn build_cors_evidence_only_acac() {
        let evidence = build_cors_evidence(&None, &Some("true".into()));
        assert_eq!(evidence.len(), 1);
        assert_eq!(&*evidence[0].0, "access-control-allow-credentials");
    }

    #[test]
    fn null_origin_is_lowercase() {
        assert_eq!(NULL_ORIGIN, "null");
    }

    #[test]
    fn evil_origin_contains_evil_com() {
        assert!(EVIL_ORIGIN.contains("evil.com"));
    }

    #[test]
    fn build_cors_evidence_preserves_values() {
        let evidence = build_cors_evidence(&Some("https://example.com".into()), &Some("false".into()));
        assert_eq!(&*evidence[0].1, "https://example.com");
        assert_eq!(&*evidence[1].1, "false");
    }

    #[test]
    fn build_cors_evidence_empty_strings_adversarial() {
        let evidence = build_cors_evidence(&Some("".into()), &Some("".into()));
        assert_eq!(evidence.len(), 2);
        assert_eq!(&*evidence[0].1, "");
        assert_eq!(&*evidence[1].1, "");
    }

    #[test]
    fn build_cors_evidence_special_chars_in_origin_adversarial() {
        let evidence = build_cors_evidence(&Some("https://evil.com?x=1&y=2".into()), &None);
        assert_eq!(evidence.len(), 1);
        assert_eq!(&*evidence[0].1, "https://evil.com?x=1&y=2");
    }

    #[test]
    fn build_cors_evidence_unicode_in_origin_adversarial() {
        let evidence = build_cors_evidence(&Some("https://日本語.example.com".into()), &None);
        assert_eq!(evidence.len(), 1);
        assert_eq!(&*evidence[0].1, "https://日本語.example.com");
    }

    // ── Dangerous-methods condition logic (anti-rig for §15 test 6) ────────

    /// Anti-rig: pin the precedence of the dangerous-methods condition.
    /// The condition must fire when any dangerous method AND wildcard appears,
    /// OR when two or more dangerous methods are present, but NOT when only
    /// one dangerous method is listed without a wildcard.
    #[test]
    fn dangerous_methods_condition_requires_wildcard_or_two_plus() {
        // Helper that mirrors the probe condition with token-exact matching.
        fn should_fire(methods_upper: &str) -> bool {
            let tokens: std::collections::HashSet<&str> =
                methods_upper.split(|c: char| c == ',' || c.is_whitespace()).collect();
            let dangerous: Vec<&str> = ["DELETE", "PUT", "PATCH"]
                .iter()
                .filter(|m| tokens.contains(**m))
                .copied()
                .collect();
            (tokens.contains("*") && !dangerous.is_empty())
                || dangerous.len() >= 2
        }

        // One dangerous + wildcard → fire.
        assert!(should_fire("GET, DELETE, *"), "DELETE + wildcard must fire");

        // Two dangerous, no wildcard → fire.
        assert!(should_fire("GET, DELETE, PUT"), "DELETE + PUT must fire");

        // Three dangerous → fire.
        assert!(should_fire("DELETE, PUT, PATCH"), "all three dangerous must fire");

        // One dangerous, no wildcard → must NOT fire (would be false positive).
        assert!(!should_fire("GET, DELETE"), "single dangerous method without wildcard must NOT fire");
        assert!(!should_fire("GET, PUT"), "single dangerous method without wildcard must NOT fire");
        assert!(!should_fire("GET, PATCH"), "single dangerous method without wildcard must NOT fire");

        // No dangerous methods → must NOT fire.
        assert!(!should_fire("GET, POST"), "no dangerous methods must NOT fire");
        assert!(!should_fire("GET, *"), "wildcard alone with no dangerous method must NOT fire");

        // Substring false positive: "INPUT" must not match "PUT",
        // "PATCHED" must not match "PATCH". Token-exact matching prevents this.
        assert!(!should_fire("GET, INPUT"), "INPUT must not match PUT via substring");
        assert!(!should_fire("GET, PATCHED"), "PATCHED must not match PATCH via substring");
        assert!(!should_fire("GET, COMPUTE, OUTPUT"), "OUTPUT must not match PUT via substring");
    }
}
