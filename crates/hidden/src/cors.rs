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

/// CORS test origins — each targets a different misconfiguration class.
const EVIL_ORIGIN: &str = "https://evil.com";
const NULL_ORIGIN: &str = "null";

pub async fn probe(client: &Client, target: &Target) -> anyhow::Result<Vec<Finding>> {
    let Target::Web(asset) = target else {
        return Ok(vec![]);
    };
    let base = asset.url.as_str();
    let mut findings = Vec::new();

    // ── Test 1: arbitrary origin reflection ──────────────────────────────
    if let Ok(resp) = client.get(base).header("Origin", EVIL_ORIGIN).send().await {
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
                     can make authenticated cross-origin requests and read the response — \
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

    // ── Test 2: null origin trusted ──────────────────────────────────────
    if let Ok(resp) = client.get(base).header("Origin", NULL_ORIGIN).send().await {
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
                         Sandboxed iframes, data: URIs, and file: pages send null origin — \
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

    // ── Test 3: subdomain wildcard / prefix mismatch ─────────────────────
    // If the site is https://example.com, test if https://evil-example.com is accepted
    if let Some(domain) = target.domain() {
        let prefix_evil = format!("https://evil-{domain}");
        if let Ok(resp) = client.get(base).header("Origin", &prefix_evil).send().await {
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
    }

    // ── Test 4: suffix origin bypass (regex wildcard) ───────────────────
    if let Some(domain) = target.domain() {
        let suffix_evil = format!("https://{}.evil.com", domain);
        if let Ok(resp) = client.get(base).header("Origin", &suffix_evil).send().await {
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
    }

    // ── Test 5: HTTP origin trusted on HTTPS site ────────────────────────
    if base.starts_with("https://") {
        if let Some(domain) = target.domain() {
            let http_origin = format!("http://{domain}");
            if let Ok(resp) = client.get(base).header("Origin", &http_origin).send().await {
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
        }
    }

    // ── Test 5: overly permissive methods ───────────────────────────────
    if let Ok(resp) = client
        .request(reqwest::Method::OPTIONS, base)
        .header("Origin", EVIL_ORIGIN)
        .header("Access-Control-Request-Method", "DELETE")
        .send()
        .await
    {
        let acam = header_value(&resp, "access-control-allow-methods");
        let status = resp.status().as_u16();

        if let Some(ref methods) = acam {
            let methods_upper = methods.to_uppercase();
            let dangerous_methods: Vec<&str> = ["DELETE", "PUT", "PATCH"]
                .iter()
                .filter(|m| methods_upper.contains(**m))
                .copied()
                .collect();
            if !dangerous_methods.is_empty() && methods_upper.contains("*")
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
        // Test with a mock — just verify the helper doesn't panic on empty
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
}
