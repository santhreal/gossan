//! Content Security Policy (CSP) analysis.
//!
//! Fetches the target and inspects the `Content-Security-Policy` header for:
//!
//! - **Missing CSP entirely** — any XSS is game over, no mitigations.
//! - **`unsafe-inline`** in `script-src` — defeats the primary purpose of CSP
//!   against script injection.
//! - **`unsafe-eval`** in `script-src` — allows `eval()`, `Function()`,
//!   `setTimeout(string)` — classic XSS gadgets.
//! - **Wildcard `*` in `script-src`** — loads scripts from any domain.
//! - **`data:` URI in `script-src`** — allows `<script src="data:...">`.
//! - **Missing `frame-ancestors`** — clickjacking is possible.
//! - **`report-only` without enforcement** — CSP exists but isn't enforced.
//!
//! Severity is calibrated to real-world impact:
//! - Missing CSP entirely: Medium (it's defense-in-depth, not a vulnerability per se)
//! - `unsafe-inline` in script-src: High (XSS bypass)
//! - `unsafe-eval`: Medium (requires existing injection vector)
//! - Wildcard/data: High (easy script gadget)
//! - Missing frame-ancestors: Low (clickjacking is low-impact on most APIs)

use gossan_core::Target;
use reqwest::Client;
use secfinding::{Evidence, Finding, Severity};

/// CSP directives that are dangerous in `script-src`.
const DANGEROUS_SCRIPT_VALUES: &[(&str, Severity, &str, &str)] = &[
    (
        "'unsafe-inline'",
        Severity::High,
        "CSP: unsafe-inline in script-src",
        "script-src allows 'unsafe-inline' — inline <script> tags and event handlers \
         bypass CSP entirely. Any XSS injection point becomes exploitable. \
         Fix: remove 'unsafe-inline' and use nonces or hashes for legitimate inline scripts.",
    ),
    (
        "'unsafe-eval'",
        Severity::Medium,
        "CSP: unsafe-eval in script-src",
        "script-src allows 'unsafe-eval' — eval(), Function(), and setTimeout(string) \
         are permitted. Attackers with a DOM injection can execute arbitrary JS. \
         Fix: remove 'unsafe-eval' and refactor code to avoid eval-like patterns.",
    ),
    (
        "data:",
        Severity::High,
        "CSP: data: URI in script-src",
        "script-src allows data: URIs — attackers can inject scripts via \
         <script src=\"data:text/javascript,...\">. \
         Fix: remove 'data:' from script-src.",
    ),
];

pub async fn probe(client: &Client, target: &Target) -> anyhow::Result<Vec<Finding>> {
    let Target::Web(asset) = target else {
        return Ok(vec![]);
    };
    let base = asset.url.as_str();
    let mut findings = Vec::new();

    let resp = client.get(base).send().await?;
    let status = resp.status().as_u16();
    let headers = resp.headers().clone();

    let csp_header = headers
        .get("content-security-policy")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let csp_report_only = headers
        .get("content-security-policy-report-only")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // ── Missing CSP entirely ─────────────────────────────────────────────
    if csp_header.is_none() {
        let detail = if csp_report_only.is_some() {
            "The site has Content-Security-Policy-Report-Only but no enforcing \
             Content-Security-Policy header. CSP is monitoring-only — XSS payloads \
             execute but are reported. Fix: deploy an enforcing CSP alongside report-only."
        } else {
            "No Content-Security-Policy header detected. Without CSP, any XSS \
             vulnerability has no browser-side mitigation — inline scripts, eval, and \
             third-party script loads are all unrestricted. \
             Fix: deploy a CSP with strict script-src (nonce or hash based)."
        };

        let severity = if csp_report_only.is_some() {
            Severity::Low
        } else {
            Severity::Medium
        };

        findings.push(
            crate::finding_builder(
                target,
                severity,
                if csp_report_only.is_some() {
                    "CSP: report-only without enforcement"
                } else {
                    "CSP: no Content-Security-Policy header"
                },
                detail,
            )
            .evidence(Evidence::HttpResponse {
                status,
                headers: csp_evidence_headers(&csp_header, &csp_report_only),
                body_excerpt: None,
            })
            .tag("csp")
            .tag("web")
            .tag("headers")
            .build()
            .map_err(|e| anyhow::anyhow!(e))?,
        );

        return Ok(findings);
    }

    // ── Analyze the enforcing CSP ────────────────────────────────────────
    let csp = csp_header.as_deref().unwrap_or("");
    let directives = parse_directives(csp);

    // Find script-src (or fall back to default-src)
    let script_src = directives
        .iter()
        .find(|(name, _)| *name == "script-src")
        .or_else(|| directives.iter().find(|(name, _)| *name == "default-src"));

    if let Some((_, values)) = script_src {
        let values_lower: Vec<String> = values.iter().map(|v| v.to_lowercase()).collect();

        // Check for wildcard
        if values_lower.iter().any(|v| v == "*") {
            findings.push(
                crate::finding_builder(
                    target,
                    Severity::High,
                    "CSP: wildcard * in script-src",
                    "script-src contains '*' — scripts can be loaded from any domain. \
                     This defeats the purpose of CSP entirely. An attacker can host \
                     malicious JS on any domain and inject it. \
                     Fix: replace '*' with specific trusted domains or use nonces.",
                )
                .evidence(Evidence::HttpResponse {
                    status,
                    headers: csp_evidence_headers(&csp_header, &csp_report_only),
                    body_excerpt: None,
                })
                .tag("csp")
                .tag("web")
                .tag("misconfiguration")
                .build()
                .map_err(|e| anyhow::anyhow!(e))?,
            );
        }

        // Check for dangerous values
        for &(dangerous_value, severity, title, detail) in DANGEROUS_SCRIPT_VALUES {
            if values_lower.iter().any(|v| v == dangerous_value) {
                findings.push(
                    crate::finding_builder(target, severity, title, detail)
                        .evidence(Evidence::HttpResponse {
                            status,
                            headers: csp_evidence_headers(&csp_header, &csp_report_only),
                            body_excerpt: None,
                        })
                        .tag("csp")
                        .tag("web")
                        .tag("misconfiguration")
                        .build()
                        .map_err(|e| anyhow::anyhow!(e))?,
                );
            }
        }
    }

    // ── Missing frame-ancestors (clickjacking) ───────────────────────────
    let has_frame_ancestors = directives
        .iter()
        .any(|(name, _)| *name == "frame-ancestors");
    let has_xfo = headers.get("x-frame-options").is_some();

    if !has_frame_ancestors && !has_xfo {
        findings.push(
            crate::finding_builder(
                target,
                Severity::Low,
                "CSP: missing frame-ancestors (clickjacking)",
                "Neither frame-ancestors in CSP nor X-Frame-Options header is set. \
                 The page can be framed by any origin, enabling clickjacking attacks. \
                 Fix: add frame-ancestors 'self' to CSP or set X-Frame-Options: DENY.",
            )
            .evidence(Evidence::HttpResponse {
                status,
                headers: csp_evidence_headers(&csp_header, &csp_report_only),
                body_excerpt: None,
            })
            .tag("csp")
            .tag("clickjacking")
            .tag("web")
            .build()
            .map_err(|e| anyhow::anyhow!(e))?,
        );
    }

    Ok(findings)
}

/// Parse a CSP header into directive name → values.
fn parse_directives(csp: &str) -> Vec<(&str, Vec<&str>)> {
    csp.split(';')
        .filter_map(|directive| {
            let parts: Vec<&str> = directive.split_whitespace().collect();
            if parts.is_empty() {
                return None;
            }
            let name = parts[0];
            let values = parts[1..].to_vec();
            Some((name, values))
        })
        .collect()
}

/// Build evidence headers for CSP findings.
fn csp_evidence_headers(csp: &Option<String>, csp_ro: &Option<String>) -> Vec<(String, String)> {
    let mut headers = Vec::new();
    if let Some(val) = csp {
        headers.push(("content-security-policy".into(), val.clone()));
    }
    if let Some(val) = csp_ro {
        headers.push(("content-security-policy-report-only".into(), val.clone()));
    }
    headers
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic_csp() {
        let csp = "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.example.com; style-src *";
        let directives = parse_directives(csp);
        assert_eq!(directives.len(), 3);
        assert_eq!(directives[0].0, "default-src");
        assert_eq!(directives[0].1, vec!["'self'"]);
        assert_eq!(directives[1].0, "script-src");
        assert_eq!(
            directives[1].1,
            vec!["'self'", "'unsafe-inline'", "https://cdn.example.com"]
        );
        assert_eq!(directives[2].0, "style-src");
        assert_eq!(directives[2].1, vec!["*"]);
    }

    #[test]
    fn parse_empty_csp() {
        let directives = parse_directives("");
        assert!(directives.is_empty());
    }

    #[test]
    fn parse_directive_with_trailing_semicolons() {
        let csp = "default-src 'self';;";
        let directives = parse_directives(csp);
        assert_eq!(directives.len(), 1);
    }

    #[test]
    fn evidence_headers_both_present() {
        let headers = csp_evidence_headers(
            &Some("default-src 'self'".into()),
            &Some("script-src 'none'".into()),
        );
        assert_eq!(headers.len(), 2);
    }

    #[test]
    fn evidence_headers_none() {
        let headers = csp_evidence_headers(&None, &None);
        assert!(headers.is_empty());
    }
}
