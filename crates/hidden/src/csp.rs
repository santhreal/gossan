//! Content Security Policy (CSP) analysis.
//!
//! Fetches the target and inspects the `Content-Security-Policy` header for:
//!
//! - **Missing CSP entirely**: any XSS is game over, no mitigations.
//! - **`unsafe-inline`** in `script-src`: defeats the primary purpose of CSP
//!   against script injection.
//! - **`unsafe-eval`** in `script-src`: allows `eval()`, `Function()`,
//!   `setTimeout(string)`: classic XSS gadgets.
//! - **Wildcard `*` in `script-src`** (loads scripts from any domain).
//! - **`data:` URI in `script-src`**: allows `<script src="data:...">`.
//! - **Missing `frame-ancestors`**: clickjacking is possible.
//! - **`report-only` without enforcement**: CSP exists but isn't enforced.
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
        "script-src allows 'unsafe-inline', inline <script> tags and event handlers \
         bypass CSP entirely. Any XSS injection point becomes exploitable. \
         Fix: remove 'unsafe-inline' and use nonces or hashes for legitimate inline scripts.",
    ),
    (
        "'unsafe-eval'",
        Severity::Medium,
        "CSP: unsafe-eval in script-src",
        "script-src allows 'unsafe-eval', eval(), Function(), and setTimeout(string) \
         are permitted. Attackers with a DOM injection can execute arbitrary JS. \
         Fix: remove 'unsafe-eval' and refactor code to avoid eval-like patterns.",
    ),
    (
        "data:",
        Severity::High,
        "CSP: data: URI in script-src",
        "script-src allows data: URIs, attackers can inject scripts via \
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

    let resp = match client.get(base).send().await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("csp: request failed url={base} error={e}");
            return Ok(findings);
        }
    };
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
             Content-Security-Policy header. CSP is monitoring-only. XSS payloads \
             execute but are reported. Fix: deploy an enforcing CSP alongside report-only."
        } else {
            "No Content-Security-Policy header detected. Without CSP, any XSS \
             vulnerability has no browser-side mitigation, inline scripts, eval, and \
             third-party script loads are all unrestricted. \
             Fix: deploy a CSP with strict script-src (nonce or hash based)."
        };

        let severity = if csp_report_only.is_some() {
            Severity::Low
        } else {
            Severity::Medium
        };

        findings.push(
            crate::misconfig_finding(
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
                crate::misconfig_finding(
                    target,
                    Severity::Medium,
                    "CSP: wildcard * in script-src",
                    "script-src contains '*', scripts can be loaded from any domain. \
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
                    crate::misconfig_finding(target, severity, title, detail)
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
            crate::misconfig_finding(
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
fn parse_directives(csp: &str) -> Vec<(String, Vec<&str>)> {
    csp.split(';')
        .filter_map(|directive| {
            let parts: Vec<&str> = directive.split_whitespace().collect();
            if parts.is_empty() {
                return None;
            }
            let name = parts[0].to_lowercase();
            let values = parts[1..].to_vec();
            Some((name, values))
        })
        .collect()
}

/// Build evidence headers for CSP findings.
fn csp_evidence_headers(
    csp: &Option<String>,
    csp_ro: &Option<String>,
) -> Vec<(std::sync::Arc<str>, std::sync::Arc<str>)> {
    let mut headers = Vec::new();
    if let Some(val) = csp {
        headers.push((
            "content-security-policy".into(),
            std::sync::Arc::<str>::from(val.as_str()),
        ));
    }
    if let Some(val) = csp_ro {
        headers.push((
            "content-security-policy-report-only".into(),
            std::sync::Arc::<str>::from(val.as_str()),
        ));
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
        assert_eq!(directives[1].1, vec!["'self'", "'unsafe-inline'", "https://cdn.example.com"]);
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

    #[test]
    fn parse_directives_with_leading_trailing_whitespace() {
        let csp = "  default-src 'self'  ;  script-src 'none'  ";
        let directives = parse_directives(csp);
        assert_eq!(directives.len(), 2);
        assert_eq!(directives[0].0, "default-src");
        assert_eq!(directives[1].0, "script-src");
    }

    #[test]
    fn parse_directives_single_directive_no_values() {
        let csp = "upgrade-insecure-requests";
        let directives = parse_directives(csp);
        assert_eq!(directives.len(), 1);
        assert_eq!(directives[0].0, "upgrade-insecure-requests");
        assert!(directives[0].1.is_empty());
    }

    #[test]
    fn csp_evidence_headers_only_report_only() {
        let headers = csp_evidence_headers(&None, &Some("script-src 'none'".into()));
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0.as_ref(), "content-security-policy-report-only");
    }

    #[test]
    fn csp_evidence_headers_only_enforcing() {
        let headers = csp_evidence_headers(&Some("default-src 'self'".into()), &None);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0.as_ref(), "content-security-policy");
    }

    #[test]
    fn parse_directives_lowercases_names_preserves_values() {
        let csp = "Script-Src 'Self'";
        let directives = parse_directives(csp);
        assert_eq!(directives[0].0, "script-src");
        assert_eq!(directives[0].1, vec!["'Self'"]);
    }

    /// Adversarial: mixed-case directive names must be normalised so the
    /// scanner recognises them during lookup.
    #[test]
    fn parse_directives_case_insensitive_script_src() {
        let csp = "Script-Src 'unsafe-inline'";
        let directives = parse_directives(csp);
        assert_eq!(directives[0].0, "script-src");
        assert_eq!(directives[0].1, vec!["'unsafe-inline'"]);
    }

    #[test]
    fn parse_directives_case_insensitive_frame_ancestors() {
        let csp = "Frame-Ancestors 'self'";
        let directives = parse_directives(csp);
        assert_eq!(directives[0].0, "frame-ancestors");
    }

    #[test]
    fn parse_directives_case_insensitive_default_src() {
        let csp = "Default-Src 'self'; Style-SRC *";
        let directives = parse_directives(csp);
        assert_eq!(directives[0].0, "default-src");
        assert_eq!(directives[1].0, "style-src");
    }

    #[test]
    fn parse_directives_with_multiple_semicolons() {
        let csp = "default-src 'self';;; script-src 'none'";
        let directives = parse_directives(csp);
        assert_eq!(directives.len(), 2);
    }

    #[test]
    fn parse_directives_single_value() {
        let csp = "default-src 'self'";
        let directives = parse_directives(csp);
        assert_eq!(directives[0].1.len(), 1);
    }

    #[test]
    fn csp_evidence_headers_empty_strings() {
        let headers = csp_evidence_headers(&Some("".into()), &Some("".into()));
        assert_eq!(headers.len(), 2);
        assert_eq!(&*headers[0].1, "");
    }

    #[test]
    fn parse_directives_with_tabs() {
        let csp = "default-src\t'self';\tscript-src\t'none'";
        let directives = parse_directives(csp);
        assert_eq!(directives.len(), 2);
    }

    #[test]
    fn parse_directives_preserves_https_values() {
        let csp = "script-src https://cdn.example.com";
        let directives = parse_directives(csp);
        assert_eq!(directives[0].1, vec!["https://cdn.example.com"]);
    }

    #[test]
    fn parse_directives_empty_string_adversarial() {
        let directives = parse_directives("");
        assert!(directives.is_empty());
    }

    #[test]
    fn parse_directives_only_whitespace_adversarial() {
        let directives = parse_directives("   \t\n  ");
        assert!(directives.is_empty());
    }

    #[test]
    fn parse_directives_with_inline_script_adversarial() {
        let csp = "script-src 'self' 'unsafe-inline'";
        let directives = parse_directives(csp);
        assert_eq!(directives[0].1, vec!["'self'", "'unsafe-inline'"]);
    }

    #[test]
    fn parse_directives_with_nonce_adversarial() {
        let csp = "script-src 'nonce-abc123'";
        let directives = parse_directives(csp);
        assert_eq!(directives[0].1, vec!["'nonce-abc123'"]);
    }

    #[test]
    fn parse_directives_with_hash_adversarial() {
        let csp = "script-src 'sha256-abc123'";
        let directives = parse_directives(csp);
        assert_eq!(directives[0].1, vec!["'sha256-abc123'"]);
    }

    #[test]
    fn parse_directives_frame_ancestors_none_adversarial() {
        let csp = "frame-ancestors 'none'";
        let directives = parse_directives(csp);
        assert_eq!(directives[0].0, "frame-ancestors");
        assert_eq!(directives[0].1, vec!["'none'"]);
    }

    #[test]
    fn dangerous_script_values_cover_unsafe_inline_adversarial() {
        assert!(DANGEROUS_SCRIPT_VALUES.iter().any(|(v, _, _, _)| *v == "'unsafe-inline'"));
    }

    #[test]
    fn dangerous_script_values_cover_unsafe_eval_adversarial() {
        assert!(DANGEROUS_SCRIPT_VALUES.iter().any(|(v, _, _, _)| *v == "'unsafe-eval'"));
    }

    #[test]
    fn dangerous_script_values_cover_data_adversarial() {
        assert!(DANGEROUS_SCRIPT_VALUES.iter().any(|(v, _, _, _)| *v == "data:"));
    }

    /// Adversarial: extreme-length CSP header with many semicolons must not
    /// cause unbounded growth or panic.
    #[test]
    fn parse_directives_extreme_length() {
        let csp = "default-src 'self';".repeat(10_000);
        let directives = parse_directives(&csp);
        assert_eq!(directives.len(), 10_000);
    }

    /// Adversarial: malformed directive with no values.
    #[test]
    fn parse_directives_no_values() {
        let csp = "upgrade-insecure-requests";
        let directives = parse_directives(csp);
        assert_eq!(directives.len(), 1);
        assert_eq!(directives[0].0, "upgrade-insecure-requests");
        assert!(directives[0].1.is_empty());
    }

    /// Adversarial: empty CSP string.
    #[test]
    fn parse_directives_empty() {
        let directives = parse_directives("");
        assert!(directives.is_empty());
    }

    /// Property tests for CSP parsing.
    #[cfg(test)]
    mod proptests {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #[test]
            fn prop_parse_directives_never_panics(csp in "\\PC*") {
                let _ = parse_directives(&csp);
            }

            #[test]
            fn prop_parse_directives_preserves_directive_count(
                parts in proptest::collection::vec("[a-z]+", 0..20)
            ) {
                let csp = parts.join("; ");
                let directives = parse_directives(&csp);
                // Each non-empty part becomes one directive
                let expected = parts.iter().filter(|p| !p.is_empty()).count();
                prop_assert_eq!(directives.len(), expected);
            }

            #[test]
            fn prop_csp_evidence_headers_never_panics(
                csp in proptest::option::of("\\PC*"),
                csp_ro in proptest::option::of("\\PC*")
            ) {
                let _ = csp_evidence_headers(&csp, &csp_ro);
            }
        }
    }
}
