//! WebAssembly (.wasm) secrets scanner.
//!
//! WASM binary files contain a "Data" section where string literals live in
//! plaintext — API keys, tokens, and URLs hardcoded in Rust/Go/C++ code that
//! was compiled to WASM are fully readable without decompilation.
//!
//! Strategy:
//!   1. Scan HTML for <script src="*.wasm">, <link href="*.wasm">, and JS fetch("*.wasm")
//!   2. Download each .wasm file
//!   3. Extract the data/code sections as printable ASCII strings (like `strings` binary)
//!   4. Run the same secret-detection regexes used for JS files
//!
//! Also flags: hardcoded internal URLs, debug flags, and production API endpoints
//! that should not be in a client-side WASM binary.

use gossan_core::Target;
use regex::Regex;
use secfinding::{Evidence, Finding, Severity};
use std::sync::OnceLock;

fn wasm_url_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r#"(?:src|href|fetch|import|load)\s*(?:=|\()\s*['"]?([^\s'"]+\.wasm)"#)
            .expect("static wasm URL regex is valid")
    })
}

/// Extract runs of printable ASCII ≥ 6 characters from binary data.
/// Mirrors what the `strings` utility does — finds string literals in WASM data sections.
fn extract_strings(data: &[u8]) -> Vec<String> {
    let mut results = Vec::new();
    let mut current = Vec::new();

    for &b in data {
        if b.is_ascii_graphic() || b == b' ' {
            current.push(b);
        } else {
            if current.len() >= 6 {
                if let Ok(s) = std::str::from_utf8(&current) {
                    results.push(s.to_string());
                }
            }
            current.clear();
        }
    }
    if current.len() >= 6 {
        if let Ok(s) = std::str::from_utf8(&current) {
            results.push(s.to_string());
        }
    }
    results
}

/// Secret patterns to run against extracted WASM strings.
/// A subset of the JS secrets rules — patterns that are realistic in compiled code.
const WASM_SECRET_PATTERNS: &[(&str, &str, Severity)] = &[
    (
        r"AKIA[0-9A-Z]{16}",
        "AWS Access Key in WASM",
        Severity::Critical,
    ),
    (
        r"AIza[0-9A-Za-z\-_]{35}",
        "GCP API Key in WASM",
        Severity::High,
    ),
    (
        r"ghp_[a-zA-Z0-9]{36}",
        "GitHub Token in WASM",
        Severity::Critical,
    ),
    (
        r"sk-[a-zA-Z0-9]{48}",
        "OpenAI API Key in WASM",
        Severity::Critical,
    ),
    (
        r"sk_live_[0-9a-zA-Z]{24,}",
        "Stripe Secret Key in WASM",
        Severity::Critical,
    ),
    (
        r"xox[baprs]-[0-9a-zA-Z\-]{10,48}",
        "Slack Token in WASM",
        Severity::High,
    ),
    (
        r"SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}",
        "SendGrid Key in WASM",
        Severity::High,
    ),
    (r"npm_[a-zA-Z0-9]{36}", "NPM Token in WASM", Severity::High),
    (
        r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY",
        "Private Key in WASM",
        Severity::Critical,
    ),
    (
        r"(?:password|passwd|secret|api_?key)\s*=\s*[^\s]{8,}",
        "Hardcoded credential in WASM",
        Severity::Medium,
    ),
    (
        r"https?://(?:localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)[:/]",
        "Internal URL hardcoded in WASM",
        Severity::High,
    ),
];

struct CompiledWasmRule {
    re: Regex,
    name: &'static str,
    severity: Severity,
}

fn compiled_wasm_rules() -> &'static Vec<CompiledWasmRule> {
    static COMPILED: OnceLock<Vec<CompiledWasmRule>> = OnceLock::new();
    COMPILED.get_or_init(|| {
        WASM_SECRET_PATTERNS
            .iter()
            .filter_map(|(pat, name, sev)| {
                Regex::new(pat).ok().map(|re| CompiledWasmRule {
                    re,
                    name,
                    severity: *sev,
                })
            })
            .collect()
    })
}

pub async fn probe(
    client: &reqwest::Client,
    html: &str,
    base: &url::Url,
    target: &Target,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Extract .wasm URLs from the HTML
    let wasm_urls: Vec<String> = wasm_url_re()
        .captures_iter(html)
        .filter_map(|cap| cap.get(1))
        .filter_map(|m| base.join(m.as_str()).ok())
        .filter(|u| u.scheme() == "http" || u.scheme() == "https")
        .map(|u| u.to_string())
        .collect();

    if wasm_urls.is_empty() {
        return findings;
    }

    tracing::debug!(count = wasm_urls.len(), "WASM files found");

    for wasm_url in &wasm_urls {
        let Ok(resp) = client.get(wasm_url).send().await else {
            continue;
        };
        if resp.status().as_u16() != 200 {
            continue;
        }

        let Ok(bytes) = resp.bytes().await else {
            continue;
        };

        // Verify WASM magic bytes: \0asm
        if bytes.len() < 4 || &bytes[..4] != b"\x00asm" {
            continue; // not a valid WASM file
        }

        let size_kb = bytes.len() / 1024;
        let strings = extract_strings(&bytes);
        let virtual_body = strings.join("\n");

        // Run all secret detection rules — report each distinct type found
        let rules = compiled_wasm_rules();
        let mut had_secret = false;
        for rule in rules {
            if let Some(m) = rule.re.find(&virtual_body) {
                let matched = m.as_str();
                // Find the string literal containing the match for context
                let ctx = strings
                    .iter()
                    .find(|s| s.contains(matched))
                    .map(|s| s.chars().take(120).collect::<String>())
                    .unwrap_or_else(|| matched.chars().take(80).collect());

                findings.push(
                    crate::finding_builder(target, rule.severity,
                        format!("{} ({}KB)", rule.name, size_kb),
                        format!("WebAssembly binary at {} ({} KB, {} string literals extracted) \
                                 contains what appears to be a hardcoded secret. WASM data sections \
                                 are trivially readable — no decompiler needed, just `strings` or \
                                 wasm-objdump.", wasm_url, size_kb, strings.len()))
                    .evidence(Evidence::JsSnippet {
                        url: wasm_url.clone(),
                        line: 0, // WASM has no line numbers
                        snippet: ctx,
                    })
                    .tag("wasm").tag("secret").tag("exposure")
                    .exploit_hint(format!(
                        "# Extract all strings from WASM:\n\
                         curl -s '{}' | strings\n\
                         # Or with wasm-objdump:\n\
                         wasm-objdump -x -s {} | grep -A2 'Data'", wasm_url, wasm_url))
                    .build().expect("finding builder: required fields are set")
                );
                had_secret = true;
            }
        }

        // Even without secrets, flag that WASM exists — data sections are readable without decompilation
        if !had_secret {
            findings.push(
                crate::finding_builder(
                    target,
                    Severity::Info,
                    format!(
                        "WebAssembly binary: {} ({} KB)",
                        wasm_url.split('/').next_back().unwrap_or("?.wasm"),
                        size_kb
                    ),
                    format!(
                        "{} — {} string literals readable without decompilation. \
                             Review for hardcoded secrets, internal endpoints, and business logic.",
                        wasm_url,
                        strings.len()
                    ),
                )
                .tag("wasm")
                .tag("exposure")
                .build()
                .expect("finding builder: required fields are set"),
            );
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_strings_returns_printable_runs() {
        let strings = extract_strings(b"\0hello world\0abc\0SECRET123\0");
        assert_eq!(strings, vec!["hello world", "SECRET123"]);
    }

    #[test]
    fn wasm_url_regex_matches_common_attributes() {
        let html = r#"<script src="/pkg/app_bg.wasm"></script><link href="mod.wasm">"#;
        let urls: Vec<_> = wasm_url_re()
            .captures_iter(html)
            .filter_map(|cap| cap.get(1).map(|m| m.as_str().to_string()))
            .collect();
        assert!(urls.iter().any(|u| u.ends_with("app_bg.wasm")));
        assert!(urls.iter().any(|u| u.ends_with("mod.wasm")));
    }

    #[test]
    fn compiled_rules_include_high_value_secrets() {
        let names: Vec<_> = compiled_wasm_rules().iter().map(|r| r.name).collect();
        assert!(names.contains(&"AWS Access Key in WASM"));
        assert!(names.contains(&"Private Key in WASM"));
    }
}
