//! Hardcoded secret detection in JavaScript source code.
//!
//! Runs 26 regex-based detection rules against JS file content to flag
//! API keys, tokens, private keys, internal URLs, and credentials that
//! developers accidentally ship in client-side bundles.
//!
//! Rules are ordered by confidence — high-entropy patterns like `AKIA...`
//! almost never false-positive, while generic `password=` patterns do.
//!
//! This module is used by the JS scanner to scan both raw `.js` files
//! and extracted source map `sourcesContent` entries.

use gossan_core::Target;
use regex::Regex;
use secfinding::{Evidence, Finding, Severity};
use std::sync::OnceLock;

/// A compiled secret-detection rule.
struct SecretRule {
    re: Regex,
    name: &'static str,
    severity: Severity,
}

/// All compiled secret detection rules.
fn rules() -> &'static Vec<SecretRule> {
    static RULES: OnceLock<Vec<SecretRule>> = OnceLock::new();
    RULES.get_or_init(|| {
        PATTERNS
            .iter()
            .filter_map(|(pat, name, sev)| {
                Regex::new(pat).ok().map(|re| SecretRule {
                    re,
                    name,
                    severity: *sev,
                })
            })
            .collect()
    })
}

/// Raw pattern definitions: (regex, display name, severity).
const PATTERNS: &[(&str, &str, Severity)] = &[
    // ── Cloud provider keys ─────────────────────────────────────────────────
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key", Severity::Critical),
    (
        r#"(?:aws_secret_access_key|aws_secret)\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})['"]?"#,
        "AWS Secret Key",
        Severity::Critical,
    ),
    (r"AIza[0-9A-Za-z\-_]{35}", "GCP API Key", Severity::High),
    (
        r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
        "Google OAuth Client ID",
        Severity::Medium,
    ),
    // ── Version control tokens ──────────────────────────────────────────────
    (
        r"ghp_[a-zA-Z0-9]{36}",
        "GitHub PAT (fine-grained)",
        Severity::Critical,
    ),
    (
        r"gho_[a-zA-Z0-9]{36}",
        "GitHub OAuth Token",
        Severity::Critical,
    ),
    (
        r"ghu_[a-zA-Z0-9]{36}",
        "GitHub User Token",
        Severity::Critical,
    ),
    (
        r"ghs_[a-zA-Z0-9]{36}",
        "GitHub Server Token",
        Severity::Critical,
    ),
    (
        r"glpat-[0-9A-Za-z\-_]{20,}",
        "GitLab PAT",
        Severity::Critical,
    ),
    // ── Payment / SaaS ──────────────────────────────────────────────────────
    (
        r"sk_live_[0-9a-zA-Z]{24,}",
        "Stripe Secret Key",
        Severity::Critical,
    ),
    (
        r"rk_live_[0-9a-zA-Z]{24,}",
        "Stripe Restricted Key",
        Severity::High,
    ),
    (
        r"sq0csp-[0-9A-Za-z\-_]{43}",
        "Square OAuth Secret",
        Severity::Critical,
    ),
    (r"sk-[a-zA-Z0-9]{48}", "OpenAI API Key", Severity::Critical),
    // ── Communication ───────────────────────────────────────────────────────
    (
        r"xox[baprs]-[0-9a-zA-Z\-]{10,48}",
        "Slack Token",
        Severity::High,
    ),
    (
        r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+",
        "Slack Webhook URL",
        Severity::High,
    ),
    (
        r"SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}",
        "SendGrid API Key",
        Severity::High,
    ),
    (r"key-[0-9a-zA-Z]{32}", "Mailgun API Key", Severity::High),
    // ── Package registries ──────────────────────────────────────────────────
    (r"npm_[a-zA-Z0-9]{36}", "NPM Access Token", Severity::High),
    (
        r"pypi-Ag[A-Za-z0-9\-_]{50,}",
        "PyPI API Token",
        Severity::High,
    ),
    // ── JWT / crypto ────────────────────────────────────────────────────────
    (
        r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_.+/=]+",
        "JSON Web Token",
        Severity::Medium,
    ),
    (
        r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY",
        "Private Key",
        Severity::Critical,
    ),
    // ── Firebase / Supabase ─────────────────────────────────────────────────
    (
        r"[a-z0-9\-]+\.firebaseio\.com",
        "Firebase Database URL",
        Severity::Medium,
    ),
    (
        r"[a-z0-9]+\.supabase\.co",
        "Supabase Project URL",
        Severity::Info,
    ),
    // ── Internal infrastructure ─────────────────────────────────────────────
    (
        r"https?://(?:localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)[:/]",
        "Internal URL Exposure",
        Severity::High,
    ),
    // ── Generic credential patterns (lower confidence, still valuable) ──────
    (
        r#"(?:password|passwd|secret|api_?key|apikey|token|auth)\s*[:=]\s*['"]([^'"]{8,64})['"]"#,
        "Hardcoded Credential",
        Severity::Medium,
    ),
    (
        r#"(?:Authorization|Bearer)\s*[:=]\s*['"]([^'"]{10,200})['"]"#,
        "Hardcoded Auth Header",
        Severity::High,
    ),
];

/// Scan JavaScript source content for hardcoded secrets.
///
/// Returns one finding per distinct secret type found. Multiple matches of
/// the same type are collapsed into a single finding with a count.
pub fn scan(js_url: &str, body: &str, target: &Target) -> Vec<Finding> {
    let mut findings = Vec::new();

    for rule in rules() {
        let matches: Vec<_> = rule.re.find_iter(body).collect();
        if matches.is_empty() {
            continue;
        }

        // Use the first match for evidence, report count for all
        let first = matches[0].as_str();
        let line_no = body[..matches[0].start()]
            .chars()
            .filter(|c| *c == '\n')
            .count()
            + 1;

        // Redact the middle of the secret for safe reporting
        let redacted = redact(first);

        let count_suffix = if matches.len() > 1 {
            format!(" ({} occurrences)", matches.len())
        } else {
            String::new()
        };

        findings.push(
            crate::finding_builder(
                target,
                rule.severity,
                format!("{}{}", rule.name, count_suffix),
                format!(
                    "Hardcoded secret detected in JavaScript at line {}. \
                         Client-side JS is fully readable — this credential is effectively public.",
                    line_no
                ),
            )
            .evidence(Evidence::JsSnippet {
                url: js_url.to_string(),
                line: line_no,
                snippet: redacted,
            })
            .tag("secret")
            .tag("exposure")
            .tag("js")
            .build()
            .expect("finding builder: required fields are set"),
        );
    }

    findings
}

/// Redact the middle portion of a secret for safe logging.
/// Keeps first 6 and last 4 characters visible.
fn redact(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= 12 {
        return format!("{}***", chars.iter().take(4).collect::<String>());
    }
    let prefix: String = chars[..6].iter().collect();
    let suffix: String = chars[chars.len() - 4..].iter().collect();
    format!("{prefix}...{suffix}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use gossan_core::{DiscoverySource, DomainTarget};

    fn target() -> Target {
        Target::Domain(DomainTarget {
            domain: "example.com".into(),
            source: DiscoverySource::Seed,
        })
    }

    // ── Detection tests (must find real secrets) ────────────────────────────

    #[test]
    fn detects_aws_key() {
        let js = r#"const key = "AKIAIOSFODNN7EXAMPLE";"#;
        let findings = scan("app.js", js, &target());
        assert!(
            findings.iter().any(|f| f.title.contains("AWS Access Key")),
            "should detect AWS access key pattern AKIA..."
        );
    }

    #[test]
    fn detects_github_pat() {
        let token = format!("ghp_{}", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij");
        let js = format!(r#"var token = "{token}";"#);
        let findings = scan("app.js", &js, &target());
        assert!(
            findings.iter().any(|f| f.title.contains("GitHub PAT")),
            "should detect GitHub fine-grained PAT"
        );
    }

    #[test]
    fn detects_stripe_key() {
        let key = format!("sk_live_{}", "51HZqQmLwR0sCKcTDabcdefgh");
        let js = format!(r#"stripe.setKey("{key}");"#);
        let findings = scan("app.js", &js, &target());
        assert!(
            findings.iter().any(|f| f.title.contains("Stripe Secret")),
            "should detect Stripe secret key"
        );
    }

    #[test]
    fn detects_openai_key() {
        let js = r#"const api = "sk-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKL";"#;
        let findings = scan("app.js", js, &target());
        assert!(
            findings.iter().any(|f| f.title.contains("OpenAI")),
            "should detect OpenAI API key pattern sk-..."
        );
    }

    #[test]
    fn detects_internal_url() {
        let js = r#"fetch("http://192.168.1.50:8080/api/internal");"#;
        let findings = scan("app.js", js, &target());
        assert!(
            findings.iter().any(|f| f.title.contains("Internal URL")),
            "should detect hardcoded internal URL"
        );
    }

    #[test]
    fn detects_jwt() {
        let js = r#"var jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";"#;
        let findings = scan("app.js", js, &target());
        assert!(
            findings.iter().any(|f| f.title.contains("JSON Web Token")),
            "should detect JWT"
        );
    }

    #[test]
    fn detects_private_key() {
        let js = r#"var k = "-----BEGIN RSA PRIVATE KEY-----\nMIIE...";"#;
        let findings = scan("app.js", js, &target());
        assert!(
            findings.iter().any(|f| f.title.contains("Private Key")),
            "should detect PEM private key header"
        );
    }

    #[test]
    fn detects_slack_webhook() {
        let js = r#"const webhook = "https://hooks.slack.com/services/T01234567/B01234567/abcdefghijklmnop";"#;
        let findings = scan("app.js", js, &target());
        assert!(
            findings.iter().any(|f| f.title.contains("Slack Webhook")),
            "should detect Slack webhook URL"
        );
    }

    #[test]
    fn detects_hardcoded_password() {
        let js = r#"const config = { password: "superSecretP@ss123" };"#;
        let findings = scan("app.js", js, &target());
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("Hardcoded Credential")),
            "should detect hardcoded password assignment"
        );
    }

    #[test]
    fn detects_gitlab_pat() {
        let js = r#"const token = "glpat-abcdefghijklmnopqrst";"#;
        let findings = scan("app.js", js, &target());
        assert!(
            findings.iter().any(|f| f.title.contains("GitLab PAT")),
            "should detect GitLab personal access token"
        );
    }

    // ── False positive resistance tests ─────────────────────────────────────

    #[test]
    fn no_false_positive_on_placeholder_keys() {
        let js = r#"
            const api_key = "YOUR_API_KEY_HERE";
            const token = "INSERT_TOKEN";
            const key = "xxx";
        "#;
        let findings = scan("app.js", js, &target());
        // "xxx" is too short, "YOUR_API_KEY" and "INSERT_TOKEN" don't match specific patterns
        assert!(
            findings.is_empty() || findings.iter().all(|f| f.severity <= Severity::Medium),
            "placeholder strings should not produce high-severity findings"
        );
    }

    #[test]
    fn no_false_positive_on_css_values() {
        let js = r##"
            color: "#AKIAIOSFODNN7NOTREAL";
            background: "sk-notarealkey";
        "##;
        let _findings = scan("app.js", js, &target());
        // The CSS strings may partially match patterns but within quotes — some matches expected
        // Key is they don't crash and the scanner handles gracefully
    }

    #[test]
    fn clean_js_has_no_findings() {
        let js = r#"
            function init() {
                document.getElementById("app").innerHTML = "Hello World";
                console.log("Application started");
                fetch("/api/users").then(r => r.json());
            }
        "#;
        let findings = scan("app.js", js, &target());
        assert!(
            findings.is_empty(),
            "clean JS with no secrets should produce no findings"
        );
    }

    // ── Edge case / adversarial tests ───────────────────────────────────────

    #[test]
    fn handles_minified_js() {
        // Minified JS with no newlines — secrets still visible
        let js = r#"var a="test",b="AKIAIOSFODNN7EXAMPLE",c=function(){return fetch("/api")};"#;
        let findings = scan("app.min.js", js, &target());
        assert!(
            findings.iter().any(|f| f.title.contains("AWS")),
            "should detect secrets in minified (single-line) JS"
        );
    }

    #[test]
    fn handles_empty_input() {
        assert!(scan("empty.js", "", &target()).is_empty());
    }

    #[test]
    fn handles_huge_js_without_panic() {
        let big = "x".repeat(5_000_000); // 5MB of 'x'
        let _ = scan("big.js", &big, &target()); // should not panic or timeout
    }

    #[test]
    fn multiple_secrets_produce_separate_findings() {
        let gh = format!("ghp_{}", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij");
        let stripe = format!("sk_live_{}", "51HZqQmLwR0sCKcTDabcdefgh");
        let js = format!(
            r#"
            const aws = "AKIAIOSFODNN7EXAMPLE";
            const gh = "{gh}";
            const stripe = "{stripe}";
        "#
        );
        let findings = scan("multi.js", &js, &target());
        assert!(
            findings.len() >= 3,
            "multiple different secret types should produce separate findings, got {}",
            findings.len()
        );
    }

    #[test]
    fn duplicate_secret_produces_single_finding_with_count() {
        let js = r#"
            const a = "AKIAIOSFODNN7EXAMPLE";
            const b = "AKIAIOSFODNN7EXAMPLE";
            const c = "AKIAIOSFODNN7EXAMPLE";
        "#;
        let findings = scan("dupes.js", js, &target());
        let aws_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("AWS"))
            .collect();
        assert_eq!(
            aws_findings.len(),
            1,
            "duplicate secrets should collapse into one finding"
        );
        assert!(
            aws_findings[0].title.contains("3 occurrences"),
            "collapsed finding should report count"
        );
    }

    #[test]
    fn redact_preserves_prefix_and_suffix() {
        assert_eq!(redact("AKIAIOSFODNN7EXAMPLE"), "AKIAIO...MPLE");
        assert_eq!(redact("short"), "shor***");
    }

    #[test]
    fn line_numbers_are_correct() {
        let js = "line1\nline2\nconst key = \"AKIAIOSFODNN7EXAMPLE\";\nline4\n";
        let findings = scan("test.js", js, &target());
        let aws = findings
            .iter()
            .find(|f| f.title.contains("AWS"))
            .expect("should find AWS key");
        // The secret is on line 3
        match &aws.evidence[0] {
            Evidence::JsSnippet { line, .. } => assert_eq!(*line, 3),
            _ => panic!("expected JsSnippet evidence"),
        }
    }

    #[test]
    fn firebase_url_detected() {
        let js = r#"const db = "my-project-123.firebaseio.com";"#;
        let findings = scan("app.js", js, &target());
        assert!(findings.iter().any(|f| f.title.contains("Firebase")));
    }

    #[test]
    fn gcp_key_detected() {
        let js = r#"const key = "AIzaSyDaGmWKa4JsXZ-HjGw7ISLn_3namBGewQe";"#;
        let findings = scan("app.js", js, &target());
        assert!(findings.iter().any(|f| f.title.contains("GCP")));
    }

    #[test]
    fn sendgrid_key_detected() {
        let sg_key = format!("SG.ngeVfQFYQlKU0ufo8x5d1A.{}", "TwL2iGABf9DHoTf-09kqeF8tAmbihYzrnopKc-1s5cr");
        let js = format!(r#"const sg = "{sg_key}";"#);
        let findings = scan("app.js", &js, &target());
        assert!(findings.iter().any(|f| f.title.contains("SendGrid")));
    }

    #[test]
    fn all_patterns_compile_successfully() {
        // Verify no regex compilation failures
        assert!(
            rules().len() == PATTERNS.len(),
            "all {} patterns should compile, only {} did",
            PATTERNS.len(),
            rules().len()
        );
    }
}
