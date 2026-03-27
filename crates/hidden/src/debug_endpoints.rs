//! Debug/monitoring endpoint exposure scanner.
//!
//! Probes for common framework debug, profiler, and monitoring endpoints that
//! should never be accessible in production. These often leak environment
//! variables, database credentials, heap dumps, or application internals.
//!
//! | Endpoint | Framework | Risk |
//! |----------|-----------|------|
//! | `/actuator/env` | Spring Boot | Env vars / secrets |
//! | `/actuator/heapdump` | Spring Boot | Heap dump / creds in memory |
//! | `/__debug__/` | Django | Full interactive debugger |
//! | `/debug/pprof/` | Go pprof | CPU/memory profiles |
//! | `/metrics` | Prometheus | Internal service metrics |
//! | `/healthz` | Kubernetes | Deployment metadata |
//! | `/server-status` | Apache | Connection / request details |
//! | `/server-info` | Apache | Module configuration |
//! | `/_profiler/` | Symfony | Request profiler |
//! | `/elmah.axd` | ASP.NET ELMAH | Error log with stack traces |

use gossan_core::Target;
use reqwest::Client;
use secfinding::{Evidence, Finding, Severity};

/// A debug endpoint to probe: path, framework attribution, and severity.
struct DebugProbe {
    path: &'static str,
    name: &'static str,
    framework: &'static str,
    severity: Severity,
    /// Strings that confirm this is a real debug page (not a generic 200).
    confirm_strings: &'static [&'static str],
}

/// All known debug/monitoring endpoints.
const PROBES: &[DebugProbe] = &[
    // ── Spring Boot Actuator ─────────────────────────────────────────────
    DebugProbe {
        path: "/actuator",
        name: "Spring Boot Actuator Index",
        framework: "Spring Boot",
        severity: Severity::High,
        confirm_strings: &["_links", "actuator"],
    },
    DebugProbe {
        path: "/actuator/env",
        name: "Spring Boot Environment Variables",
        framework: "Spring Boot",
        severity: Severity::Critical,
        confirm_strings: &["propertySources", "systemProperties"],
    },
    DebugProbe {
        path: "/actuator/heapdump",
        name: "Spring Boot Heap Dump",
        framework: "Spring Boot",
        severity: Severity::Critical,
        // Heap dumps return binary; a 200 with Content-Type octet-stream is enough.
        confirm_strings: &[],
    },
    DebugProbe {
        path: "/actuator/configprops",
        name: "Spring Boot Config Properties",
        framework: "Spring Boot",
        severity: Severity::High,
        confirm_strings: &["beans", "prefix"],
    },
    DebugProbe {
        path: "/actuator/mappings",
        name: "Spring Boot Request Mappings",
        framework: "Spring Boot",
        severity: Severity::Medium,
        confirm_strings: &["dispatcherServlets", "requestMappingConditions"],
    },
    // ── Django ────────────────────────────────────────────────────────────
    DebugProbe {
        path: "/__debug__/",
        name: "Django Debug Toolbar",
        framework: "Django",
        severity: Severity::Critical,
        confirm_strings: &["djDebug", "debug toolbar"],
    },
    // ── Go pprof ─────────────────────────────────────────────────────────
    DebugProbe {
        path: "/debug/pprof/",
        name: "Go pprof Profiler",
        framework: "Go net/http/pprof",
        severity: Severity::High,
        confirm_strings: &["goroutine", "heap", "profile"],
    },
    // ── Prometheus / Kubernetes ───────────────────────────────────────────
    DebugProbe {
        path: "/metrics",
        name: "Prometheus Metrics Endpoint",
        framework: "Prometheus",
        severity: Severity::Medium,
        confirm_strings: &["# HELP", "# TYPE", "process_"],
    },
    DebugProbe {
        path: "/healthz",
        name: "Kubernetes Health Check",
        framework: "Kubernetes",
        severity: Severity::Info,
        confirm_strings: &[],
    },
    // ── Apache ───────────────────────────────────────────────────────────
    DebugProbe {
        path: "/server-status",
        name: "Apache Server Status",
        framework: "Apache httpd",
        severity: Severity::Medium,
        confirm_strings: &["Apache Server Status", "Total Accesses"],
    },
    DebugProbe {
        path: "/server-info",
        name: "Apache Server Info",
        framework: "Apache httpd",
        severity: Severity::High,
        confirm_strings: &["Server Settings", "Module Name"],
    },
    // ── Symfony ───────────────────────────────────────────────────────────
    DebugProbe {
        path: "/_profiler/",
        name: "Symfony Web Profiler",
        framework: "Symfony",
        severity: Severity::High,
        confirm_strings: &["sf-toolbar", "profiler"],
    },
    // ── ASP.NET ──────────────────────────────────────────────────────────
    DebugProbe {
        path: "/elmah.axd",
        name: "ELMAH Error Log",
        framework: "ASP.NET ELMAH",
        severity: Severity::High,
        confirm_strings: &["Error Log for", "ELMAH"],
    },
    DebugProbe {
        path: "/trace.axd",
        name: "ASP.NET Trace",
        framework: "ASP.NET",
        severity: Severity::High,
        confirm_strings: &["Application Trace", "Request Details"],
    },
    // ── PHP ──────────────────────────────────────────────────────────────
    DebugProbe {
        path: "/info.php",
        name: "PHP Info Page",
        framework: "PHP",
        severity: Severity::Medium,
        confirm_strings: &["phpinfo()", "PHP Version"],
    },
    // ── GraphQL ──────────────────────────────────────────────────────────
    DebugProbe {
        path: "/graphiql",
        name: "GraphiQL IDE Exposed",
        framework: "GraphQL",
        severity: Severity::Medium,
        confirm_strings: &["graphiql", "GraphiQL"],
    },
    // ── Webpack/Node Dev ─────────────────────────────────────────────────
    DebugProbe {
        path: "/__webpack_hmr",
        name: "Webpack HMR Endpoint",
        framework: "Webpack Dev Server",
        severity: Severity::Medium,
        confirm_strings: &[],
    },
];

/// Probe all debug/monitoring endpoints for this web asset.
pub async fn probe(client: &Client, target: &Target) -> anyhow::Result<Vec<Finding>> {
    let Target::Web(asset) = target else {
        return Ok(vec![]);
    };
    let mut findings = Vec::new();
    let base = asset.url.as_str().trim_end_matches('/');

    for debug_probe in PROBES {
        let url = format!("{}{}", base, debug_probe.path);

        let resp = match client.get(&url).send().await {
            Ok(r) => r,
            Err(_) => continue,
        };

        let status = resp.status().as_u16();

        // Skip non-2xx responses.
        if !(200..300).contains(&status) {
            continue;
        }

        let content_type = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();

        // Special case: heapdump returns binary.
        if debug_probe.path.contains("heapdump") && content_type.contains("octet-stream") {
            findings.push(
                crate::finding_builder(
                    target,
                    debug_probe.severity,
                    format!("{} Exposed", debug_probe.name),
                    format!(
                        "{} endpoint at {} returns a binary heap dump. \
                         This contains in-memory application data including \
                         database credentials, API keys, and session tokens. \
                         Framework: {}. Fix: disable or restrict actuator endpoints.",
                        debug_probe.name, debug_probe.path, debug_probe.framework
                    ),
                )
                .evidence(Evidence::HttpResponse {
                    status,
                    headers: vec![("content-type".into(), content_type)],
                    body_excerpt: Some("[binary heap dump]".into()),
                })
                .tag("debug")
                .tag("exposure")
                .tag(
                    debug_probe
                        .framework
                        .split_whitespace()
                        .next()
                        .unwrap_or("web"),
                )
                .build()
                .map_err(|e| anyhow::anyhow!(e))?,
            );
            continue;
        }

        // For text responses, read the body and check confirm strings.
        let body = match resp.text().await {
            Ok(b) => b,
            Err(_) => continue,
        };

        // If no confirm_strings, a 200 is enough (healthz, HMR).
        let confirmed = debug_probe.confirm_strings.is_empty()
            || debug_probe.confirm_strings.iter().any(|s| body.contains(s));

        if confirmed {
            let excerpt = if body.len() > 200 {
                format!("{}...", &body[..200])
            } else {
                body.clone()
            };

            findings.push(
                crate::finding_builder(
                    target,
                    debug_probe.severity,
                    format!("{} Exposed", debug_probe.name),
                    format!(
                        "{} endpoint at {} is publicly accessible. \
                         Framework: {}. This can leak application internals, \
                         configuration, and credentials. \
                         Fix: restrict access to internal networks or disable in production.",
                        debug_probe.name, debug_probe.path, debug_probe.framework
                    ),
                )
                .evidence(Evidence::HttpResponse {
                    status,
                    headers: vec![("content-type".into(), content_type)],
                    body_excerpt: Some(excerpt),
                })
                .tag("debug")
                .tag("exposure")
                .tag(
                    debug_probe
                        .framework
                        .split_whitespace()
                        .next()
                        .unwrap_or("web"),
                )
                .build()
                .map_err(|e| anyhow::anyhow!(e))?,
            );
        }
    }

    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_probes_have_valid_paths() {
        for probe in PROBES {
            assert!(
                probe.path.starts_with('/'),
                "probe path must start with /: {}",
                probe.path
            );
        }
    }

    #[test]
    fn probe_list_covers_major_frameworks() {
        let frameworks: Vec<_> = PROBES.iter().map(|p| p.framework).collect();
        assert!(frameworks.contains(&"Spring Boot"));
        assert!(frameworks.contains(&"Django"));
        assert!(frameworks.contains(&"Go net/http/pprof"));
        assert!(frameworks.contains(&"Prometheus"));
        assert!(frameworks.contains(&"Apache httpd"));
    }

    #[test]
    fn critical_probes_require_confirm_strings_or_content_type() {
        for probe in PROBES {
            if probe.severity == Severity::Critical {
                // Critical probes must have confirm strings OR be heapdump (binary check).
                assert!(
                    !probe.confirm_strings.is_empty() || probe.path.contains("heapdump"),
                    "critical probe {} must have confirm strings to avoid false positives",
                    probe.name
                );
            }
        }
    }

    #[test]
    fn no_duplicate_paths() {
        let mut paths: Vec<_> = PROBES.iter().map(|p| p.path).collect();
        paths.sort();
        paths.dedup();
        assert_eq!(paths.len(), PROBES.len(), "duplicate paths in debug probes");
    }
}
