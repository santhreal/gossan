//! Debug/monitoring endpoint exposure scanner.
//!
//! Probes for common framework debug, profiler, and monitoring endpoints that
//! should never be accessible in production. These often leak environment
//! variables, database credentials, heap dumps, or application internals.
//!
//! Probe definitions are loaded from `debug_probes.toml` at runtime when
//! available, falling back to the compiled-in `PROBES` array.

use gossan_core::Target;
use reqwest::Client;
use secfinding::{Evidence, Finding, Severity};
use serde::Deserialize;

/// A debug endpoint to probe: path, framework attribution, and severity.
struct DebugProbe {
    path: String,
    name: String,
    framework: String,
    severity: Severity,
    confirm_strings: Vec<String>,
}

/// TOML-deserializable debug probe definition.
#[derive(Deserialize)]
struct TomlDebugProbe {
    path: String,
    name: String,
    framework: String,
    severity: String,
    #[serde(default)]
    confirm_strings: Vec<String>,
}

/// TOML file root structure.
#[derive(Deserialize)]
struct TomlDebugProbes {
    probe: Vec<TomlDebugProbe>,
}

fn parse_severity(s: &str) -> Severity {
    match s.to_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::Info,
    }
}

fn load_toml_probes() -> Vec<DebugProbe> {
    let mut probes = Vec::new();
    for path in &["src/debug_probes.toml", "crates/hidden/src/debug_probes.toml"] {
        if let Ok(content) = std::fs::read_to_string(path) {
            if let Ok(parsed) = toml::from_str::<TomlDebugProbes>(&content) {
                for p in parsed.probe {
                    probes.push(DebugProbe {
                        path: p.path,
                        name: p.name,
                        framework: p.framework,
                        severity: parse_severity(&p.severity),
                        confirm_strings: p.confirm_strings,
                    });
                }
                if !probes.is_empty() {
                    tracing::info!(count = probes.len(), path = path, "loaded debug probes from TOML");
                    return probes;
                }
            }
        }
    }
    probes
}

fn get_probes() -> Vec<DebugProbe> {
    let toml = load_toml_probes();
    if !toml.is_empty() {
        return toml;
    }
    // Fallback to compiled-in definitions
    COMPILED_PROBES
        .iter()
        .map(|p| DebugProbe {
            path: p.path.to_string(),
            name: p.name.to_string(),
            framework: p.framework.to_string(),
            severity: p.severity,
            confirm_strings: p.confirm_strings.iter().map(|s| s.to_string()).collect(),
        })
        .collect()
}

struct CompiledDebugProbe {
    path: &'static str,
    name: &'static str,
    framework: &'static str,
    severity: Severity,
    confirm_strings: &'static [&'static str],
}

const COMPILED_PROBES: &[CompiledDebugProbe] = &[
    CompiledDebugProbe {
        path: "/actuator",
        name: "Spring Boot Actuator Index",
        framework: "Spring Boot",
        severity: Severity::High,
        confirm_strings: &["_links", "actuator"],
    },
    CompiledDebugProbe {
        path: "/actuator/env",
        name: "Spring Boot Environment Variables",
        framework: "Spring Boot",
        severity: Severity::Critical,
        confirm_strings: &["propertySources", "systemProperties"],
    },
    CompiledDebugProbe {
        path: "/actuator/heapdump",
        name: "Spring Boot Heap Dump",
        framework: "Spring Boot",
        severity: Severity::Critical,
        confirm_strings: &[],
    },
    CompiledDebugProbe {
        path: "/actuator/configprops",
        name: "Spring Boot Config Properties",
        framework: "Spring Boot",
        severity: Severity::High,
        confirm_strings: &["beans", "prefix"],
    },
    CompiledDebugProbe {
        path: "/actuator/mappings",
        name: "Spring Boot Request Mappings",
        framework: "Spring Boot",
        severity: Severity::Medium,
        confirm_strings: &["dispatcherServlets", "requestMappingConditions"],
    },
    CompiledDebugProbe {
        path: "/__debug__/",
        name: "Django Debug Toolbar",
        framework: "Django",
        severity: Severity::Critical,
        confirm_strings: &["djDebug", "debug toolbar"],
    },
    CompiledDebugProbe {
        path: "/debug/pprof/",
        name: "Go pprof Profiler",
        framework: "Go net/http/pprof",
        severity: Severity::High,
        confirm_strings: &["goroutine", "heap", "profile"],
    },
    CompiledDebugProbe {
        path: "/metrics",
        name: "Prometheus Metrics Endpoint",
        framework: "Prometheus",
        severity: Severity::Medium,
        confirm_strings: &["# HELP", "# TYPE", "process_"],
    },
    CompiledDebugProbe {
        path: "/healthz",
        name: "Kubernetes Health Check",
        framework: "Kubernetes",
        severity: Severity::Info,
        confirm_strings: &[],
    },
    CompiledDebugProbe {
        path: "/server-status",
        name: "Apache Server Status",
        framework: "Apache httpd",
        severity: Severity::Medium,
        confirm_strings: &["Apache Server Status", "Total Accesses"],
    },
    CompiledDebugProbe {
        path: "/server-info",
        name: "Apache Server Info",
        framework: "Apache httpd",
        severity: Severity::High,
        confirm_strings: &["Server Settings", "Module Name"],
    },
    CompiledDebugProbe {
        path: "/_profiler/",
        name: "Symfony Web Profiler",
        framework: "Symfony",
        severity: Severity::High,
        confirm_strings: &["sf-toolbar", "profiler"],
    },
    CompiledDebugProbe {
        path: "/elmah.axd",
        name: "ELMAH Error Log",
        framework: "ASP.NET ELMAH",
        severity: Severity::High,
        confirm_strings: &["Error Log for", "ELMAH"],
    },
    CompiledDebugProbe {
        path: "/trace.axd",
        name: "ASP.NET Trace",
        framework: "ASP.NET",
        severity: Severity::High,
        confirm_strings: &["Application Trace", "Request Details"],
    },
    CompiledDebugProbe {
        path: "/info.php",
        name: "PHP Info Page",
        framework: "PHP",
        severity: Severity::Medium,
        confirm_strings: &["phpinfo()", "PHP Version"],
    },
    CompiledDebugProbe {
        path: "/graphiql",
        name: "GraphiQL IDE Exposed",
        framework: "GraphQL",
        severity: Severity::Medium,
        confirm_strings: &["graphiql", "GraphiQL"],
    },
    CompiledDebugProbe {
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
    let probes = get_probes();

    for debug_probe in &probes {
        let url = format!("{}{}", base, debug_probe.path);

        let resp = match client.get(&url).send().await {
            Ok(r) => r,
            Err(_) => continue,
        };

        let status = resp.status().as_u16();

        if !(200..300).contains(&status) {
            continue;
        }

        let content_type = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();

        if debug_probe.path.contains("heapdump") && content_type.contains("octet-stream") {
            findings.push(
                crate::exposure_finding(
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
                    headers: vec![("content-type".into(), content_type.clone().into())],
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

        let body = match gossan_core::net::bounded_text(resp, 4 * 1024 * 1024).await {
            Ok(b) => b,
            Err(_) => continue,
        };

        let confirmed = debug_probe.confirm_strings.is_empty()
            || debug_probe
                .confirm_strings
                .iter()
                .any(|s| body.contains(s));

        if confirmed {
            let excerpt = if body.len() > 200 {
                format!("{}...", &body[..200])
            } else {
                body.clone()
            };

            findings.push(
                crate::exposure_finding(
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
                    headers: vec![("content-type".into(), content_type.clone().into())],
                    body_excerpt: Some((excerpt).into()),
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
        for probe in get_probes() {
            assert!(
                probe.path.starts_with('/'),
                "probe path must start with /: {}",
                probe.path
            );
        }
    }

    #[test]
    fn probe_list_covers_major_frameworks() {
        let probes = get_probes();
        let frameworks: Vec<_> = probes.iter().map(|p| p.framework.as_str()).collect();
        assert!(frameworks.contains(&"Spring Boot"));
        assert!(frameworks.contains(&"Django"));
        assert!(frameworks.contains(&"Go net/http/pprof"));
        assert!(frameworks.contains(&"Prometheus"));
        assert!(frameworks.contains(&"Apache httpd"));
    }

    #[test]
    fn critical_probes_require_confirm_strings_or_content_type() {
        for probe in get_probes() {
            if probe.severity == Severity::Critical {
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
        let probes = get_probes();
        let mut paths: Vec<_> = probes.iter().map(|p| p.path.as_str()).collect();
        paths.sort();
        paths.dedup();
        assert_eq!(paths.len(), probes.len(), "duplicate paths in debug probes");
    }
}
