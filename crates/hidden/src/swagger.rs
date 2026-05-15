//! OpenAPI/Swagger spec exposure and content analysis probe.
//!
//! Finds exposed API specs, then parses them to surface:
//!   - Endpoints with no security requirement (unauthenticated access)
//!   - API key / token parameters in path or query definitions
//!   - Server URLs using plain HTTP (unencrypted transport)
//!   - Total endpoint count (scope indicator for attackers)
//!   - Every endpoint as an individual finding (capped at 50)

use gossan_core::Target;
use secfinding::{Evidence, Finding, Severity};

const PATHS: &[&str] = &[
    "/swagger.json",
    "/swagger.yaml",
    "/swagger/v1/swagger.json",
    "/openapi.json",
    "/openapi.yaml",
    "/openapi/v3/api-docs",
    "/api-docs",
    "/api-docs/",
    "/api/swagger.json",
    "/api/openapi.json",
    "/v1/swagger.json",
    "/v2/swagger.json",
    "/v2/api-docs",
    "/v3/api-docs",
    "/v3/openapi.json",
    "/docs",
    "/redoc",
    "/swagger-ui",
    "/swagger-ui.html",
    "/swagger-ui/index.html",
    "/api/v1/swagger.json",
    "/api/v2/openapi.json",
    "/.well-known/openapi.json",
    "/swagger-resources",
    "/swagger-ui/springfox.js",
    "/api/swagger-ui.html",
    "/api/v3/api-docs",
    "/rest/v1/swagger.json",
    "/api/swagger/v1/swagger.json",
    // Spring Boot Actuator
    "/actuator",
    "/actuator/info",
    "/actuator/health",
    "/actuator/env",
    "/actuator/mappings",
    // ASP.NET
    "/swagger/index.html",
    "/swagger/v1/swagger.json",
    // FastAPI
    "/openapi.json",
    "/docs",
    "/redoc",
    // GraphQL schema
    "/graphql/schema",
    "/api/graphql/schema",
];

/// Maximum number of endpoint findings to emit per spec.
const MAX_ENDPOINT_FINDINGS: usize = 50;

pub async fn probe(
    client: &reqwest::Client,
    target: &Target,
    baseline: Option<&crate::soft404::BaselineFingerprint>,
) -> anyhow::Result<Vec<Finding>> {
    let Target::Web(asset) = target else {
        return Ok(vec![]);
    };
    let base = asset.url.as_str().trim_end_matches('/');
    let mut findings = Vec::new();

    for path in PATHS {
        let url = format!("{}{}", base, path);
        let Ok(resp) = client.get(&url).send().await else {
            continue;
        };

        let status = resp.status().as_u16();
        if status != 200 {
            continue;
        }

        // Reject HTML responses early to avoid false positives on SPA shells
        let content_type = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if content_type.contains("text/html") {
            continue;
        }

        let Ok(body) = gossan_core::net::bounded_text(resp, 4 * 1024 * 1024).await else {
            continue;
        };

        // Soft-404 check using baseline
        if crate::soft404::is_likely_404(status, body.as_bytes(), baseline, false) {
            continue;
        }

        let is_spec = body.contains("\"openapi\"")
            || body.contains("\"swagger\"")
            || body.contains("openapi:")
            || body.contains("swagger:")
            || body.contains("\"paths\"")
            || body.contains("paths:");

        if !is_spec {
            continue;
        }

        // Primary finding: spec is exposed
        gossan_core::try_push_finding(crate::exposure_finding(
                target, Severity::Medium,
                "OpenAPI/Swagger spec exposed",
                format!("API specification at {} is publicly accessible — reveals all endpoints, \
                         parameters, schemas, and authentication requirements to unauthenticated callers.", url),
            )
            .evidence(Evidence::HttpResponse {
                status: 200,
                headers: vec![],
                body_excerpt: Some(body.chars().take(300).collect::<String>().into()),
            })
            .tag("swagger").tag("exposure"), &mut findings);

        // Attempt to parse and analyse the spec body
        if let Ok(spec) = serde_json::from_str::<serde_json::Value>(&body) {
            analyze_spec(&spec, &url, target, &mut findings);
        } else {
            analyze_spec_text(&body, &url, target, &mut findings);
        }

        break; // one spec per target is sufficient
    }

    Ok(findings)
}

/// Full JSON spec analysis via serde_json.
fn analyze_spec(
    spec: &serde_json::Value,
    spec_url: &str,
    target: &Target,
    findings: &mut Vec<Finding>,
) {
    // ── HTTP server URLs ──────────────────────────────────────────────────────
    if let Some(servers) = spec.get("servers").and_then(|s| s.as_array()) {
        for server in servers {
            if let Some(srv_url) = server.get("url").and_then(|u| u.as_str()) {
                if srv_url.starts_with("http://") {
                    gossan_core::try_push_finding(crate::exposure_finding(
                            target,
                            Severity::Medium,
                            "OpenAPI spec lists HTTP (unencrypted) server URL",
                            format!(
                                "The spec at {} declares server URL '{}' using plain HTTP. \
                                     All API traffic to this server is unencrypted and susceptible \
                                     to eavesdropping and MITM attacks.",
                                spec_url, srv_url
                            ),
                        )
                        .tag("swagger")
                        .tag("tls")
                        .tag("exposure"), findings);
                }
            }
        }
    }

    // Swagger 2.0 base URL check
    if spec.get("host").is_some() {
        let schemes = spec
            .get("schemes")
            .and_then(|s| s.as_array())
            .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>())
            .unwrap_or_default();
        if schemes.contains(&"http") && !schemes.contains(&"https") {
            gossan_core::try_push_finding(crate::exposure_finding(
                    target,
                    Severity::Medium,
                    "Swagger 2.0 spec: HTTP-only scheme declared",
                    format!(
                        "The spec at {} lists only HTTP in the 'schemes' array. \
                             API communication is unencrypted.",
                        spec_url
                    ),
                )
                .tag("swagger")
                .tag("tls"), findings);
        }
    }

    // ── Unauthenticated endpoints ─────────────────────────────────────────────
    let global_security_defined = spec
        .get("components")
        .and_then(|c| c.get("securitySchemes"))
        .map(|ss| !ss.as_object().map(|o| o.is_empty()).unwrap_or(true))
        .unwrap_or(false)
        || spec.get("securityDefinitions").is_some(); // Swagger 2.0

    let global_security_required = spec
        .get("security")
        .and_then(|s| s.as_array())
        .map(|arr| !arr.is_empty())
        .unwrap_or(false);

    let mut unauth_endpoints: Vec<String> = Vec::new();
    let mut total_endpoints: usize = 0;
    let mut api_key_params: Vec<String> = Vec::new();

    if let Some(paths) = spec.get("paths").and_then(|p| p.as_object()) {
        for (path, path_item) in paths {
            if let Some(methods) = path_item.as_object() {
                for (method, operation) in methods {
                    let valid_method = matches!(
                        method.as_str(),
                        "get" | "post" | "put" | "patch" | "delete" | "head" | "options"
                    );
                    if !valid_method {
                        continue;
                    }
                    total_endpoints += 1;

                    let op_security = operation.get("security");
                    let explicitly_unauthenticated = op_security
                        .and_then(|s| s.as_array())
                        .map(|arr| arr.is_empty())
                        .unwrap_or(false);

                    let no_security_anywhere = !global_security_defined
                        && !global_security_required
                        && op_security.is_none();

                    let overrides_to_unauth =
                        global_security_required && explicitly_unauthenticated;

                    if no_security_anywhere || overrides_to_unauth {
                        unauth_endpoints.push(format!("{} {}", method.to_uppercase(), path));
                    }

                    let all_params_locs = [
                        operation.get("parameters"),
                        path_item.get("parameters"),
                    ];
                    for params_opt in all_params_locs {
                        if let Some(params) = params_opt.and_then(|p| p.as_array()) {
                            for param in params {
                                let name = param
                                    .get("name")
                                    .and_then(|n| n.as_str())
                                    .unwrap_or("")
                                    .to_lowercase();
                                let r#in = param.get("in").and_then(|i| i.as_str()).unwrap_or("");
                                if (name.contains("key")
                                    || name.contains("token")
                                    || name.contains("secret")
                                    || name.contains("api_key")
                                    || name.contains("apikey")
                                    || name == "auth"
                                    || name.contains("bearer"))
                                    && matches!(r#in, "query" | "header" | "path")
                                {
                                    let entry = format!(
                                        "{} {}: ?{}= ({})",
                                        method.to_uppercase(),
                                        path,
                                        name,
                                        r#in
                                    );
                                    if !api_key_params.contains(&entry) {
                                        api_key_params.push(entry);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Emit aggregate finding for unauthenticated endpoints
    if !unauth_endpoints.is_empty() {
        let sample = unauth_endpoints[..unauth_endpoints.len().min(5)].join(", ");
        gossan_core::try_push_finding(crate::exposure_finding(
                target,
                Severity::High,
                format!(
                    "{} API endpoint(s) with no authentication requirement",
                    unauth_endpoints.len()
                ),
                format!(
                    "Spec at {} declares {} of {} endpoints with no security scheme. \
                         Sample: {}. These endpoints are likely accessible without credentials — \
                         confirm by probing them directly.",
                    spec_url,
                    unauth_endpoints.len(),
                    total_endpoints,
                    sample
                ),
            )
            .evidence(Evidence::HttpResponse {
                status: 200,
                headers: vec![],
                body_excerpt: Some(unauth_endpoints[..unauth_endpoints.len().min(10)].join("\n").into()),
            })
            .tag("swagger")
            .tag("auth-bypass")
            .tag("exposure"), findings);

        // Emit one finding per unauthenticated endpoint (capped)
        for ep in unauth_endpoints.iter().take(MAX_ENDPOINT_FINDINGS) {
            gossan_core::try_push_finding(crate::exposure_finding(
                    target,
                    Severity::Medium,
                    format!("Unauthenticated API endpoint: {}", ep),
                    format!(
                        "The OpenAPI spec at {} declares '{}' with no security requirement. \
                         This endpoint may be accessible without authentication.",
                        spec_url, ep
                    ),
                )
                .tag("swagger")
                .tag("endpoint")
                .tag("auth-bypass")
                .tag("exposure"), findings);
        }
    }

    // Report API key parameters
    if !api_key_params.is_empty() {
        gossan_core::try_push_finding(crate::exposure_finding(target, Severity::Medium,
                format!("{} API key/token parameter(s) documented in spec",
                    api_key_params.len()),
                format!("The spec at {} documents {} endpoint(s) that accept authentication \
                         via query/header parameter. Credentials in URLs are logged by proxies, \
                         CDNs, and browser history. Prefer Authorization header, never query params.\n{}",
                    spec_url, api_key_params.len(),
                    api_key_params[..api_key_params.len().min(5)].join("\n")))
            .tag("swagger").tag("exposure").tag("credentials"), findings);
    }
}

/// Text-heuristic analysis for YAML specs (no parser dependency).
fn analyze_spec_text(body: &str, spec_url: &str, target: &Target, findings: &mut Vec<Finding>) {
    if body.contains("http://") && !body.contains("https://") {
        gossan_core::try_push_finding(crate::exposure_finding(
                target,
                Severity::Medium,
                "OpenAPI/YAML spec lists HTTP-only server",
                format!(
                    "Spec at {} appears to reference only HTTP URLs. \
                         API traffic may be unencrypted.",
                    spec_url
                ),
            )
            .tag("swagger")
            .tag("tls"), findings);
    }

    let path_count = body
        .lines()
        .filter(|l| {
            let t = l.trim_start();
            t.starts_with('/') && t.ends_with(':')
        })
        .count();

    if path_count > 20 {
        gossan_core::try_push_finding(crate::exposure_finding(
                target,
                Severity::Medium,
                format!("Large API surface exposed: ~{} paths in spec", path_count),
                format!(
                    "The YAML spec at {} documents approximately {} API paths. \
                         A large attack surface increases the probability of vulnerable endpoints.",
                    spec_url, path_count
                ),
            )
            .tag("swagger")
            .tag("exposure"), findings);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gossan_core::{HostTarget, Protocol, ServiceTarget, Target, WebAssetTarget};
    use reqwest::Url;

    fn target() -> Target {
        Target::Web(Box::new(WebAssetTarget {
            url: Url::parse("https://example.com").unwrap_or_else(|_| Url::parse("http://127.0.0.1").unwrap()),
            service: ServiceTarget {
                host: HostTarget {
                    ip: "127.0.0.1".parse().unwrap_or_else(|_| "127.0.0.1".parse().unwrap()),
                    domain: Some("example.com".into()),
                },
                port: 443,
                protocol: Protocol::Tcp,
                banner: None,
                tls: true,
            },
            tech: vec![],
            status: 200,
            title: None,
            favicon_hash: None,
            body_hash: None,
            forms: vec![],
            params: vec![],
        }))
    }

    #[test]
    fn analyze_spec_flags_http_only_server_urls() {
        let spec = serde_json::json!({
            "openapi": "3.0.0",
            "servers": [{"url": "http://api.example.com"}],
            "paths": {}
        });
        let mut findings = Vec::new();
        analyze_spec(
            &spec,
            "https://example.com/openapi.json",
            &target(),
            &mut findings,
        );
        assert!(findings
            .iter()
            .any(|f| f.title().contains("HTTP (unencrypted) server URL")));
    }

    #[test]
    fn analyze_spec_flags_swagger_http_only_schemes() {
        let spec = serde_json::json!({
            "swagger": "2.0",
            "host": "api.example.com",
            "schemes": ["http"],
            "paths": {}
        });
        let mut findings = Vec::new();
        analyze_spec(
            &spec,
            "https://example.com/swagger.json",
            &target(),
            &mut findings,
        );
        assert!(findings
            .iter()
            .any(|f| f.title().contains("HTTP-only scheme declared")));
    }

    #[test]
    fn analyze_spec_detects_unauthenticated_endpoints() {
        let spec = serde_json::json!({
            "openapi": "3.0.0",
            "paths": {
                "/admin": {
                    "get": {
                        "responses": {"200": {"description": "ok"}}
                    }
                }
            }
        });
        let mut findings = Vec::new();
        analyze_spec(
            &spec,
            "https://example.com/openapi.json",
            &target(),
            &mut findings,
        );
        let finding = findings
            .iter()
            .find(|f| f.title().contains("no authentication requirement"))
            .unwrap();
        assert!(finding.detail().contains("GET /admin"));
    }

    #[test]
    fn analyze_spec_respects_global_security_unless_operation_opts_out() {
        let spec = serde_json::json!({
            "openapi": "3.0.0",
            "components": {"securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer"}}},
            "security": [{"bearerAuth": []}],
            "paths": {
                "/public": {"get": {"security": [], "responses": {"200": {"description": "ok"}}}},
                "/private": {"get": {"responses": {"200": {"description": "ok"}}}}
            }
        });
        let mut findings = Vec::new();
        analyze_spec(
            &spec,
            "https://example.com/openapi.json",
            &target(),
            &mut findings,
        );
        let finding = findings
            .iter()
            .find(|f| f.title().contains("no authentication requirement"))
            .unwrap();
        assert!(finding.detail().contains("GET /public"));
        assert!(!finding.detail().contains("GET /private"));
    }

    #[test]
    fn analyze_spec_reports_api_key_and_token_parameters() {
        let spec = serde_json::json!({
            "openapi": "3.0.0",
            "paths": {
                "/search": {
                    "get": {
                        "parameters": [
                            {"name": "api_key", "in": "query"},
                            {"name": "bearer_token", "in": "header"}
                        ],
                        "responses": {"200": {"description": "ok"}}
                    }
                }
            }
        });
        let mut findings = Vec::new();
        analyze_spec(
            &spec,
            "https://example.com/openapi.json",
            &target(),
            &mut findings,
        );
        let finding = findings
            .iter()
            .find(|f| f.title().contains("API key/token parameter"))
            .unwrap();
        assert!(finding.detail().contains("?api_key="));
        assert!(finding.detail().contains("bearer_token"));
    }

    #[test]
    fn analyze_spec_text_flags_http_only_yaml_specs() {
        let mut findings = Vec::new();
        analyze_spec_text(
            "servers:\n  - url: http://api.example.com",
            "https://example.com/openapi.yaml",
            &target(),
            &mut findings,
        );
        assert!(findings
            .iter()
            .any(|f| f.title().contains("HTTP-only server")));
    }

    #[test]
    fn analyze_spec_text_flags_large_yaml_surfaces() {
        let yaml = (0..25)
            .map(|i| format!("/path{}/:\n  get:\n", i))
            .collect::<String>();
        let mut findings = Vec::new();
        analyze_spec_text(
            &yaml,
            "https://example.com/openapi.yaml",
            &target(),
            &mut findings,
        );
        assert!(findings
            .iter()
            .any(|f| f.title().contains("Large API surface exposed")));
    }

    #[test]
    fn swagger_path_list_contains_common_openapi_locations() {
        assert!(PATHS.contains(&"/swagger.json"));
        assert!(PATHS.contains(&"/v3/openapi.json"));
        assert!(PATHS.contains(&"/.well-known/openapi.json"));
        assert!(PATHS.contains(&"/swagger-resources"));
        assert!(PATHS.contains(&"/api/v3/api-docs"));
    }

    #[test]
    fn emits_individual_endpoint_findings() {
        let spec = serde_json::json!({
            "openapi": "3.0.0",
            "paths": {
                "/public": {"get": {"responses": {"200": {"description": "ok"}}}},
                "/api": {"post": {"responses": {"200": {"description": "ok"}}}}
            }
        });
        let mut findings = Vec::new();
        analyze_spec(&spec, "https://example.com/openapi.json", &target(), &mut findings);
        let endpoint_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.title().contains("Unauthenticated API endpoint"))
            .collect();
        assert_eq!(endpoint_findings.len(), 2);
    }
}
