//! OpenAPI/Swagger spec exposure and content analysis probe.
//!
//! Finds exposed API specs, then parses them to surface:
//!   - Endpoints with no security requirement (unauthenticated access)
//!   - API key / token parameters in path or query definitions
//!   - Server URLs using plain HTTP (unencrypted transport)
//!   - Total endpoint count (scope indicator for attackers)

use gossan_core::Target;
use secfinding::{Evidence, Finding, Severity};

const PATHS: &[&str] = &[
    "/swagger.json",
    "/swagger.yaml",
    "/openapi.json",
    "/openapi.yaml",
    "/api-docs",
    "/api-docs/",
    "/api/swagger.json",
    "/api/openapi.json",
    "/v1/swagger.json",
    "/v2/swagger.json",
    "/v3/openapi.json",
    "/docs",
    "/redoc",
    "/swagger-ui",
    "/swagger-ui.html",
    "/api/v1/swagger.json",
    "/api/v2/openapi.json",
    "/.well-known/openapi.json",
];

pub async fn probe(client: &reqwest::Client, target: &Target) -> anyhow::Result<Vec<Finding>> {
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

        if resp.status().as_u16() != 200 {
            continue;
        }

        let body = resp.text().await.unwrap_or_default();
        let is_spec = body.contains("\"openapi\"")
            || body.contains("\"swagger\"")
            || body.contains("openapi:")
            || body.contains("swagger:");

        if !is_spec {
            continue;
        }

        // Primary finding: spec is exposed
        findings.push(
            crate::finding_builder(
                target, Severity::Medium,
                "OpenAPI/Swagger spec exposed",
                format!("API specification at {} is publicly accessible — reveals all endpoints, \
                         parameters, schemas, and authentication requirements to unauthenticated callers.", url),
            )
            .evidence(Evidence::HttpResponse {
                status: 200,
                headers: vec![],
                body_excerpt: Some(body.chars().take(300).collect()),
            })
            .tag("swagger").tag("exposure")
            .build().expect("finding builder: required fields are set"),
        );

        // Attempt to parse and analyse the spec body
        if let Ok(spec) = serde_json::from_str::<serde_json::Value>(&body) {
            analyze_spec(&spec, &url, target, &mut findings);
        } else {
            // YAML: try to extract key signals without a full YAML parser
            // (hidden crate has no yaml dep — extract via text heuristics)
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
                    findings.push(
                        crate::finding_builder(
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
                        .tag("exposure")
                        .build()
                        .expect("finding builder: required fields are set"),
                    );
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
            findings.push(
                crate::finding_builder(
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
                .tag("tls")
                .build()
                .expect("finding builder: required fields are set"),
            );
        }
    }

    // ── Unauthenticated endpoints ─────────────────────────────────────────────
    // OpenAPI 3.x: spec-level security + per-operation security override
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
                    // Only HTTP method keys, not x-extensions or summary/description
                    let valid_method = matches!(
                        method.as_str(),
                        "get" | "post" | "put" | "patch" | "delete" | "head" | "options"
                    );
                    if !valid_method {
                        continue;
                    }
                    total_endpoints += 1;

                    // Per-operation security: empty array `[]` explicitly disables auth
                    let op_security = operation.get("security");
                    let explicitly_unauthenticated = op_security
                        .and_then(|s| s.as_array())
                        .map(|arr| arr.is_empty())
                        .unwrap_or(false);

                    // No security defined anywhere = unauthenticated
                    let no_security_anywhere = !global_security_defined
                        && !global_security_required
                        && op_security.is_none();

                    // Global security but operation explicitly opts out
                    let overrides_to_unauth =
                        global_security_required && explicitly_unauthenticated;

                    if no_security_anywhere || overrides_to_unauth {
                        unauth_endpoints.push(format!("{} {}", method.to_uppercase(), path));
                    }

                    // Detect API key / token parameters in operation
                    let all_params_locs = [
                        operation.get("parameters"),
                        path_item.get("parameters"), // path-level params
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

    // Report unauthenticated endpoints
    if !unauth_endpoints.is_empty() {
        let sample = unauth_endpoints[..unauth_endpoints.len().min(5)].join(", ");
        findings.push(
            crate::finding_builder(
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
                body_excerpt: Some(unauth_endpoints[..unauth_endpoints.len().min(10)].join("\n")),
            })
            .tag("swagger")
            .tag("auth-bypass")
            .tag("exposure")
            .build()
            .expect("finding builder: required fields are set"),
        );
    }

    // Report API key parameters (credential exposure attack surface)
    if !api_key_params.is_empty() {
        findings.push(
            crate::finding_builder(target, Severity::Medium,
                format!("{} API key/token parameter(s) documented in spec",
                    api_key_params.len()),
                format!("The spec at {} documents {} endpoint(s) that accept authentication \
                         via query/header parameter. Credentials in URLs are logged by proxies, \
                         CDNs, and browser history. Prefer Authorization header, never query params.\n{}",
                    spec_url, api_key_params.len(),
                    api_key_params[..api_key_params.len().min(5)].join("\n")))
            .tag("swagger").tag("exposure").tag("credentials")
            .build().expect("finding builder: required fields are set")
        );
    }
}

/// Text-heuristic analysis for YAML specs (no parser dependency).
fn analyze_spec_text(body: &str, spec_url: &str, target: &Target, findings: &mut Vec<Finding>) {
    if body.contains("http://") && !body.contains("https://") {
        findings.push(
            crate::finding_builder(
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
            .tag("tls")
            .build()
            .expect("finding builder: required fields are set"),
        );
    }

    // Count rough path entries (lines starting with "  /" in YAML)
    let path_count = body
        .lines()
        .filter(|l| {
            let t = l.trim_start();
            t.starts_with('/') && t.ends_with(':')
        })
        .count();

    if path_count > 20 {
        findings.push(
            crate::finding_builder(
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
            .tag("exposure")
            .build()
            .expect("finding builder: required fields are set"),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gossan_core::{HostTarget, Protocol, ServiceTarget, Target, WebAssetTarget};
    use reqwest::Url;

    fn target() -> Target {
        Target::Web(Box::new(WebAssetTarget {
            url: Url::parse("https://example.com").unwrap(),
            service: ServiceTarget {
                host: HostTarget {
                    ip: "127.0.0.1".parse().unwrap(),
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
            .any(|f| f.title.contains("HTTP (unencrypted) server URL")));
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
            .any(|f| f.title.contains("HTTP-only scheme declared")));
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
            .find(|f| f.title.contains("no authentication requirement"))
            .unwrap();
        assert!(finding.detail.contains("GET /admin"));
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
            .find(|f| f.title.contains("no authentication requirement"))
            .unwrap();
        assert!(finding.detail.contains("GET /public"));
        assert!(!finding.detail.contains("GET /private"));
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
            .find(|f| f.title.contains("API key/token parameter"))
            .unwrap();
        assert!(finding.detail.contains("?api_key="));
        assert!(finding.detail.contains("bearer_token"));
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
            .any(|f| f.title.contains("HTTP-only server")));
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
            .any(|f| f.title.contains("Large API surface exposed")));
    }

    #[test]
    fn swagger_path_list_contains_common_openapi_locations() {
        assert!(PATHS.contains(&"/swagger.json"));
        assert!(PATHS.contains(&"/v3/openapi.json"));
        assert!(PATHS.contains(&"/.well-known/openapi.json"));
    }
}
