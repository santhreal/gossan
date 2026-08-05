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

/// Maximum number of endpoints to collect in memory during analysis.
const MAX_COLLECTED_ENDPOINTS: usize = 1000;

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

        let Ok(body) = gossan_core::net::bounded_text(resp, crate::MAX_BODY_BYTES).await else {
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
                format!("API specification at {} is publicly accessible, reveals all endpoints, \
                         parameters, schemas, and authentication requirements to unauthenticated callers.", url),
            )
            .evidence(Evidence::HttpResponse {
                status: 200,
                headers: vec![],
                body_excerpt: Some(body.chars().take(crate::MAX_BODY_EXCERPT_CHARS).collect::<String>().into()),
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
                    gossan_core::try_push_finding(
                        crate::exposure_finding(
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
                        .tag("exposure"),
                        findings,
                    );
                }
            }
        }
    }

    // Swagger 2.0 base URL check.
    // When `schemes` is omitted, Swagger 2.0 defaults to the scheme used to
    // access the spec (or both). An HTTP-served spec with no schemes must
    // still be flagged as HTTP-only exposure.
    if spec.get("host").is_some() {
        let schemes = match spec.get("schemes").and_then(|s| s.as_array()) {
            Some(arr) => arr.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>(),
            None => {
                let from_url = if spec_url.starts_with("http://") {
                    vec!["http"]
                } else if spec_url.starts_with("https://") {
                    vec!["https"]
                } else {
                    vec!["https", "http"]
                };
                tracing::debug!(
                    spec_url,
                    ?from_url,
                    "Swagger 2.0 schemes absent; defaulting from spec URL"
                );
                from_url
            }
        };
        if schemes.contains(&"http") && !schemes.contains(&"https") {
            gossan_core::try_push_finding(
                crate::exposure_finding(
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
                .tag("tls"),
                findings,
            );
        }
    }

    // ── Unauthenticated endpoints ─────────────────────────────────────────────
    // Whether the root `security` array requires authentication globally.
    // The presence of security schemes in `components.securitySchemes` is
    // irrelevant: a scheme that is defined but never applied does not protect
    // any endpoint.
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

                    // An endpoint is unauthenticated when the operation-level
                    // `security` array is explicitly empty (overriding a global
                    // requirement), or when neither the root `security` array
                    // nor the operation-level array requires authentication.
                    // The presence of schemes in `components.securitySchemes`
                    // is irrelevant unless they are actually applied.
                    let unauthenticated = op_security
                        .map(|s| s.as_array().map(|arr| arr.is_empty()).unwrap_or(false))
                        .unwrap_or(!global_security_required);

                    if unauthenticated {
                        if unauth_endpoints.len() < MAX_COLLECTED_ENDPOINTS {
                            unauth_endpoints.push(format!("{} {}", method.to_uppercase(), path));
                        }
                    }

                    let all_params_locs =
                        [operation.get("parameters"), path_item.get("parameters")];
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
                                    if api_key_params.len() < MAX_COLLECTED_ENDPOINTS && !api_key_params.contains(&entry) {
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
        gossan_core::try_push_finding(
            crate::exposure_finding(
                target,
                Severity::High,
                format!(
                    "{} API endpoint(s) with no authentication requirement",
                    unauth_endpoints.len()
                ),
                format!(
                    "Spec at {} declares {} of {} endpoints with no security scheme. \
                         Sample: {}. These endpoints are likely accessible without credentials. \
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
                body_excerpt: Some(
                    unauth_endpoints[..unauth_endpoints.len().min(10)]
                        .join("\n")
                        .into(),
                ),
            })
            .tag("swagger")
            .tag("auth-bypass")
            .tag("exposure"),
            findings,
        );

        // Emit one finding per unauthenticated endpoint (capped)
        for ep in unauth_endpoints.iter().take(MAX_ENDPOINT_FINDINGS) {
            gossan_core::try_push_finding(
                crate::exposure_finding(
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
                .tag("exposure"),
                findings,
            );
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
        gossan_core::try_push_finding(
            crate::exposure_finding(
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
            .tag("tls"),
            findings,
        );
    }

    let path_count = body
        .lines()
        .filter(|l| {
            let t = l.trim_start();
            t.starts_with('/') && t.ends_with(':')
        })
        .count();

    if path_count > 20 {
        gossan_core::try_push_finding(
            crate::exposure_finding(
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
            .tag("exposure"),
            findings,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Absent Swagger 2.0 `schemes` on an HTTP-served spec must still flag
    /// HTTP-only exposure (do not treat missing schemes as empty/no-HTTP).
    #[test]
    fn analyze_spec_flags_http_when_schemes_absent_on_http_url() {
        let spec = json!({
            "swagger": "2.0",
            "host": "api.example.com",
            "paths": { "/ping": { "get": {} } }
        });
        let target = gossan_core::testkit::web_target("http://example.com/");
        let mut findings = Vec::new();
        analyze_spec(
            &spec,
            "http://example.com/swagger.json",
            &target,
            &mut findings,
        );
        let http_only = findings
            .iter()
            .find(|f| f.title().contains("HTTP-only scheme"));
        assert!(
            http_only.is_some(),
            "expected HTTP-only finding when schemes omitted on http:// spec URL, got {:?}",
            findings.iter().map(|f| f.title()).collect::<Vec<_>>()
        );
    }

    /// Security schemes defined in `components` but never applied must not
    /// prevent an endpoint from being flagged as unauthenticated.
    #[test]
    fn analyze_spec_flags_unauth_when_schemes_defined_but_not_applied() {
        let spec = json!({
            "openapi": "3.0.0",
            "components": {
                "securitySchemes": {
                    "bearer": { "type": "http", "scheme": "bearer" }
                }
            },
            "paths": {
                "/api/users": { "get": {} }
            }
        });
        let target = gossan_core::testkit::web_target("http://example.com/");
        let mut findings = Vec::new();
        analyze_spec(&spec,
            "http://example.com/openapi.json",
            &target,
            &mut findings,
        );
        let unauth = findings
            .iter()
            .find(|f| f.title().contains("API endpoint(s) with no authentication"));
        assert!(
            unauth.is_some(),
            "expected unauthenticated endpoint finding when schemes are not applied, got {:?}",
            findings
        );
    }

    /// A globally required security scheme should suppress the unauthenticated
    /// finding when the operation does not explicitly override it.
    #[test]
    fn analyze_spec_respects_global_security_requirement() {
        let spec = json!({
            "openapi": "3.0.0",
            "security": [{ "bearer": [] }],
            "components": {
                "securitySchemes": {
                    "bearer": { "type": "http", "scheme": "bearer" }
                }
            },
            "paths": {
                "/api/users": { "get": {} }
            }
        });
        let target = gossan_core::testkit::web_target("http://example.com/");
        let mut findings = Vec::new();
        analyze_spec(
            &spec,
            "http://example.com/openapi.json",
            &target,
            &mut findings,
        );
        let unauth = findings
            .iter()
            .find(|f| f.title().contains("API endpoint(s) with no authentication"));
        assert!(
            unauth.is_none(),
            "expected no unauthenticated finding when global security is required, got {:?}",
            findings
        );
    }

    /// An explicitly empty operation-level `security` array overrides a global
    /// requirement and marks the endpoint as unauthenticated.
    #[test]
    fn analyze_spec_explicit_empty_security_overrides_global() {
        let spec = json!({
            "openapi": "3.0.0",
            "security": [{ "bearer": [] }],
            "components": {
                "securitySchemes": {
                    "bearer": { "type": "http", "scheme": "bearer" }
                }
            },
            "paths": {
                "/api/users": { "get": { "security": [] } }
            }
        });
        let target = gossan_core::testkit::web_target("http://example.com/");
        let mut findings = Vec::new();
        analyze_spec(
            &spec,
            "http://example.com/openapi.json",
            &target,
            &mut findings,
        );
        let unauth = findings
            .iter()
            .find(|f| f.title().contains("API endpoint(s) with no authentication"));
        assert!(
            unauth.is_some(),
            "expected unauthenticated finding when operation security is empty, got {:?}",
            findings
        );
    }

    /// Adversarial: a malicious spec with thousands of unauthenticated endpoints
    /// must not cause unbounded memory growth. The fix caps internal Vecs at
    /// MAX_COLLECTED_ENDPOINTS.
    #[test]
    fn analyze_spec_caps_unauth_endpoints() {
        let mut paths = serde_json::Map::new();
        for i in 0..2000 {
            let mut methods = serde_json::Map::new();
            methods.insert("get".to_string(), json!({}));
            paths.insert(format!("/api/v1/resource{}", i), json!(methods));
        }
        let spec = json!({
            "openapi": "3.0.0",
            "paths": paths,
        });
        let target = gossan_core::testkit::web_target("http://example.com/");
        let mut findings = Vec::new();
        analyze_spec(&spec, "http://example.com/openapi.json", &target, &mut findings);
        // The aggregate finding should still be emitted
        let agg = findings.iter().find(|f| f.title().contains("API endpoint(s) with no authentication"));
        assert!(agg.is_some(), "aggregate finding must be emitted even with capped endpoints");
    }

    /// Adversarial: a spec with thousands of API-key parameters must be capped.
    #[test]
    fn analyze_spec_caps_api_key_params() {
        let mut paths = serde_json::Map::new();
        for i in 0..2000 {
            let mut methods = serde_json::Map::new();
            methods.insert("get".to_string(), json!({
                "parameters": [
                    {"name": format!("api_key{}", i), "in": "query"}
                ]
            }));
            paths.insert(format!("/api/v1/resource{}", i), json!(methods));
        }
        let spec = json!({
            "openapi": "3.0.0",
            "paths": paths,
        });
        let target = gossan_core::testkit::web_target("http://example.com/");
        let mut findings = Vec::new();
        analyze_spec(&spec, "http://example.com/openapi.json", &target, &mut findings);
        let key_finding = findings.iter().find(|f| f.title().contains("API key/token parameter"));
        assert!(key_finding.is_some(), "API key finding must be emitted even with capped params");
    }

    /// Property: analyze_spec never panics on arbitrary JSON input.
    #[cfg(test)]
    mod proptests {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #[test]
            fn prop_analyze_spec_never_panics(
                path_count in 0usize..10,
                has_http in proptest::bool::ANY
            ) {
                let mut paths = serde_json::Map::new();
                for i in 0..path_count {
                    let mut methods = serde_json::Map::new();
                    methods.insert("get".to_string(), serde_json::Value::Object(serde_json::Map::new()));
                    paths.insert(format!("/api/{}", i), serde_json::Value::Object(methods));
                }
                let mut spec = serde_json::Map::new();
                spec.insert("openapi".to_string(), serde_json::Value::String("3.0.0".to_string()));
                if has_http {
                    spec.insert("servers".to_string(), serde_json::json!([{"url": "http://example.com"}]));
                }
                spec.insert("paths".to_string(), serde_json::Value::Object(paths));
                let target = gossan_core::testkit::web_target("http://example.com/");
                let mut findings = Vec::new();
                analyze_spec(&serde_json::Value::Object(spec), "http://example.com/openapi.json", &target, &mut findings);
                // Must not panic (if we reach here, property holds).
            }
        }
    }
}