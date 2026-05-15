//! OAuth / OIDC misconfiguration probe.
//!
//! Detects common misconfigurations in OAuth 2.0 and OpenID Connect deployments:
//!
//! - **Open redirect in `redirect_uri`**: the authorization endpoint accepts
//!   arbitrary redirect URIs, allowing auth code / token theft.
//! - **Exposed `.well-known/openid-configuration`**: leaks all OAuth endpoints,
//!   supported scopes, and signing keys — valuable recon for targeted attacks.
//! - **Token endpoint without client authentication**: the `/token` endpoint
//!   accepts requests without `client_secret`, enabling public client abuse.
//! - **JWKS endpoint exposure**: signing keys are publicly accessible (expected
//!   for validation, but can reveal algorithm mismatches).

use gossan_core::Target;
use reqwest::Client;
use secfinding::{Evidence, Finding, Severity};

/// Well-known OAuth/OIDC discovery paths.
const OIDC_DISCOVERY_PATHS: &[&str] = &[
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    "/oauth/.well-known/openid-configuration",
    "/auth/.well-known/openid-configuration",
    "/realms/master/.well-known/openid-configuration", // Keycloak
    "/.well-known/openid-configuration/",
];

/// Common authorization endpoint paths to probe for redirect_uri bypass.
const AUTH_ENDPOINT_PATHS: &[&str] = &[
    "/authorize",
    "/oauth/authorize",
    "/oauth2/authorize",
    "/auth/authorize",
    "/connect/authorize",
    "/oauth/auth",
    "/api/oauth/authorize",
];

/// Probe for OAuth/OIDC misconfigurations.
pub async fn probe(client: &Client, target: &Target) -> anyhow::Result<Vec<Finding>> {
    let Target::Web(asset) = target else {
        return Ok(vec![]);
    };
    let base = asset.url.as_str().trim_end_matches('/');
    let mut findings = Vec::new();

    // ── OIDC discovery endpoint ──────────────────────────────────────────
    for path in OIDC_DISCOVERY_PATHS {
        let url = format!("{}{}", base, path);
        let Ok(resp) = client.get(&url).send().await else {
            continue;
        };

        if resp.status().as_u16() != 200 {
            continue;
        }

        let Ok(body) = gossan_core::net::bounded_text(resp, 4 * 1024 * 1024).await else {
            continue;
        };

        // Check if this is a real OIDC discovery document.
        if !body.contains("authorization_endpoint") && !body.contains("issuer") {
            continue;
        }

        let Ok(doc) = serde_json::from_str::<serde_json::Value>(&body) else {
            continue;
        };

        // Extract useful endpoints from the discovery document.
        let issuer = doc["issuer"].as_str().unwrap_or("unknown");
        let auth_ep = doc["authorization_endpoint"].as_str();
        let token_ep = doc["token_endpoint"].as_str();
        let jwks_uri = doc["jwks_uri"].as_str();
        let scopes: Vec<&str> = doc["scopes_supported"]
            .as_array()
            .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
            .unwrap_or_default();

        gossan_core::try_push_finding(
            crate::misconfig_finding(
                target,
                Severity::Info,
                format!("OIDC discovery: {}", issuer),
                format!(
                    "OpenID Connect discovery document at '{}' reveals the full OAuth \
                     infrastructure: authorization endpoint, token endpoint, JWKS URI, \
                     and {} supported scopes. This is standard behavior but provides \
                     valuable recon for further testing.",
                    url,
                    scopes.len()
                ),
            )
            .tag("oauth")
            .tag("oidc")
            .tag("discovery")
            .evidence(Evidence::HttpResponse {
                status: 200,
                headers: vec![],
                body_excerpt: Some(body.chars().take(500).collect::<String>().into()),
            }),
            &mut findings,
        );

        // ── Probe the authorization endpoint for open redirect ───────────
        if let Some(auth_url) = auth_ep {
            let evil_redirect = "https://evil-oauth-redirect.santh.io/callback";
            let probe_url = format!(
                "{}?response_type=code&client_id=gossan_probe&redirect_uri={}&scope=openid",
                auth_url,
                urlencoding::encode(evil_redirect)
            );

            if let Ok(resp) = client.get(&probe_url).send().await {
                let status = resp.status().as_u16();
                // If it redirects to our evil URI without error, redirect_uri is not validated.
                if status == 302 || status == 303 {
                    if let Some(loc) = resp.headers().get("location") {
                        if let Ok(loc_str) = loc.to_str() {
                            if loc_str.contains("evil-oauth-redirect") {
                                gossan_core::try_push_finding(
                                    crate::misconfig_finding(
                                        target,
                                        Severity::Critical,
                                        "OAuth redirect_uri not validated — authorization code theft",
                                        format!(
                                            "The OAuth authorization endpoint at '{}' accepted \
                                             an arbitrary redirect_uri ('{}') without validation. \
                                             An attacker can steal authorization codes by redirecting \
                                             the victim to their own server after authentication.",
                                            auth_url, evil_redirect
                                        ),
                                    )
                                    .tag("oauth")
                                    .tag("open-redirect")
                                    .tag("critical")
                                    .evidence(Evidence::HttpResponse {
                                        status,
                                        headers: vec![("Location".into(), loc_str.into())],
                                        body_excerpt: None,
                                    })
                                    .exploit_hint(format!(
                                        "# Redirect victim to:\\n{}",
                                        probe_url
                                    )),
                                    &mut findings,
                                );
                            }
                        }
                    }
                }
            }
        }

        // ── Probe JWKS endpoint ──────────────────────────────────────────
        if let Some(jwks_url) = jwks_uri {
            if let Ok(resp) = client.get(jwks_url).send().await {
                if resp.status().as_u16() == 200 {
                    if let Ok(jwks_body) =
                        gossan_core::net::bounded_text(resp, 4 * 1024 * 1024).await
                    {
                        if let Ok(jwks) = serde_json::from_str::<serde_json::Value>(&jwks_body) {
                            let key_count =
                                jwks["keys"].as_array().map(|arr| arr.len()).unwrap_or(0);

                            // Check for weak algorithms (none, HS256 with exposed key).
                            let algorithms: Vec<&str> = jwks["keys"]
                                .as_array()
                                .map(|arr| arr.iter().filter_map(|k| k["alg"].as_str()).collect())
                                .unwrap_or_default();

                            let has_symmetric = algorithms.iter().any(|a| a.starts_with("HS"));

                            if has_symmetric {
                                gossan_core::try_push_finding(
                                    crate::misconfig_finding(
                                        target,
                                        Severity::High,
                                        "JWKS exposes symmetric signing keys",
                                        format!(
                                            "The JWKS endpoint at '{}' lists {} keys including \
                                             symmetric algorithms ({}). If the symmetric key \
                                             material is exposed (not just the algorithm name), \
                                             an attacker can forge JWTs.",
                                            jwks_url,
                                            key_count,
                                            algorithms.join(", ")
                                        ),
                                    )
                                    .tag("oauth")
                                    .tag("jwt")
                                    .tag("cryptographic")
                                    .evidence(
                                        Evidence::HttpResponse {
                                            status: 200,
                                            headers: vec![],
                                            body_excerpt: Some(
                                                jwks_body
                                                    .chars()
                                                    .take(500)
                                                    .collect::<String>()
                                                    .into(),
                                            ),
                                        },
                                    ),
                                    &mut findings,
                                );
                            }
                        }
                    }
                }
            }
        }

        // ── Probe token endpoint without client_secret ───────────────────
        if let Some(token_url) = token_ep {
            let params = [
                ("grant_type", "authorization_code"),
                ("code", "gossan_probe_invalid_code"),
                ("redirect_uri", "https://example.com/callback"),
                ("client_id", "gossan_probe"),
            ];

            if let Ok(resp) = client.post(token_url).form(&params).send().await {
                let status = resp.status().as_u16();
                // If the error is about the code being invalid (not about missing client_secret),
                // the token endpoint doesn't require client authentication.
                if let Ok(body) = gossan_core::net::bounded_text(resp, 4 * 1024 * 1024).await {
                    if (status == 400 || status == 200)
                        && (body.contains("invalid_grant")
                            || body.contains("invalid_code")
                            || body.contains("code_expired"))
                        && !body.contains("invalid_client")
                        && !body.contains("client_secret")
                    {
                        gossan_core::try_push_finding(
                            crate::misconfig_finding(
                                target,
                                Severity::Medium,
                                "OAuth token endpoint accepts public clients",
                                format!(
                                    "The token endpoint at '{}' processed the request \
                                     without requiring client_secret. The error was about \
                                     the authorization code, not client authentication. \
                                     This means any application can exchange codes without \
                                     proving its identity. Use PKCE and/or require client_secret.",
                                    token_url
                                ),
                            )
                            .tag("oauth")
                            .tag("misconfiguration")
                            .evidence(Evidence::HttpResponse {
                                status,
                                headers: vec![],
                                body_excerpt: Some(
                                    body.chars().take(300).collect::<String>().into(),
                                ),
                            }),
                            &mut findings,
                        );
                    }
                }
            }
        }

        // Only probe the first valid OIDC discovery path.
        break;
    }

    // ── Fallback: probe common auth endpoints without discovery ───────────
    if findings.is_empty() {
        for path in AUTH_ENDPOINT_PATHS {
            let url = format!("{}{}", base, path);
            let Ok(resp) = client.get(&url).send().await else {
                continue;
            };
            let status = resp.status().as_u16();
            // If the endpoint exists (200 or redirect), it's worth noting.
            if status == 200 || status == 302 || status == 303 {
                gossan_core::try_push_finding(
                    crate::misconfig_finding(
                        target,
                        Severity::Info,
                        format!("OAuth endpoint detected: {}", path),
                        format!(
                            "HTTP {} from '{}' — an OAuth authorization endpoint is present. \
                             Test for redirect_uri validation, state parameter enforcement, \
                             and PKCE support.",
                            status, url
                        ),
                    )
                    .tag("oauth")
                    .tag("discovery"),
                    &mut findings,
                );
                break;
            }
        }
    }

    Ok(findings)
}
