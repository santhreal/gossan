//! OAuth / OIDC misconfiguration probe.
//!
//! Detects common misconfigurations in OAuth 2.0 and OpenID Connect deployments:
//!
//! - **Open redirect in `redirect_uri`**: the authorization endpoint accepts
//!   arbitrary redirect URIs, allowing auth code / token theft.
//! - **Exposed `.well-known/openid-configuration`**: leaks all OAuth endpoints,
//!   supported scopes, and signing keys (valuable recon for targeted attacks).
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
pub async fn probe(
    client: &Client,
    target: &Target,
    baseline: Option<&crate::soft404::BaselineFingerprint>,
) -> anyhow::Result<Vec<Finding>> {
    let Target::Web(asset) = target else {
        return Ok(vec![]);
    };
    let base = asset.url.as_str().trim_end_matches('/');
    let mut findings = Vec::new();

    // ── OIDC discovery endpoint ──────────────────────────────────────────
    for path in OIDC_DISCOVERY_PATHS {
        let url = format!("{}{}", base, path);
        let resp = match client.get(&url).send().await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(
                    "OIDC discovery probe send failed: url={} error={}",
                    url,
                    e
                );
                continue;
            }
        };

        if resp.status().as_u16() != 200 {
            continue;
        }

        let body = match gossan_core::net::bounded_text(resp, crate::MAX_BODY_BYTES).await {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(
                    "OIDC discovery body read failed: url={} error={}",
                    url,
                    e
                );
                continue;
            }
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
                body_excerpt: Some(body.chars().take(crate::MAX_BODY_EXCERPT_CHARS).collect::<String>().into()),
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

            match client.get(&probe_url).send().await {
                Ok(resp) => {
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
                                            "OAuth redirect_uri not validated, authorization code theft",
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
                Err(e) => {
                    tracing::warn!(
                        "OAuth redirect_uri probe send failed: url={} error={}",
                        probe_url,
                        e
                    );
                }
            }
        }

        // ── Probe JWKS endpoint ──────────────────────────────────────────
        if let Some(jwks_url) = jwks_uri {
            match client.get(jwks_url).send().await {
                Ok(resp) => {
                    if resp.status().as_u16() == 200 {
                        match gossan_core::net::bounded_text(resp, crate::MAX_BODY_BYTES).await {
                            Ok(jwks_body) => {
                                match serde_json::from_str::<serde_json::Value>(&jwks_body) {
                                    Ok(jwks) => {

                                        let key_count =
                                            jwks["keys"].as_array().map(|arr| arr.len()).unwrap_or(0);

                                        // High only when usable oct key material (`k`) is present.
                                        // Alg-only HS* entries are common and must not emit High.
                                        let algorithms: Vec<&str> = jwks["keys"]
                                            .as_array()
                                            .map(|arr| {
                                                arr.iter().filter_map(|k| k["alg"].as_str()).collect()
                                            })
                                            .unwrap_or_default();

                                        if jwks_exposes_usable_oct_symmetric_material(&jwks) {
                                            gossan_core::try_push_finding(
                                                crate::misconfig_finding(
                                                    target,
                                                    Severity::High,
                                                    "JWKS exposes symmetric signing keys",
                                                    format!(
                                                        "The JWKS endpoint at '{}' lists {} keys and                                                      includes usable oct key material (field `k`).                                                      Symmetric algorithms present: {}. An attacker                                                      with this material can forge JWTs.",
                                                        jwks_url,
                                                        key_count,
                                                        if algorithms.is_empty() {
                                                            "unspecified".to_string()
                                                        } else {
                                                            algorithms.join(", ")
                                                        }
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
                                    Err(e) => {
                                        tracing::warn!(error = %e, "JWKS JSON parse failed");
                                    }
                                }
                            }
                            Err(e) => {
                                tracing::warn!(
                                    "JWKS body read failed: url={} error={}",
                                    jwks_url,
                                    e
                                );
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        "JWKS probe send failed: url={} error={}",
                        jwks_url,
                        e
                    );
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

            match client.post(token_url).form(&params).send().await {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    // If the error is about the code being invalid (not about missing client_secret),
                    // the token endpoint doesn't require client authentication.
                    match gossan_core::net::bounded_text(resp, crate::MAX_BODY_BYTES).await {
                        Ok(body) => {
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
                                            body.chars().take(crate::MAX_BODY_EXCERPT_CHARS).collect::<String>().into(),
                                        ),
                                    }),
                                    &mut findings,
                                );
                            }
                        }
                        Err(e) => {
                            tracing::warn!(
                                "OAuth token endpoint body read failed: url={} error={}",
                                token_url,
                                e
                            );
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        "OAuth token endpoint probe send failed: url={} error={}",
                        token_url,
                        e
                    );
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
            let resp = match client.get(&url).send().await {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(
                        "OAuth auth endpoint probe send failed: url={} error={}",
                        url,
                        e
                    );
                    continue;
                }
            };
            let status = resp.status().as_u16();
            let bytes = match crate::soft404::read_limited(resp, crate::MAX_BODY_BYTES).await {
                Some(b) => b,
                None => continue,
            };
            // If the endpoint exists (200 or redirect), it's worth noting.
            if status == 200 || status == 302 || status == 303 {
                if crate::soft404::is_likely_404(status, &bytes, baseline, false) {
                    continue;
                }
                gossan_core::try_push_finding(
                    crate::misconfig_finding(
                        target,
                        Severity::Info,
                        format!("OAuth endpoint detected: {}", path),
                        format!(
                            "HTTP {} from '{}', an OAuth authorization endpoint is present. \
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


/// True when a JWK carries usable symmetric oct key material (`kty=oct` + non-empty `k`).
fn jwk_has_usable_oct_key_material(key: &serde_json::Value) -> bool {
    let kty_oct = key["kty"]
        .as_str()
        .map(|s| s.eq_ignore_ascii_case("oct"))
        .unwrap_or(false);
    let has_k = key["k"]
        .as_str()
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false);
    kty_oct && has_k
}

/// High-severity JWKS finding gate: alg-only HS* must not fire.
fn jwks_exposes_usable_oct_symmetric_material(jwks: &serde_json::Value) -> bool {
    jwks["keys"]
        .as_array()
        .map(|arr| arr.iter().any(jwk_has_usable_oct_key_material))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oidc_discovery_paths_include_well_known() {
        assert!(OIDC_DISCOVERY_PATHS.contains(&"/.well-known/openid-configuration"));
    }

    #[test]
    fn oidc_discovery_paths_include_keycloak() {
        assert!(OIDC_DISCOVERY_PATHS.contains(&"/realms/master/.well-known/openid-configuration"));
    }

    #[test]
    fn auth_endpoint_paths_include_authorize() {
        assert!(AUTH_ENDPOINT_PATHS.contains(&"/authorize"));
    }

    #[test]
    fn auth_endpoint_paths_include_connect_authorize() {
        assert!(AUTH_ENDPOINT_PATHS.contains(&"/connect/authorize"));
    }

    #[test]
    fn auth_endpoint_paths_count_is_reasonable() {
        assert!(
            AUTH_ENDPOINT_PATHS.len() >= 5,
            "expected >=5 auth endpoint paths, got {}",
            AUTH_ENDPOINT_PATHS.len()
        );
    }

    #[tokio::test]
    async fn fallback_auth_endpoint_suppressed_on_catch_all_spa() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let shell = "<html><body>SPA shell</body></html>";
        // All paths, including common auth endpoints, return the SPA shell.
        Mock::given(method("GET"))
            .and(path("/authorize"))
            .respond_with(ResponseTemplate::new(200).set_body_string(shell))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string(shell))
            .mount(&server)
            .await;

        let client = reqwest::Client::new();
        let target = gossan_core::testkit::web_target(&server.uri());
        let baseline = crate::soft404::establish(&client, &server.uri()).await;
        let findings = probe(&client, &target, baseline.as_ref()).await.unwrap();
        assert!(
            !findings.iter().any(|f| f.title().contains("OAuth endpoint detected")),
            "expected fallback OAuth endpoint to be suppressed on catch-all SPA, got {:?}",
            findings
        );
    }

    #[tokio::test]
    async fn fallback_auth_endpoint_fires_on_real_redirect() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let shell = "<html><body>SPA shell</body></html>";
        Mock::given(method("GET"))
            .and(path("/authorize"))
            .respond_with(
                ResponseTemplate::new(302).insert_header("location", "https://idp.example.com/callback"),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string(shell))
            .mount(&server)
            .await;

        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let target = gossan_core::testkit::web_target(&server.uri());
        let baseline = crate::soft404::establish(&client, &server.uri()).await;
        let findings = probe(&client, &target, baseline.as_ref()).await.unwrap();
        assert!(
            findings.iter().any(|f| f.title().contains("OAuth endpoint detected")),
            "expected fallback OAuth endpoint finding on real 302, got {:?}",
            findings
        );
    }

    #[test]
    fn jwks_alg_only_hs256_does_not_emit_high_signal() {
        let jwks = serde_json::json!({
            "keys": [
                {"kty": "RSA", "alg": "HS256", "kid": "a"},
                {"kty": "EC", "alg": "HS384", "kid": "b"},
                {"alg": "HS512", "kid": "c"}
            ]
        });
        assert!(
            !jwks_exposes_usable_oct_symmetric_material(&jwks),
            "alg-only HS* must not count as exposed symmetric key material"
        );
    }

    #[test]
    fn jwks_oct_with_k_emits_high_signal() {
        let jwks = serde_json::json!({
            "keys": [
                {
                    "kty": "oct",
                    "alg": "HS256",
                    "kid": "sym",
                    "k": "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"
                }
            ]
        });
        assert!(jwks_exposes_usable_oct_symmetric_material(&jwks));
    }

    #[test]
    fn jwks_oct_without_k_does_not_emit_high_signal() {
        let jwks = serde_json::json!({
            "keys": [{"kty": "oct", "alg": "HS256", "kid": "empty"}]
        });
        assert!(!jwks_exposes_usable_oct_symmetric_material(&jwks));
    }

    #[test]
    fn jwk_empty_k_string_is_not_usable_material() {
        let key = serde_json::json!({"kty": "oct", "alg": "HS256", "k": "   "});
        assert!(!jwk_has_usable_oct_key_material(&key));
    }
}
