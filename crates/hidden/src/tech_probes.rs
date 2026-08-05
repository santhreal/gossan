//! Technology-specific vulnerability probes.
//!
//! Once `techstack` fingerprints the CMS/framework, these probes run
//! targeted checks that only make sense for that specific technology.
//!
//! WordPress  - user enumeration (REST), xmlrpc.php, debug.log
//! Drupal     - CHANGELOG.txt version, update.php exposure
//! Laravel    - Ignition debug/RCE (CVE-2021-3129)
//! Joomla     - /administrator/ panel exposure
//! Strapi     - open registration, admin UI

use gossan_core::{Target, WebAssetTarget};
use reqwest::Client;
use secfinding::{Evidence, Finding, Severity};

pub async fn probe(
    client: &Client,
    asset: &WebAssetTarget,
    target: &Target,
    rate_limiter: &crate::HostRateLimiter,
    host: &str,
    baseline: Option<&crate::soft404::BaselineFingerprint>,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let base = asset.url.as_str().trim_end_matches('/');

    for tech in &asset.tech {
        let f = match tech.name.as_str() {
            "WordPress" => wordpress(client, base, target, rate_limiter, host, baseline).await,
            "Drupal" => drupal(client, base, target, rate_limiter, host).await,
            "Laravel" => laravel(client, base, target, rate_limiter, host).await,
            "Joomla" => joomla(client, base, target, rate_limiter, host).await,
            "Strapi" => strapi(client, base, target, rate_limiter, host).await,
            _ => vec![],
        };
        findings.extend(f);
    }

    findings
}

// -- WordPress -----------------------------------------------------------------

async fn wordpress(
    client: &Client,
    base: &str,
    target: &Target,
    rate_limiter: &crate::HostRateLimiter,
    host: &str,
    baseline: Option<&crate::soft404::BaselineFingerprint>,
) -> Vec<Finding> {
    let mut f = Vec::new();

    // User enumeration via REST API, leaks usernames for brute force
    let url = format!("{}/wp-json/wp/v2/users", base);
    rate_limiter.wait_for_host(host).await;
    match client.get(&url).send().await {
        Ok(resp) => {
                let status = resp.status().as_u16();
                rate_limiter.observe_status(host, status).await;
                if status == 200 {
                    let body = match gossan_core::net::bounded_text(resp, crate::MAX_BODY_BYTES).await {

                        Ok(b) => b,

                        Err(e) => {

                            tracing::warn!(

                                "tech probe body read failed: url={} error={}",

                                url, e

                            );

                            String::new()

                        }

                    };
                    if body.contains("\"id\"") && body.contains("\"slug\"") {
                        gossan_core::try_push_finding(
                            crate::info_finding(
                                target,
                                Severity::High,
                                "WordPress user enumeration via REST API",
                                format!(
                                    "{} exposes user accounts (IDs, names, slugs). \
                                         Attackers use these to craft targeted brute force attacks.",
                                    url
                                ),
                            )
                            .evidence(Evidence::HttpResponse {
                                status: 200,
                                headers: vec![],
                                body_excerpt: Some(body.chars().take(crate::MAX_BODY_EXCERPT_CHARS).collect::<String>().into()),
                            })
                            .tag("wordpress")
                            .tag("user-enum")
                            .tag("exposure")
                            .exploit_hint(format!(
                                "curl -s '{}/wp-json/wp/v2/users' | jq '.[].{{id,name,slug}}'",
                                base
                            )),
                            &mut f,
                        );
                    }
                }
        }
        Err(e) => {
            tracing::warn!(
                "tech probe send failed: url={} error={}",
                url, e
            );
        }
    }

    // XML-RPC: brute force amplification via system.multicall
    let xmlrpc_url = format!("{}/xmlrpc.php", base);
    rate_limiter.wait_for_host(host).await;
    match client.get(&xmlrpc_url).send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            rate_limiter.observe_status(host, status).await;
            if status == 200 || status == 405 {
                let body = match gossan_core::net::bounded_text(resp, crate::MAX_BODY_BYTES).await {
                    Ok(b) => b,
                    Err(e) => {
                        tracing::warn!(
                            "xmlrpc body read failed: url={} error={}",
                            xmlrpc_url,
                            e
                        );
                        String::new()
                    }
                };
                if xmlrpc_response_confirms_enabled(status, &body, baseline) {
                    gossan_core::try_push_finding(
                        crate::info_finding(
                            target,
                            Severity::Medium,
                            "WordPress XML-RPC enabled",
                            format!(
                                "{} is accessible. system.multicall lets attackers test                                      hundreds of passwords per request, completely bypassing                                      rate-limiting and account lockout controls.",
                                xmlrpc_url
                            ),
                        )
                        .evidence(Evidence::HttpResponse {
                            status,
                            headers: vec![],
                            body_excerpt: Some(
                                body.chars()
                                    .take(crate::MAX_BODY_EXCERPT_CHARS)
                                    .collect::<String>()
                                    .into(),
                            ),
                        })
                        .tag("wordpress")
                        .tag("xmlrpc")
                        .tag("brute-force")
                        .exploit_hint(format!(
                            "# WPScan multicall brute force (no lockout):\n                             wpscan --url {} --passwords wordlist.txt --xmlrpc-brute-force",
                            base
                        )),
                        &mut f,
                    );
                }
            }
        }
        Err(e) => {
            tracing::warn!(
                "xmlrpc probe send failed: url={} error={}",
                xmlrpc_url,
                e
            );
        }
    }

    // Debug log often left behind after troubleshooting
    let debug_url = format!("{}/wp-content/debug.log", base);
    rate_limiter.wait_for_host(host).await;
    match client.get(&debug_url).send().await {
        Ok(resp) => {
                let status = resp.status().as_u16();
                rate_limiter.observe_status(host, status).await;
                if status == 200 {
                    let body = match gossan_core::net::bounded_text(resp, crate::MAX_BODY_BYTES).await {

                        Ok(b) => b,

                        Err(e) => {

                            tracing::warn!(

                                "tech probe body read failed: url={} error={}",

                                debug_url, e

                            );

                            String::new()

                        }

                    };
                    if (body.contains("PHP") || body.contains("WordPress") || body.contains("Fatal"))
                        && body.len() > 50
                    {
                        gossan_core::try_push_finding(
                            crate::info_finding(
                                target,
                                Severity::High,
                                "WordPress debug.log publicly readable",
                                format!(
                                    "{} leaks PHP errors, internal paths, plugin names, \
                                         and sometimes credentials or API keys.",
                                    debug_url
                                ),
                            )
                            .evidence(Evidence::HttpResponse {
                                status: 200,
                                headers: vec![],
                                body_excerpt: Some(body.chars().take(crate::MAX_BODY_EXCERPT_CHARS).collect::<String>().into()),
                            })
                            .tag("wordpress")
                            .tag("log-exposure")
                            .tag("exposure"),
                            &mut f,
                        );
                    }
                }
        }
        Err(e) => {
            tracing::warn!(
                "tech probe send failed: url={} error={}",
                debug_url, e
            );
        }
    }

    f
}

/// Confirm XML-RPC only with body markers; never treat bare HTTP 405 as proof.
/// Also reject soft-404 / catch-all shells that happen to return 200/405.
fn xmlrpc_response_confirms_enabled(
    status: u16,
    body: &str,
    baseline: Option<&crate::soft404::BaselineFingerprint>,
) -> bool {
    if !(status == 200 || status == 405) {
        return false;
    }
    let lower = body.to_ascii_lowercase();
    let has_marker = lower.contains("xml-rpc") || lower.contains("xmlrpc");
    if !has_marker {
        return false;
    }
    if crate::soft404::is_likely_404(status, body.as_bytes(), baseline, false) {
        return false;
    }
    true
}


#[cfg(test)]
mod tests {
    use super::*;
    use gossan_core::{HostTarget, Protocol, ServiceTarget, WebAssetTarget};
    use reqwest::Url;

    fn dummy_asset(tech: Vec<gossan_core::Technology>) -> WebAssetTarget {
        WebAssetTarget {
            url: Url::parse("http://example.com/").unwrap(),
            service: ServiceTarget {
                host: HostTarget {
                    ip: "127.0.0.1".parse().unwrap(),
                    domain: Some("example.com".to_string()),
                },
                port: 80,
                protocol: Protocol::Tcp,
                banner: None,
                tls: false,
            },
            tech,
            status: 200,
            title: None,
            favicon_hash: None,
            body_hash: None,
            forms: vec![],
            params: vec![],
        }
    }

    #[test]
    fn probe_returns_empty_for_empty_tech_list() {
        let client = reqwest::Client::new();
        let asset = dummy_asset(vec![]);
        let target = Target::Web(Box::new(asset.clone()));
        let rl = crate::HostRateLimiter::new(0);
        let findings =
            futures::executor::block_on(probe(&client, &asset, &target, &rl, "example.com", None));
        assert!(findings.is_empty());
    }

    #[test]
    fn probe_returns_empty_for_unknown_tech() {
        let client = reqwest::Client::new();
        let tech = vec![gossan_core::Technology {
            name: "UnknownCMS".to_string(),
            version: None,
            category: gossan_core::TechCategory::Cms,
            confidence: 100,
        }];
        let asset = dummy_asset(tech);
        let target = Target::Web(Box::new(asset.clone()));
        let rl = crate::HostRateLimiter::new(0);
        let findings =
            futures::executor::block_on(probe(&client, &asset, &target, &rl, "example.com", None));
        assert!(findings.is_empty());
    }

    #[test]
    fn dummy_asset_url_is_parsed() {
        let asset = dummy_asset(vec![]);
        assert_eq!(asset.url.as_str(), "http://example.com/");
    }

    #[test]
    fn dummy_asset_has_empty_tech_by_default() {
        let asset = dummy_asset(vec![]);
        assert!(asset.tech.is_empty());
    }

    #[test]
    fn dummy_asset_has_expected_host_domain() {
        let asset = dummy_asset(vec![]);
        assert_eq!(asset.service.host.domain, Some("example.com".to_string()));
    }
}

// -- Drupal --------------------------------------------------------------------

async fn drupal(
    client: &Client,
    base: &str,
    target: &Target,
    rate_limiter: &crate::HostRateLimiter,
    host: &str,
) -> Vec<Finding> {
    let mut f = Vec::new();

    // CHANGELOG.txt reveals exact Drupal version
    let url = format!("{}/CHANGELOG.txt", base);
    rate_limiter.wait_for_host(host).await;
    match client.get(&url).send().await {
        Ok(resp) => {
                let status = resp.status().as_u16();
                rate_limiter.observe_status(host, status).await;
                if status == 200 {
                    let body = match gossan_core::net::bounded_text(resp, crate::MAX_BODY_BYTES).await {

                        Ok(b) => b,

                        Err(e) => {

                            tracing::warn!(

                                "tech probe body read failed: url={} error={}",

                                url, e

                            );

                            String::new()

                        }

                    };
                    if body.contains("Drupal") {
                        let version = body
                            .lines()
                            .find(|l| l.trim().starts_with("Drupal"))
                            .map(|l| l.trim().to_string())
                            .unwrap_or_else(|| "Drupal (version unknown)".into());
                        gossan_core::try_push_finding(crate::info_finding(target, Severity::Medium,
                                "Drupal version disclosure via CHANGELOG.txt",
                                format!("CHANGELOG.txt reveals exact Drupal version: \"{}\". \
                                         Enables targeted CVE exploitation: Drupalgeddon2 (SA-CORE-2018-002, \
                                         CVSS 9.8) affects versions < 8.5.1.", version))
                            .evidence(Evidence::HttpResponse {
                                status: 200, headers: vec![],
                                body_excerpt: Some(body.chars().take(crate::MAX_BODY_EXCERPT_CHARS).collect::<String>().into()),
                            })
                            .tag("drupal").tag("version-disclosure").tag("exposure")
                            .exploit_hint(format!(
                                "# Drupalgeddon2 (< 8.5.1 / < 7.58):\n\
                                 python3 drupalgeddon2.py -u {}", base)), &mut f);
                    }
                }
        }
        Err(e) => {
            tracing::warn!(
                "tech probe send failed: url={} error={}",
                url, e
            );
        }
    }

    // update.php accessible to anonymous users
    let update_url = format!("{}/update.php", base);
    rate_limiter.wait_for_host(host).await;
    match client.get(&update_url).send().await {
        Ok(resp) => {
                let status = resp.status().as_u16();
                rate_limiter.observe_status(host, status).await;
                if status == 200 {
                    let body = match gossan_core::net::bounded_text(resp, crate::MAX_BODY_BYTES).await {

                        Ok(b) => b,

                        Err(e) => {

                            tracing::warn!(

                                "tech probe body read failed: url={} error={}",

                                update_url, e

                            );

                            String::new()

                        }

                    };
                    if body.contains("Drupal") || body.contains("database update") {
                        gossan_core::try_push_finding(
                            crate::info_finding(
                                target,
                                Severity::High,
                                "Drupal update.php exposed",
                                format!(
                                    "{} is publicly accessible. Running database updates \
                                         via the web interface can corrupt data or expose the \
                                         install to privilege escalation.",
                                    update_url
                                ),
                            )
                            .evidence(Evidence::HttpResponse {
                                status: 200,
                                headers: vec![],
                                body_excerpt: None,
                            })
                            .tag("drupal")
                            .tag("exposure"),
                            &mut f,
                        );
                    }
                }
        }
        Err(e) => {
            tracing::warn!(
                "tech probe send failed: url={} error={}",
                update_url, e
            );
        }
    }

    f
}

// -- Laravel -------------------------------------------------------------------

async fn laravel(
    client: &Client,
    base: &str,
    target: &Target,
    rate_limiter: &crate::HostRateLimiter,
    host: &str,
) -> Vec<Finding> {
    let mut f = Vec::new();

    // Ignition health-check, if exposed, RCE likely available (CVE-2021-3129)
    let url = format!("{}/_ignition/health-check", base);
    rate_limiter.wait_for_host(host).await;
    match client.get(&url).send().await {
        Ok(resp) => {
                let status = resp.status().as_u16();
                rate_limiter.observe_status(host, status).await;
                if status == 200 {
                    let body = match gossan_core::net::bounded_text(resp, crate::MAX_BODY_BYTES).await {

                        Ok(b) => b,

                        Err(e) => {

                            tracing::warn!(

                                "tech probe body read failed: url={} error={}",

                                url, e

                            );

                            String::new()

                        }

                    };
                    if body.contains("can_execute_commands") || body.contains("ignition") {
                        let can_exec = body.contains("\"can_execute_commands\":true");
                        let sev = if can_exec {
                            Severity::Critical
                        } else {
                            Severity::High
                        };
                        gossan_core::try_push_finding(crate::info_finding(target, sev,
                                if can_exec {
                                    "Laravel Ignition RCE: CVE-2021-3129 (can_execute_commands:true)"
                                } else {
                                    "Laravel Ignition debug endpoint exposed (CVE-2021-3129)"
                                },
                                format!("{}/_ignition/ debug endpoint is accessible{}. \
                                         CVE-2021-3129 achieves unauthenticated RCE via PHAR deserialization \
                                         through the make-view-variable solution endpoint. CVSS 9.8.", base,
                                        if can_exec { " with shell execution enabled" } else { "" }))
                            .evidence(Evidence::HttpResponse {
                                status: 200, headers: vec![],
                                body_excerpt: Some(body.chars().take(crate::MAX_BODY_EXCERPT_CHARS).collect::<String>().into()),
                            })
                            .tag("laravel").tag("rce").tag("cve-2021-3129")
                            .exploit_hint(format!(
                                "# CVE-2021-3129: PHAR deserialization RCE:\n\
                                 git clone https://github.com/ambionics/laravel-exploits\n\
                                 php -d phar.readonly=0 phpggc Laravel/RCE5 'id' --phar phar -o /tmp/rce.phar\n\
                                 python3 laravel-exploits/laravel-ignition-rce.py {} /tmp/rce.phar", base)), &mut f);
                    }
                }
        }
        Err(e) => {
            tracing::warn!(
                "tech probe send failed: url={} error={}",
                url, e
            );
        }
    }

    f
}

// -- Joomla --------------------------------------------------------------------

async fn joomla(
    client: &Client,
    base: &str,
    target: &Target,
    rate_limiter: &crate::HostRateLimiter,
    host: &str,
) -> Vec<Finding> {
    let mut f = Vec::new();

    let admin_url = format!("{}/administrator/", base);
    rate_limiter.wait_for_host(host).await;
    match client.get(&admin_url).send().await {
        Ok(resp) => {
                let status = resp.status().as_u16();
                rate_limiter.observe_status(host, status).await;
                if status == 200 {
                    let body = match gossan_core::net::bounded_text(resp, crate::MAX_BODY_BYTES).await {

                        Ok(b) => b,

                        Err(e) => {

                            tracing::warn!(

                                "tech probe body read failed: url={} error={}",

                                admin_url, e

                            );

                            String::new()

                        }

                    };
                    if body.contains("Joomla") || body.contains("mod-login") {
                        gossan_core::try_push_finding(crate::info_finding(target, Severity::Medium,
                                "Joomla administrator panel exposed",
                                format!("{} is publicly accessible. The Joomla admin \
                                         backend is exposed to credential brute force and \
                                         known auth bypass CVEs.", admin_url))
                            .evidence(Evidence::HttpResponse {
                                status: 200, headers: vec![], body_excerpt: None,
                            })
                            .tag("joomla").tag("admin-panel").tag("exposure")
                            .exploit_hint(format!(
                                "hydra -L users.txt -P passwords.txt {} http-post-form \
                                 '/administrator/index.php:username=^USER^&passwd=^PASS^&task=login:F=Invalid'",
                                base)), &mut f);
                    }
                }
        }
        Err(e) => {
            tracing::warn!(
                "tech probe send failed: url={} error={}",
                admin_url, e
            );
        }
    }

    f
}

// -- Strapi --------------------------------------------------------------------

async fn strapi(
    client: &Client,
    base: &str,
    target: &Target,
    rate_limiter: &crate::HostRateLimiter,
    host: &str,
) -> Vec<Finding> {
    let mut f = Vec::new();

    // Admin UI exposed
    let admin_url = format!("{}/admin", base);
    rate_limiter.wait_for_host(host).await;
    match client.get(&admin_url).send().await {
        Ok(resp) => {
                let status = resp.status().as_u16();
                rate_limiter.observe_status(host, status).await;
                if status == 200 {
                    let body = match gossan_core::net::bounded_text(resp, crate::MAX_BODY_BYTES).await {

                        Ok(b) => b,

                        Err(e) => {

                            tracing::warn!(

                                "tech probe body read failed: url={} error={}",

                                admin_url, e

                            );

                            String::new()

                        }

                    };
                    if body.contains("strapi") || body.contains("Strapi") {
                        gossan_core::try_push_finding(
                            crate::info_finding(
                                target,
                                Severity::Medium,
                                "Strapi admin panel accessible",
                                format!(
                                    "{} admin UI is reachable. If initial setup was never completed, \
                                         an attacker can register the first super-admin account.",
                                    admin_url
                                ),
                            )
                            .evidence(Evidence::HttpResponse {
                                status: 200,
                                headers: vec![],
                                body_excerpt: None,
                            })
                            .tag("strapi")
                            .tag("admin-panel")
                            .tag("exposure"),
                            &mut f,
                        );
                    }
                }
        }
        Err(e) => {
            tracing::warn!(
                "tech probe send failed: url={} error={}",
                admin_url, e
            );
        }
    }

    // Open self-registration endpoint (v4 path)
    let reg_url = format!("{}/api/auth/local/register", base);
    rate_limiter.wait_for_host(host).await;
    match client
        .post(&reg_url)
        .header("content-type", "application/json")
        .body(r#"{"username":"gossan-probe","email":"probe@invalid.test","password":"!Probe99"}"#)
        .send()
        .await
    {
        Ok(resp) => {
            let status = resp.status().as_u16();
            rate_limiter.observe_status(host, status).await;
            if status == 200 {
            gossan_core::try_push_finding(crate::info_finding(target, Severity::High,
                    "Strapi open user registration enabled",
                    format!("{} accepts new user signups without restriction. \
                             Attackers can self-register to gain authenticated API access \
                             and explore protected endpoints.", reg_url))
                .evidence(Evidence::HttpResponse {
                    status: 200, headers: vec![], body_excerpt: None,
                })
                .tag("strapi").tag("auth-bypass").tag("exposure")
                .exploit_hint(format!(
                    "curl -s -X POST '{}' -H 'Content-Type: application/json' \\\n  \
                     -d '{{\"username\":\"attacker\",\"email\":\"a@evil.com\",\"password\":\"P@ssw0rd!\"}}' \\\n  \
                     | jq .jwt", reg_url)), &mut f);
            }
        }
        Err(e) => {
            tracing::warn!("tech probe send failed: url={} error={}", reg_url, e);
        }
    }

    f
}

#[cfg(test)]
mod xmlrpc_confirm_tests {
    use super::*;

    #[test]
    fn xmlrpc_bare_405_without_markers_is_not_confirmation() {
        assert!(
            !xmlrpc_response_confirms_enabled(405, "Method Not Allowed", None),
            "bare 405 must not confirm XML-RPC"
        );
        assert!(!xmlrpc_response_confirms_enabled(200, "<html>hello</html>", None));
    }

    #[test]
    fn xmlrpc_markers_confirm_on_200_or_405() {
        assert!(xmlrpc_response_confirms_enabled(
            200,
            "XML-RPC server accepts POST requests only.",
            None
        ));
        assert!(xmlrpc_response_confirms_enabled(
            405,
            "XML-RPC server accepts POST requests only.",
            None
        ));
        assert!(xmlrpc_response_confirms_enabled(200, "this is xmlrpc endpoint", None));
    }

    #[test]
    fn xmlrpc_soft404_shell_with_marker_word_rejected() {
        let body = "<html>xmlrpc marketing page</html>";
        let baseline = crate::soft404::BaselineFingerprint {
            status: 200,
            avg_body_len: body.len(),
            // Non-matching hashes; length similarity alone still marks soft-404.
            hashes: vec![0],
        };
        assert!(
            !xmlrpc_response_confirms_enabled(200, body, Some(&baseline)),
            "soft-404 HTML mentioning xmlrpc must not confirm"
        );
    }

}
