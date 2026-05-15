//! Dependency confusion probe.
//!
//! Detects exposed package manifest files that reveal internal package names,
//! scopes, and registries — the raw material for dependency confusion /
//! typosquatting attacks.

use gossan_core::Target;
use reqwest::Client;
use secfinding::{Evidence, Finding, Severity};

/// Manifest files that disclose dependency information.
const MANIFESTS: &[(&str, &str, &[&str])] = &[
    (
        "/package.json",
        "npm package.json exposed",
        &["dependencies", "devDependencies", "name", "version"],
    ),
    (
        "/composer.json",
        "PHP composer.json exposed",
        &["require", "require-dev", "name"],
    ),
    ("/requirements.txt", "Python requirements.txt exposed", &[]),
    ("/Gemfile", "Ruby Gemfile exposed", &["gem", "source"]),
    ("/go.mod", "Go go.mod exposed", &["module", "require"]),
    (
        "/pom.xml",
        "Maven pom.xml exposed",
        &["<project", "<dependency>"],
    ),
    (
        "/build.gradle",
        "Gradle build.gradle exposed",
        &["dependencies", "repositories"],
    ),
    (
        "/Cargo.toml",
        "Rust Cargo.toml exposed",
        &["[package]", "[dependencies]"],
    ),
];

pub async fn probe(client: &Client, target: &Target) -> anyhow::Result<Vec<Finding>> {
    let Target::Web(asset) = target else {
        return Ok(vec![]);
    };
    let base = asset.url.as_str().trim_end_matches('/');
    let mut findings = Vec::new();

    for (path, title, confirms) in MANIFESTS {
        let url = format!("{}{}", base, path);
        let Ok(resp) = client.get(&url).send().await else {
            continue;
        };
        if resp.status().as_u16() != 200 {
            continue;
        }
        let body = gossan_core::net::bounded_text(resp, 4 * 1024 * 1024)
            .await
            .unwrap_or_default();

        // Confirm it's a real manifest, not a generic 200 page
        let confirmed = if confirms.is_empty() {
            body.len() > 10 && !body.trim_start().starts_with('<')
        } else {
            confirms.iter().any(|c| body.contains(c))
        };

        if !confirmed {
            continue;
        }

        let scopes = extract_scopes(path, &body);
        let detail = if scopes.is_empty() {
            format!(
                "{} is publicly accessible. Dependency names and versions are disclosed, \
                 enabling dependency confusion or typosquatting attacks.",
                url
            )
        } else {
            format!(
                "{} is publicly accessible. Detected scope(s): {}. \
                 An attacker can register these names on public registries \
                 to inject malicious code into the build pipeline.",
                url,
                scopes.join(", ")
            )
        };

        gossan_core::try_push_finding(
            crate::supply_chain_finding(target, Severity::Medium, *title, detail)
                .evidence(Evidence::HttpResponse {
                    status: 200,
                    headers: vec![],
                    body_excerpt: Some(body.chars().take(300).collect::<String>().into()),
                })
                .tag("supply-chain")
                .tag("dependency-confusion")
                .tag("exposure"),
            &mut findings,
        );
    }

    Ok(findings)
}

fn extract_scopes(path: &str, body: &str) -> Vec<String> {
    let mut scopes = Vec::new();

    if path == "/package.json" {
        // Look for scoped npm packages: "@scope/name". Real package.json
        // files often serialise as one line; iterating `find('@')` would
        // only catch the first scope. Use `match_indices` so every `@`
        // in every line is considered.
        for line in body.lines() {
            for (start, _) in line.match_indices('@') {
                let rest = &line[start + 1..];
                if let Some(slash) = rest.find('/') {
                    let scope = &rest[..slash];
                    if !scope.is_empty()
                        && !scope.contains(' ')
                        && !scope.contains('"')
                        && !scopes.contains(&scope.to_string())
                    {
                        scopes.push(scope.to_string());
                    }
                }
            }
        }
    } else if path == "/composer.json" {
        // Composer require map is also commonly one-line. Walk every
        // double-quoted token and keep the ones that look like
        // `vendor/package` (forward-slash, no whitespace).
        for line in body.lines() {
            let mut cursor = 0;
            while let Some(open_rel) = line[cursor..].find('"') {
                let open = cursor + open_rel;
                let after = &line[open + 1..];
                let Some(close_rel) = after.find('"') else {
                    break;
                };
                let close = open + 1 + close_rel;
                let token = &line[open + 1..close];
                if token.contains('/')
                    && !token.contains(' ')
                    && !scopes.contains(&token.to_string())
                {
                    scopes.push(token.to_string());
                }
                cursor = close + 1;
            }
        }
    }

    scopes.into_iter().take(5).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_npm_scopes() {
        let body = r#"{ "dependencies": { "@internal/auth": "1.0.0", "@tools/build": "2.0.0" } }"#;
        let scopes = extract_scopes("/package.json", body);
        assert!(scopes.contains(&"internal".to_string()));
        assert!(scopes.contains(&"tools".to_string()));
    }

    #[test]
    fn extract_composer_packages() {
        let body = r#"{ "require": { "vendor/package": "^1.0" } }"#;
        let scopes = extract_scopes("/composer.json", body);
        assert!(scopes.contains(&"vendor/package".to_string()));
    }
}
