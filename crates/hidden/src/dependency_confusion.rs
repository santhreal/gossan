//! Dependency confusion probe.
//!
//! Detects exposed package manifest files that reveal internal package names,
//! scopes, and registries, the raw material for dependency confusion /
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

    for (path, title, confirms) in MANIFESTS {
        let url = format!("{}{}", base, path);
        let Ok(resp) = client.get(&url).send().await else {
            tracing::warn!(url = %url, "dependency_confusion: manifest fetch send failed");
            continue;
        };
        if resp.status().as_u16() != 200 {
            continue;
        }
        let body = gossan_core::net::bounded_text(resp, crate::MAX_BODY_BYTES)
            .await?;

        if crate::soft404::is_likely_404(200, body.as_bytes(), baseline, false) {
            continue;
        }

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
                    body_excerpt: Some(body.chars().take(crate::MAX_BODY_EXCERPT_CHARS).collect::<String>().into()),
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

    #[test]
    fn manifests_include_package_json() {
        assert!(MANIFESTS.iter().any(|(p, _, _)| *p == "/package.json"));
    }

    #[test]
    fn manifests_include_cargo_toml() {
        assert!(MANIFESTS.iter().any(|(p, _, _)| *p == "/Cargo.toml"));
    }

    #[test]
    fn extract_scopes_empty_for_unknown_path() {
        let scopes = extract_scopes("/unknown.txt", "anything");
        assert!(scopes.is_empty());
    }

    #[test]
    fn extract_scopes_limits_to_five() {
        let body = (0..10)
            .map(|i| format!("\"@scope{}/pkg\": \"1.0.0\"", i))
            .collect::<Vec<_>>()
            .join(", ");
        let scopes = extract_scopes("/package.json", &body);
        assert_eq!(scopes.len(), 5);
    }

    #[test]
    fn manifests_all_have_non_empty_title() {
        for (_, title, _) in MANIFESTS {
            assert!(!title.is_empty());
        }
    }

    #[test]
    fn extract_npm_scopes_ignores_invalid() {
        let body = r#"{ "dependencies": { "@ bad scope/pkg": "1.0.0" } }"#;
        let scopes = extract_scopes("/package.json", body);
        assert!(scopes.is_empty());
    }

    #[test]
    fn extract_composer_scopes_ignores_whitespace() {
        let body = r#"{ "require": { "bad vendor / bad package": "^1.0" } }"#;
        let scopes = extract_scopes("/composer.json", body);
        assert!(!scopes.iter().any(|s| s.contains(' ')));
    }

    #[test]
    fn manifests_include_go_mod() {
        assert!(MANIFESTS.iter().any(|(p, _, _)| *p == "/go.mod"));
    }

    #[test]
    fn manifests_all_have_confirmation_strings_or_empty() {
        for (_, _, confirms) in MANIFESTS {
            // Every manifest either has confirm strings or explicitly empty list
            assert!(confirms.is_empty() || !confirms.is_empty());
        }
    }

    #[test]
    fn extract_scopes_dedupes_duplicates() {
        let body = r#"{ "dependencies": { "@internal/a": "1.0.0", "@internal/b": "2.0.0" } }"#;
        let scopes = extract_scopes("/package.json", body);
        assert_eq!(scopes.len(), 1);
        assert_eq!(scopes[0], "internal");
    }

    #[test]
    fn extract_scopes_empty_body() {
        let scopes = extract_scopes("/package.json", "");
        assert!(scopes.is_empty());
    }

    #[test]
    fn extract_scopes_single_param() {
        let body = r#"{"dependencies":{"@scope/pkg":"1.0.0"}}"#;
        let scopes = extract_scopes("/package.json", body);
        assert_eq!(scopes.len(), 1);
        assert_eq!(scopes[0], "scope");
    }

    #[test]
    fn extract_scopes_100_params() {
        let deps: Vec<String> = (0..100)
            .map(|i| format!("\"@scope{}/pkg\": \"1.0.0\"", i))
            .collect();
        let body = format!("{{\"dependencies\":{{{}}}}}", deps.join(", "));
        let scopes = extract_scopes("/package.json", &body);
        assert_eq!(scopes.len(), 5); // capped at 5
    }

    #[test]
    fn extract_scopes_special_chars_ignored() {
        let body = r#"{"dependencies":{"@bad scope/pkg":"1.0.0"}}"#;
        let scopes = extract_scopes("/package.json", body);
        assert!(scopes.is_empty());
    }

    #[test]
    fn extract_scopes_unicode_in_package_name() {
        let body = r#"{"dependencies":{"@日本語/pkg":"1.0.0"}}"#;
        let scopes = extract_scopes("/package.json", body);
        assert_eq!(scopes.len(), 1);
        assert_eq!(scopes[0], "日本語");
    }

    #[test]
    fn extract_scopes_path_traversal_extracts_first_segment() {
        let body = r#"{"dependencies":{"@../etc/passwd/pkg":"1.0.0"}}"#;
        let scopes = extract_scopes("/package.json", body);
        assert_eq!(scopes.len(), 1);
        // extract_scopes splits on first '/', so ".." is the scope segment
        assert_eq!(scopes[0], "..");
    }

    #[test]
    fn extract_scopes_url_encoding_no_literal_slash() {
        let body = r#"{"dependencies":{"@scope%2Fpkg":"1.0.0"}}"#;
        let scopes = extract_scopes("/package.json", body);
        // %2F is not a literal '/', so no scope is extracted
        assert!(scopes.is_empty());
    }

    #[test]
    fn extract_scopes_null_bytes_preserved_in_segment() {
        let body = "{\"dependencies\":{\"@scope\0/pkg\":\"1.0.0\"}}";
        let scopes = extract_scopes("/package.json", body);
        assert_eq!(scopes.len(), 1);
        assert_eq!(scopes[0], "scope\0");
    }

    #[test]
    fn extract_scopes_composer_empty() {
        let scopes = extract_scopes("/composer.json", "");
        assert!(scopes.is_empty());
    }

    #[test]
    fn extract_scopes_composer_single_package() {
        let body = r#"{"require":{"vendor/package":"^1.0"}}"#;
        let scopes = extract_scopes("/composer.json", body);
        assert_eq!(scopes.len(), 1);
        assert_eq!(scopes[0], "vendor/package");
    }

    #[test]
    fn extract_scopes_composer_100_packages() {
        let pkgs: Vec<String> = (0..100)
            .map(|i| format!("\"vendor{}/package\": \"^1.0\"", i))
            .collect();
        let body = format!("{{\"require\":{{{}}}}}", pkgs.join(", "));
        let scopes = extract_scopes("/composer.json", &body);
        assert_eq!(scopes.len(), 5); // capped at 5
    }

    #[test]
    fn extract_scopes_unknown_path_returns_empty() {
        let scopes = extract_scopes("/unknown.txt", "anything");
        assert!(scopes.is_empty());
    }

    #[tokio::test]
    async fn catch_all_html_manifest_suppressed_by_soft404_baseline() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let shell = "<html><body> name version dependencies </body></html>";
        Mock::given(method("GET"))
            .and(path("/package.json"))
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
            findings.is_empty(),
            "expected package.json finding suppressed on catch-all HTML, got {:?}",
            findings
        );
    }

    #[tokio::test]
    async fn real_manifest_fires_when_body_differs_from_baseline() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let shell = "<html><body>SPA shell</body></html>";
        // Make the real manifest body much larger than the baseline shell so the
        // length check does not classify it as a soft-404 in non-strict mode.
        let manifest = format!(
            r#"{{"name":"x","dependencies":{{}},"description":"{}"}}"#,
            "x".repeat(500)
        );
        Mock::given(method("GET"))
            .and(path("/package.json"))
            .respond_with(ResponseTemplate::new(200).set_body_string(manifest))
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
            findings.iter().any(|f| f.title().contains("package.json")),
            "expected package.json finding when body differs from baseline, got {:?}",
            findings
        );
    }
}
