//! GraphQL security probes.
//!
//! 1. Introspection enabled — full schema disclosure
//! 2. Introspection bypass via alias wrapping
//! 3. Introspection bypass via fragment spreading
//! 4. Introspection via __type(name:...)
//! 5. Batching attack — DoS / rate-limit bypass via array of operations
//! 6. Field suggestion leakage — "did you mean password?" exposes schema fragments
//! 7. Verbose error mode — stack traces / internal paths in error responses
//! 8. Alias amplification — single request fans out to N resolver calls

use gossan_core::Target;
use reqwest::Client;
use secfinding::{Evidence, Finding, Severity};

const PATHS: &[&str] = &[
    "/graphql",
    "/api/graphql",
    "/v1/graphql",
    "/v2/graphql",
    "/query",
    "/gql",
    "/graphiql",
    "/playground",
    "/graph",
    "/api/graph",
    "/api/query",
];

const INTROSPECTION: &str =
    r#"{"query":"{ __schema { queryType { name } types { name kind fields { name } } } }"}"#;

const INTROSPECTION_ALIAS: &str =
    r#"{"query":"{ introspection: __schema { queryType { name } types { name kind fields { name } } } }"}"#;

const INTROSPECTION_FRAGMENT: &str =
    r#"{"query":"query { ... on __Schema { queryType { name } types { name kind } } }"}"#;

const INTROSPECTION_TYPE: &str =
    r#"{"query":"query { __type(name: \"Query\") { name fields { name } } }"}"#;

const FIELD_PROBE: &str = r#"{"query":"{ __typenme }"}"#;

const BATCH: &str = r#"[
  {"query":"{ __typename }"},
  {"query":"{ __typename }"},
  {"query":"{ __typename }"},
  {"query":"{ __typename }"},
  {"query":"{ __typename }"},
  {"query":"{ __typename }"},
  {"query":"{ __typename }"},
  {"query":"{ __typename }"},
  {"query":"{ __typename }"},
  {"query":"{ __typename }"}
]"#;

const ALIAS_AMP: &str = r#"{"query":"{
  a1:__typename a2:__typename a3:__typename a4:__typename a5:__typename
  a6:__typename a7:__typename a8:__typename a9:__typename a10:__typename
  a11:__typename a12:__typename a13:__typename a14:__typename a15:__typename
  a16:__typename a17:__typename a18:__typename a19:__typename a20:__typename
}"}"#;

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

    // Find the active GraphQL endpoint first
    let mut endpoint: Option<String> = None;
    for path in PATHS {
        let url = format!("{}{}", base, path);
        if let Ok(r) = client
            .post(&url)
            .header("content-type", "application/json")
            .body(r#"{"query":"{ __typename }"}"#)
            .send()
            .await
        {
            if r.status().as_u16() == 200 {
                let body = capped_text(r, crate::MAX_BODY_BYTES).await.unwrap_or_default();
                // Validate it's real GraphQL, not a catch-all SPA
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body) {
                    if json.get("data").and_then(|d| d.get("__typename")).is_some() {
                        endpoint = Some(url);
                        break;
                    }
                }
            }
        }
    }

    let Some(ep) = endpoint else {
        return Ok(findings);
    };

    // ── 1. Introspection ─────────────────────────────────────────────────────
    if let Ok(r) = client
        .post(&ep)
        .header("content-type", "application/json")
        .body(INTROSPECTION)
        .send()
        .await
    {
        if r.status().as_u16() == 200 {
            let body = capped_text(r, crate::MAX_BODY_BYTES).await.unwrap_or_default();
            if body.contains("__schema") || body.contains("queryType") {
                gossan_core::try_push_finding(crate::vulnerability_finding(target, Severity::High,
                        "GraphQL introspection enabled — full schema exposed",
                        format!("{} allows introspection. Attackers can enumerate every query, \
                                 mutation, type, and field name — full attack surface in one request.", ep))
                    .evidence(Evidence::HttpResponse {
                        status: 200, headers: vec![],
                        body_excerpt: Some(body.chars().take(400).collect::<String>().into()),
                    })
                    .tag("graphql").tag("exposure")
                    .exploit_hint(format!(
                        "# Dump full schema:\n\
                         npx get-graphql-schema {}\n\
                         # Or with graphql-cop:\n\
                         python3 graphql-cop.py -t {}", ep, ep)), &mut findings);
            }
        }
    }

    // ── 2. Alias bypass ──────────────────────────────────────────────────────
    if findings.iter().any(|f| f.title().contains("introspection enabled")) {
        // Already found introspection, skip bypass probes
    } else if let Ok(r) = client
        .post(&ep)
        .header("content-type", "application/json")
        .body(INTROSPECTION_ALIAS)
        .send()
        .await
    {
        if r.status().as_u16() == 200 {
            let body = capped_text(r, crate::MAX_BODY_BYTES).await.unwrap_or_default();
            if body.contains("__schema") || body.contains("queryType") {
                gossan_core::try_push_finding(crate::vulnerability_finding(target, Severity::High,
                        "GraphQL introspection bypassed via alias wrapping",
                        format!("{} blocked direct introspection but allowed the same query wrapped in an alias. \
                                 Simple regex WAF filters are insufficient.", ep))
                    .evidence(Evidence::HttpResponse {
                        status: 200, headers: vec![],
                        body_excerpt: Some(body.chars().take(400).collect::<String>().into()),
                    })
                    .tag("graphql").tag("exposure").tag("waf-bypass"), &mut findings);
            }
        }
    }

    // ── 3. Fragment bypass ───────────────────────────────────────────────────
    if findings.iter().any(|f| f.title().contains("introspection")) {
        // skip
    } else if let Ok(r) = client
        .post(&ep)
        .header("content-type", "application/json")
        .body(INTROSPECTION_FRAGMENT)
        .send()
        .await
    {
        if r.status().as_u16() == 200 {
            let body = capped_text(r, crate::MAX_BODY_BYTES).await.unwrap_or_default();
            if body.contains("__schema") || body.contains("queryType") {
                gossan_core::try_push_finding(crate::vulnerability_finding(target, Severity::High,
                        "GraphQL introspection bypassed via fragment spreading",
                        format!("{} blocked field-name blacklists but accepted introspection via inline fragment. \
                                 Fragments evade naive string-matching defences.", ep))
                    .evidence(Evidence::HttpResponse {
                        status: 200, headers: vec![],
                        body_excerpt: Some(body.chars().take(400).collect::<String>().into()),
                    })
                    .tag("graphql").tag("exposure").tag("waf-bypass"), &mut findings);
            }
        }
    }

    // ── 4. __type targeted introspection ─────────────────────────────────────
    if findings.iter().any(|f| f.title().contains("introspection")) {
        // skip
    } else if let Ok(r) = client
        .post(&ep)
        .header("content-type", "application/json")
        .body(INTROSPECTION_TYPE)
        .send()
        .await
    {
        if r.status().as_u16() == 200 {
            let body = capped_text(r, crate::MAX_BODY_BYTES).await.unwrap_or_default();
            if body.contains("__type") && body.contains("fields") {
                gossan_core::try_push_finding(crate::vulnerability_finding(target, Severity::Medium,
                        "GraphQL __type introspection enabled — partial schema disclosure",
                        format!("{} allows __type(name:) queries even when full __schema introspection is disabled. \
                                 Attackers can still enumerate the schema field-by-field.", ep))
                    .evidence(Evidence::HttpResponse {
                        status: 200, headers: vec![],
                        body_excerpt: Some(body.chars().take(400).collect::<String>().into()),
                    })
                    .tag("graphql").tag("exposure"), &mut findings);
            }
        }
    }

    // ── 5. Field suggestion leakage ──────────────────────────────────────────
    if let Ok(r) = client
        .post(&ep)
        .header("content-type", "application/json")
        .body(FIELD_PROBE)
        .send()
        .await
    {
        let body = capped_text(r, crate::MAX_BODY_BYTES).await.unwrap_or_default();
        if body.contains("Did you mean") || body.contains("did you mean") {
            let suggestion = body
                .lines()
                .find(|l| l.contains("Did you mean") || l.contains("did you mean"))
                .map(|l| l.trim().to_string())
                .unwrap_or_default();

            gossan_core::try_push_finding(crate::vulnerability_finding(target, Severity::Medium,
                    "GraphQL field suggestion leakage (introspection bypass)",
                    format!("{} leaks field names via error suggestions even with introspection disabled. \
                             Attackers can enumerate all field names by fuzzing typos. Suggestion: \"{}\"",
                             ep, suggestion))
                .evidence(Evidence::HttpResponse {
                    status: 200, headers: vec![],
                    body_excerpt: Some(body.chars().take(300).collect::<String>().into()),
                })
                .tag("graphql").tag("exposure")
                .exploit_hint(format!(
                    "# Enumerate fields via suggestions (clairvoyance):\n\
                     python3 -m clairvoyance {} -o schema.json", ep)), &mut findings);
        }
    }

    // ── 6. Batch / rate-limit bypass ─────────────────────────────────────────
    if let Ok(r) = client
        .post(&ep)
        .header("content-type", "application/json")
        .body(BATCH)
        .send()
        .await
    {
        if r.status().as_u16() == 200 {
            let body = capped_text(r, crate::MAX_BODY_BYTES).await.unwrap_or_default();
            if body.trim_start().starts_with('[') {
                gossan_core::try_push_finding(crate::vulnerability_finding(
                        target,
                        Severity::Medium,
                        "GraphQL query batching enabled — rate-limit bypass",
                        format!(
                            "{} accepts batched query arrays. Attackers send N operations in \
                                 one HTTP request, bypassing per-request rate limits. Useful for \
                                 credential stuffing and brute force through GraphQL mutations.",
                            ep
                        ),
                    )
                    .evidence(Evidence::HttpResponse {
                        status: 200,
                        headers: vec![],
                        body_excerpt: Some(body.chars().take(200).collect::<String>().into()),
                    })
                    .tag("graphql")
                    .tag("rate-limit-bypass")
                    .tag("dos")
                    .exploit_hint(format!(
                        "# Batch 100 login mutations in one request:\n\
                         python3 graphql-cop.py -t {} --test BATCH_LIMIT",
                        ep
                    )), &mut findings);
            }
        }
    }

    // ── 7. Alias amplification ────────────────────────────────────────────────
    if let Ok(r) = client
        .post(&ep)
        .header("content-type", "application/json")
        .body(ALIAS_AMP)
        .send()
        .await
    {
        if r.status().as_u16() == 200 {
            let body = capped_text(r, crate::MAX_BODY_BYTES).await.unwrap_or_default();
            let hits = body.matches("__typename").count();
            if hits >= 15 {
                gossan_core::try_push_finding(crate::vulnerability_finding(target, Severity::Low,
                        "GraphQL alias amplification — no query cost limit",
                        format!("{} responded to 20 aliased resolvers without query cost analysis. \
                                 Deeply nested aliases can amplify server load exponentially (ReDoS-like).", ep))
                    .evidence(Evidence::HttpResponse {
                        status: 200, headers: vec![],
                        body_excerpt: Some(format!("Received {} resolver responses for 20 aliased fields", hits).into()),
                    })
                    .tag("graphql").tag("dos"), &mut findings);
            }
        }
    }

    Ok(findings)
}

async fn capped_text(resp: reqwest::Response, limit: usize) -> Option<String> {
    if let Some(cl) = resp.content_length() {
        if cl > limit as u64 {
            return None;
        }
    }
    match gossan_core::net::bounded_text(resp, limit).await {
        Ok(t) => {
            if t.len() > limit {
                None
            } else {
                Some(t)
            }
        }
        Err(_) => Some(String::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn introspection_payloads_are_valid_json() {
        assert!(serde_json::from_str::<serde_json::Value>(INTROSPECTION).is_ok());
        assert!(serde_json::from_str::<serde_json::Value>(INTROSPECTION_ALIAS).is_ok());
        assert!(serde_json::from_str::<serde_json::Value>(INTROSPECTION_FRAGMENT).is_ok());
        assert!(serde_json::from_str::<serde_json::Value>(INTROSPECTION_TYPE).is_ok());
    }

    #[test]
    fn batch_payload_is_json_array() {
        let v: serde_json::Value = serde_json::from_str(BATCH).unwrap();
        assert!(v.is_array());
        assert_eq!(v.as_array().unwrap().len(), 10);
    }

    #[test]
    fn alias_amp_contains_twenty_aliases() {
        assert!(ALIAS_AMP.matches("__typename").count() >= 20);
    }
}
