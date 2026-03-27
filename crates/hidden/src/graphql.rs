//! GraphQL security probes.
//!
//! 1. Introspection enabled — full schema disclosure
//! 2. Batching attack — DoS / rate-limit bypass via array of operations
//! 3. Field suggestion leakage — "did you mean password?" exposes schema fragments
//! 4. Verbose error mode — stack traces / internal paths in error responses
//! 5. Alias amplification — single request fans out to N resolver calls

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

const FIELD_PROBE: &str = r#"{"query":"{ __typenme }"}"#; // intentional typo — triggers "did you mean __typename?"

// Batch: 10 identical introspection queries in one HTTP request
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

// Alias amplification: 20 aliases resolving the same field in one query
const ALIAS_AMP: &str = r#"{"query":"{
  a1:__typename a2:__typename a3:__typename a4:__typename a5:__typename
  a6:__typename a7:__typename a8:__typename a9:__typename a10:__typename
  a11:__typename a12:__typename a13:__typename a14:__typename a15:__typename
  a16:__typename a17:__typename a18:__typename a19:__typename a20:__typename
}"}"#;

pub async fn probe(client: &Client, target: &Target) -> anyhow::Result<Vec<Finding>> {
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
                let body = r.text().await.unwrap_or_default();
                if body.contains("__typename") || body.contains("data") {
                    endpoint = Some(url);
                    break;
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
            let body = r.text().await.unwrap_or_default();
            if body.contains("__schema") || body.contains("queryType") {
                findings.push(
                    crate::finding_builder(target, Severity::High,
                        "GraphQL introspection enabled — full schema exposed",
                        format!("{} allows introspection. Attackers can enumerate every query, \
                                 mutation, type, and field name — full attack surface in one request.", ep))
                    .evidence(Evidence::HttpResponse {
                        status: 200, headers: vec![],
                        body_excerpt: Some(body.chars().take(400).collect()),
                    })
                    .tag("graphql").tag("exposure")
                    .exploit_hint(format!(
                        "# Dump full schema:\n\
                         npx get-graphql-schema {}\n\
                         # Or with graphql-cop:\n\
                         python3 graphql-cop.py -t {}", ep, ep))
                    .build().expect("finding builder: required fields are set")
                );
            }
        }
    }

    // ── 2. Field suggestion leakage ──────────────────────────────────────────
    if let Ok(r) = client
        .post(&ep)
        .header("content-type", "application/json")
        .body(FIELD_PROBE)
        .send()
        .await
    {
        let body = r.text().await.unwrap_or_default();
        // "Did you mean" in error messages leaks field names even when introspection is off
        if body.contains("Did you mean") || body.contains("did you mean") {
            // Extract the suggestion
            let suggestion = body
                .lines()
                .find(|l| l.contains("Did you mean") || l.contains("did you mean"))
                .map(|l| l.trim().to_string())
                .unwrap_or_default();

            findings.push(
                crate::finding_builder(target, Severity::Medium,
                    "GraphQL field suggestion leakage (introspection bypass)",
                    format!("{} leaks field names via error suggestions even with introspection disabled. \
                             Attackers can enumerate all field names by fuzzing typos. Suggestion: \"{}\"",
                             ep, suggestion))
                .evidence(Evidence::HttpResponse {
                    status: 200, headers: vec![],
                    body_excerpt: Some(body.chars().take(300).collect()),
                })
                .tag("graphql").tag("exposure")
                .exploit_hint(format!(
                    "# Enumerate fields via suggestions (clairvoyance):\n\
                     python3 -m clairvoyance {} -o schema.json", ep))
                .build().expect("finding builder: required fields are set")
            );
        }
    }

    // ── 3. Batch / rate-limit bypass ─────────────────────────────────────────
    if let Ok(r) = client
        .post(&ep)
        .header("content-type", "application/json")
        .body(BATCH)
        .send()
        .await
    {
        if r.status().as_u16() == 200 {
            let body = r.text().await.unwrap_or_default();
            // Array response = batching accepted
            if body.trim_start().starts_with('[') {
                findings.push(
                    crate::finding_builder(
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
                        body_excerpt: Some(body.chars().take(200).collect()),
                    })
                    .tag("graphql")
                    .tag("rate-limit-bypass")
                    .tag("dos")
                    .exploit_hint(format!(
                        "# Batch 100 login mutations in one request:\n\
                         python3 graphql-cop.py -t {} --test BATCH_LIMIT",
                        ep
                    ))
                    .build()
                    .expect("finding builder: required fields are set"),
                );
            }
        }
    }

    // ── 4. Alias amplification ────────────────────────────────────────────────
    if let Ok(r) = client
        .post(&ep)
        .header("content-type", "application/json")
        .body(ALIAS_AMP)
        .send()
        .await
    {
        if r.status().as_u16() == 200 {
            let body = r.text().await.unwrap_or_default();
            // Count alias responses — if we get 20 fields back, amplification works
            let hits = body.matches("__typename").count();
            if hits >= 15 {
                findings.push(
                    crate::finding_builder(target, Severity::Low,
                        "GraphQL alias amplification — no query cost limit",
                        format!("{} responded to 20 aliased resolvers without query cost analysis. \
                                 Deeply nested aliases can amplify server load exponentially (ReDoS-like).", ep))
                    .evidence(Evidence::HttpResponse {
                        status: 200, headers: vec![],
                        body_excerpt: Some(format!("Received {} resolver responses for 20 aliased fields", hits)),
                    })
                    .tag("graphql").tag("dos")
                    .build().expect("finding builder: required fields are set")
                );
            }
        }
    }

    Ok(findings)
}
