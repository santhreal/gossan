//! WAF fingerprinting — delegates to `wafrift-detect`.
//!
//! All signature logic, confidence scoring, and body analysis lives in the
//! standalone `wafrift-detect` crate. This module adapts its output into
//! `secfinding::Finding` for the gossan pipeline.

use gossan_core::Target;
use reqwest::Client;
use secfinding::{Evidence, Finding, Severity};

/// Probe a web target for WAF presence using `wafrift-detect`.
pub async fn probe(client: &Client, target: &Target) -> anyhow::Result<Vec<Finding>> {
    let Target::Web(asset) = target else {
        return Ok(vec![]);
    };
    let url = asset.url.as_str();

    let Ok(resp) = client.get(url).send().await else {
        return Ok(vec![]);
    };

    let status = resp.status().as_u16();
    let raw_headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();
    let headers: Vec<(std::sync::Arc<str>, std::sync::Arc<str>)> = raw_headers
        .iter()
        .map(|(k, v)| (
            std::sync::Arc::<str>::from(k.as_str()),
            std::sync::Arc::<str>::from(v.as_str()),
        ))
        .collect();

    let body = resp.bytes().await.unwrap_or_default();

    // wafrift_detect::detect now returns a Vec<DetectedWaf> (it can match
    // multiple WAFs simultaneously — e.g. a CloudFront-fronted Cloudflare
    // origin returns both). Pick the highest-confidence hit; bail if empty.
    let detected_all = wafrift_detect::detect(status, &raw_headers, &body);
    let Some(detected) = detected_all
        .into_iter()
        .max_by(|a, b| a.confidence.partial_cmp(&b.confidence).unwrap_or(std::cmp::Ordering::Equal))
    else {
        return Ok(vec![]);
    };

    let severity = if detected.confidence >= 0.8 {
        Severity::Info
    } else {
        Severity::Info
    };

    let detail = format!(
        "WAF detected: {} (confidence: {:.0}%). Indicators: {}. \
         This changes the attack approach — WAF evasion research required before active exploitation.",
        detected.name,
        detected.confidence * 100.0,
        detected.indicators.join(", "),
    );

    let mut findings = Vec::new();
    if let Some(finding) = crate::info_finding(target, severity,
        format!("WAF detected: {}", detected.name),
        detail)
    .evidence(Evidence::HttpResponse {
        status,
        headers: headers.clone(),
        body_excerpt: None,
    })
    .tag("waf")
    .tag("fingerprint")
    .build_or_log()
    {
        findings.push(finding);
    }

    Ok(findings)
}
