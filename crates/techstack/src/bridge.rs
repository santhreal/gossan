//! Bridge between the standalone `truestack` crate and panoram's internal types.
//!
//! Converts `truestack::Technology` → `gossan_core::Technology` and
//! `truestack::HeaderFinding` → `secfinding::Finding`.

use gossan_core::{ServiceTarget, Target, TechCategory, Technology, WebAssetTarget};
use secfinding::{Evidence, Finding, Severity};

/// Probe a single web service target and return a [`WebAssetTarget`] plus any
/// security-header findings.
pub async fn probe(
    client: &reqwest::Client,
    svc: ServiceTarget,
) -> anyhow::Result<(WebAssetTarget, Vec<Finding>)> {
    let base = svc
        .base_url()
        .ok_or_else(|| anyhow::anyhow!("no base url"))?;
    let resp = client.get(base.as_str()).send().await?;

    let status = resp.status().as_u16();
    let headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();

    let body = resp.text().await.unwrap_or_default();
    let title = truestack::html::extract_title(&body);

    // ── Technology detection via truestack ────────────────────────────────
    let ts_techs = truestack::fingerprints::detect(&headers, &body);
    let tech: Vec<Technology> = ts_techs.into_iter().map(convert_technology).collect();

    // ── Body hash — first 8 bytes of SHA-256, hex-encoded ────────────────
    let body_hash = {
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(body.as_bytes());
        Some(hex::encode(&hash[..8]))
    };

    // ── Favicon hash — async, best-effort ────────────────────────────────
    let favicon_hash = truestack::favicon::fetch_hash(client, base.as_str()).await;

    // ── Security header audit via truestack ───────────────────────────────
    let ts_findings = truestack::security_headers::audit(&headers);
    let web_target = Target::Service(svc.clone());
    let header_findings: Vec<Finding> = ts_findings
        .into_iter()
        .map(|f| convert_header_finding(f, &web_target))
        .collect();

    Ok((
        WebAssetTarget {
            url: base,
            service: svc,
            tech,
            status,
            title,
            favicon_hash,
            body_hash,
            forms: vec![],
            params: vec![],
        },
        header_findings,
    ))
}

/// Convert a `truestack::Technology` into `gossan_core::Technology`.
fn convert_technology(t: truestack::Technology) -> Technology {
    Technology {
        name: t.name,
        version: t.version,
        category: match t.category {
            truestack::TechCategory::Cms => TechCategory::Cms,
            truestack::TechCategory::Framework => TechCategory::Framework,
            truestack::TechCategory::Language => TechCategory::Language,
            truestack::TechCategory::Server => TechCategory::Server,
            truestack::TechCategory::Cdn => TechCategory::Cdn,
            truestack::TechCategory::Analytics => TechCategory::Analytics,
            truestack::TechCategory::Security => TechCategory::Security,
            truestack::TechCategory::Database => TechCategory::Database,
            truestack::TechCategory::Os => TechCategory::Os,
            truestack::TechCategory::Other => TechCategory::Other,
        },
        confidence: t.confidence,
    }
}

/// Convert a `truestack::HeaderFinding` into `secfinding::Finding`.
fn convert_header_finding(f: truestack::HeaderFinding, target: &Target) -> Finding {
    let mut finding = Finding::builder(
        "techstack",
        target.domain().unwrap_or("?"),
        convert_severity(f.severity),
    )
    .title(&f.title)
    .detail(&f.detail);
    for tag in &f.tags {
        finding = finding.tag(tag);
    }
    if let Some(ev) = f.evidence {
        if let Some((name, value)) = ev.header {
            finding = finding.evidence(Evidence::HttpResponse {
                status: 200,
                headers: vec![(name, value)],
                body_excerpt: ev.body_excerpt,
            });
        }
    }
    finding
        .build()
        .expect("finding builder: required fields are set")
}

/// Convert truestack severity to gossan severity.
fn convert_severity(s: truestack::Severity) -> Severity {
    match s {
        truestack::Severity::Info => Severity::Info,
        truestack::Severity::Low => Severity::Low,
        truestack::Severity::Medium => Severity::Medium,
        truestack::Severity::High => Severity::High,
        truestack::Severity::Critical => Severity::Critical,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn convert_severity_maps_all_variants() {
        assert_eq!(convert_severity(truestack::Severity::Info), Severity::Info);
        assert_eq!(convert_severity(truestack::Severity::Low), Severity::Low);
        assert_eq!(
            convert_severity(truestack::Severity::Medium),
            Severity::Medium
        );
        assert_eq!(convert_severity(truestack::Severity::High), Severity::High);
        assert_eq!(
            convert_severity(truestack::Severity::Critical),
            Severity::Critical
        );
    }

    #[test]
    fn convert_technology_preserves_name_version_and_confidence() {
        let tech = convert_technology(truestack::Technology {
            name: "nginx".into(),
            version: Some("1.25".into()),
            category: truestack::TechCategory::Server,
            confidence: 92,
        });
        assert_eq!(tech.name, "nginx");
        assert_eq!(tech.version.as_deref(), Some("1.25"));
        assert!(matches!(tech.category, TechCategory::Server));
        assert_eq!(tech.confidence, 92);
    }
}
