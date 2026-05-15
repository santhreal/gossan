//! Bridge between the standalone `truestack` crate and panoram's internal types.
//!
//! Converts `truestack::Technology` → `gossan_core::Technology` and
//! `truestack::HeaderFinding` → `secfinding::Finding`.

use gossan_core::{ServiceTarget, Target, TechCategory, Technology, WebAssetTarget};
use secfinding::Finding;

/// Cap response body text to a safe maximum (2 MB).
async fn bounded_text(resp: reqwest::Response, limit: usize) -> anyhow::Result<String> {
    let mut buf = Vec::with_capacity(limit.min(4096));
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = futures::StreamExt::next(&mut stream).await {
        let chunk = chunk?;
        let remaining = limit.saturating_sub(buf.len());
        if remaining == 0 {
            break;
        }
        let take = chunk.len().min(remaining);
        buf.extend_from_slice(&chunk[..take]);
    }
    Ok(String::from_utf8_lossy(&buf).to_string())
}

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
        .map(|(k, v)| {
            (
                k.to_string(),
                String::from_utf8_lossy(v.as_bytes()).to_string(),
            )
        })
        .collect();

    let body = bounded_text(resp, 2 * 1024 * 1024).await.unwrap_or_default();
    let title = truestack::html::extract_title(&body);

    // ── Technology detection via truestack ────────────────────────────────
    let mut ts_techs = truestack::fingerprints::detect(&headers, &body);

    // Behavioral probing
    truestack::behavior::identify(client, base.as_str(), &mut ts_techs)
        .await
        .ok();

    // Post-process: excludes, requires, dedup, implied. truestack's
    // `postprocess::apply` takes ownership of the Vec and returns the
    // pruned/expanded set.
    let rules = &truestack::fingerprints::RuleEngine::embedded().rules;
    let mut ts_techs = truestack::postprocess::apply(ts_techs, rules);

    // Version intel confidence adjustment
    truestack::version_intel::assess(&mut ts_techs, &headers);

    let tech: Vec<Technology> = ts_techs.into_iter().map(convert_technology).collect();

    // ── Body hash — first 8 bytes of SHA-256, hex-encoded ────────────────
    let body_hash = {
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(body.as_bytes());
        Some(hex::encode(&hash[..8]))
    };

    // ── Favicon hash — async, best-effort ────────────────────────────────
    let favicon_hash =
        truestack::favicon::fetch_hash_limited(client, base.as_str(), 5 * 1024 * 1024).await;

    // ── Security header audit via truestack ───────────────────────────────
    // Rebuild each truestack-emitted Finding through secfinding's builder so
    // the scanner name and target are stamped as panoram-side metadata
    // (truestack doesn't know it's running under panoram). Finding's fields
    // are immutable through accessors — the builder is the only way to
    // re-stamp them.
    let ts_findings = truestack::security_headers::audit(&headers);
    let web_target = Target::Service(svc.clone());
    let panoram_target = web_target.domain().unwrap_or("?").to_string();
    let header_findings: Vec<Finding> = ts_findings
        .into_iter()
        .filter_map(|f| {
            let mut builder = Finding::builder("techstack", panoram_target.clone(), f.severity())
                .title(f.title().to_string())
                .detail(f.detail().to_string())
                .kind(f.kind());
            for ev in f.evidence() {
                builder = builder.evidence(ev.clone());
            }
            for tag in f.tags() {
                builder = builder.tag(tag.to_string());
            }
            for cve in f.cve_ids() {
                builder = builder.cve(cve.to_string());
            }
            if let Some(hint) = f.exploit_hint() {
                builder = builder.exploit_hint(hint.to_string());
            }
            builder.build().ok()
        })
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

#[cfg(test)]
mod tests {
    use super::*;

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
