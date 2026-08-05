//! WHOIS/RDAP-based ownership correlation for sibling domain discovery.
//!
//! Previously this module treated reverse-IP hosting as an ownership
//! signal, which false-positives on shared hosting. Ownership is now
//! derived from WHOIS/RDAP registrant attributes only.

use anyhow::Context;
use gossan_core::reqwest::{Client, Url};
use std::collections::HashMap;

/// Ownership attributes extracted from WHOIS or RDAP.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OwnershipAttrs {
    pub organization: Option<String>,
    pub email: Option<String>,
    pub registrant: Option<String>,
}

impl OwnershipAttrs {
    /// Stable correlation key used to group domains that share ownership.
    pub fn correlation_key(&self) -> Option<String> {
        if let Some(email) = self.email.as_ref().map(|e| e.trim().to_lowercase()) {
            if !email.is_empty() && email.contains('@') {
                return Some(format!("email:{email}"));
            }
        }
        if let Some(org) = self.organization.as_ref().map(|o| normalize_org(o)) {
            if !org.is_empty() && !is_weak_org(&org) {
                return Some(format!("org:{org}"));
            }
        }
        if let Some(name) = self.registrant.as_ref().map(|n| normalize_org(n)) {
            if !name.is_empty() && !is_weak_org(&name) {
                return Some(format!("registrant:{name}"));
            }
        }
        None
    }

    pub fn is_empty(&self) -> bool {
        self.organization.is_none() && self.email.is_none() && self.registrant.is_none()
    }
}

fn normalize_org(value: &str) -> String {
    value
        .trim()
        .to_lowercase()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || c.is_whitespace())
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn is_weak_org(org: &str) -> bool {
    matches!(
        org,
        "n/a"
            | "na"
            | "none"
            | "not applicable"
            | "redacted for privacy"
            | "privacy protected"
            | "data protected"
            | "withheld for privacy"
            | "domains by proxy"
            | "whois privacy"
            | "privacygodaddycom"
            | "contact privacy inc"
    ) || org.contains("privacy")
        || org.contains("redacted")
        || org.contains("proxy")
}

/// Discovers sibling root domains sharing WHOIS/RDAP ownership attributes.
///
/// Without a reverse-WHOIS index this returns an empty list for a lone
/// domain; callers that already hold a candidate set should use
/// [`group_siblings_by_ownership`].
pub async fn get_sibling_domains(client: &Client, domain: &str) -> anyhow::Result<Vec<String>> {
    get_sibling_domains_with_base(client, domain, "https://api.hackertarget.com").await
}

pub async fn get_sibling_domains_with_base(
    client: &Client,
    domain: &str,
    base: &str,
) -> anyhow::Result<Vec<String>> {
    // Confirm ownership records exist (WHOIS), but never use reverse-IP hosting.
    let _attrs = fetch_ownership_attrs(client, domain, base).await?;
    Ok(Vec::new())
}

/// Fetch ownership attributes for `domain` via HackerTarget WHOIS, with RDAP fallback.
pub async fn fetch_ownership_attrs(
    client: &Client,
    domain: &str,
    base: &str,
) -> anyhow::Result<OwnershipAttrs> {
    let mut attrs = match fetch_whois_text(client, domain, base).await {
        Ok(whois) => parse_whois_ownership(&whois),
        Err(e) => {
            tracing::debug!(error = %e, domain, "whois ownership fetch failed; trying RDAP");
            OwnershipAttrs::default()
        }
    };
    if attrs.correlation_key().is_none() {
        match fetch_rdap_text(client, domain).await {
            Ok(rdap) => {
                let rdap_attrs = parse_rdap_ownership(&rdap);
                if attrs.organization.is_none() {
                    attrs.organization = rdap_attrs.organization;
                }
                if attrs.email.is_none() {
                    attrs.email = rdap_attrs.email;
                }
                if attrs.registrant.is_none() {
                    attrs.registrant = rdap_attrs.registrant;
                }
            }
            Err(e) => {
                // WHOIS empty/failed and RDAP failed: surface the error instead of
                // returning empty attrs that look like "no ownership".
                if attrs.is_empty() {
                    return Err(e).context(format!("ownership lookup failed for {domain}"));
                }
                tracing::debug!(error = %e, domain, "rdap ownership fetch failed");
            }
        }
    }
    Ok(attrs)
}

async fn fetch_whois_text(client: &Client, domain: &str, base: &str) -> anyhow::Result<String> {
    let mut url = Url::parse(&format!("{}/whois/", base.trim_end_matches('/')))?;
    url.query_pairs_mut().append_pair("q", domain);
    let r = client.get(url.as_str()).send().await?;
    Ok(gossan_core::net::bounded_text(r, crate::MAX_HORIZONTAL_TEXT_BYTES).await?)
}

async fn fetch_rdap_text(client: &Client, domain: &str) -> anyhow::Result<String> {
    let url = format!("https://rdap.org/domain/{}", domain.trim_end_matches('.'));
    let r = client.get(url).send().await?;
    Ok(gossan_core::net::bounded_text(r, crate::MAX_HORIZONTAL_TEXT_BYTES).await?)
}

/// Group candidate domains by shared WHOIS/RDAP ownership keys.
/// Returns a map of correlation-key → domains (excluding singleton groups).
pub async fn group_siblings_by_ownership(
    client: &Client,
    domains: &[String],
    base: &str,
) -> anyhow::Result<HashMap<String, Vec<String>>> {
    let mut by_key: HashMap<String, Vec<String>> = HashMap::new();
    for domain in domains {
        let attrs = match fetch_ownership_attrs(client, domain, base).await {
            Ok(attrs) => attrs,
            Err(e) => {
                tracing::warn!(error = %e, domain, "ownership attrs unavailable; skipping domain");
                continue;
            }
        };
        if let Some(key) = attrs.correlation_key() {
            by_key.entry(key).or_default().push(domain.clone());
        }
    }
    by_key.retain(|_, v| v.len() > 1);
    Ok(by_key)
}

/// Parse WHOIS text into ownership attributes.
pub fn parse_whois_ownership(resp: &str) -> OwnershipAttrs {
    let mut attrs = OwnershipAttrs::default();
    for raw in resp.lines() {
        let line = raw.trim();
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim().to_ascii_lowercase();
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        match key.as_str() {
            "orgname"
            | "organization"
            | "organisation"
            | "registrant organization"
            | "registrant organisation"
            | "owner"
            | "org" => {
                if attrs.organization.is_none() {
                    attrs.organization = Some(value.to_string());
                }
            }
            "registrant email"
            | "admin email"
            | "tech email"
            | "e-mail"
            | "email" => {
                if attrs.email.is_none() && value.contains('@') {
                    attrs.email = Some(value.to_string());
                }
            }
            "registrant name" | "registrant" | "name" => {
                if attrs.registrant.is_none() {
                    attrs.registrant = Some(value.to_string());
                }
            }
            _ => {}
        }
    }
    attrs
}

/// Best-effort RDAP JSON ownership extraction without a full schema dependency.
pub fn parse_rdap_ownership(resp: &str) -> OwnershipAttrs {
    // Prefer structured walk when JSON parses; fall back to keyword scan.
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(resp) {
        let mut attrs = OwnershipAttrs::default();
        extract_rdap_entities(&v, &mut attrs);
        if !attrs.is_empty() {
            return attrs;
        }
    }
    parse_whois_ownership(resp)
}

fn extract_rdap_entities(value: &serde_json::Value, attrs: &mut OwnershipAttrs) {
    match value {
        serde_json::Value::Object(map) => {
            if let Some(fn_) = map.get("fn").and_then(|v| v.as_str()) {
                if attrs.registrant.is_none() {
                    attrs.registrant = Some(fn_.to_string());
                }
            }
            if let Some(org) = map.get("org").and_then(|v| v.as_str()) {
                if attrs.organization.is_none() {
                    attrs.organization = Some(org.to_string());
                }
            }
            if let Some(email) = map.get("email").and_then(|v| v.as_str()) {
                if attrs.email.is_none() {
                    attrs.email = Some(email.to_string());
                }
            }
            // vcardArray: [ "vcard", [ ["fn", {}, "text", "Name"], ["email", ...], ... ] ]
            if let Some(vcard) = map.get("vcardArray").and_then(|v| v.as_array()) {
                if let Some(entries) = vcard.get(1).and_then(|v| v.as_array()) {
                    for entry in entries {
                        let Some(arr) = entry.as_array() else { continue };
                        let Some(kind) = arr.first().and_then(|v| v.as_str()) else { continue };
                        let Some(text) = arr.get(3).and_then(|v| v.as_str()) else { continue };
                        match kind {
                            "fn" if attrs.registrant.is_none() => {
                                attrs.registrant = Some(text.to_string());
                            }
                            "org" if attrs.organization.is_none() => {
                                attrs.organization = Some(text.to_string());
                            }
                            "email" if attrs.email.is_none() => {
                                attrs.email = Some(text.to_string());
                            }
                            _ => {}
                        }
                    }
                }
            }
            for child in map.values() {
                extract_rdap_entities(child, attrs);
            }
        }
        serde_json::Value::Array(items) => {
            for child in items {
                extract_rdap_entities(child, attrs);
            }
        }
        _ => {}
    }
}

/// Parse reverseiplookup response into domain list (kept for tests / callers).
pub fn parse_reverseip_response(resp: &str) -> Vec<String> {
    resp.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| l.trim().to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_whois_extracts_org_and_email() {
        let resp = "Domain Name: EXAMPLE.COM\nRegistrant Organization: Example Org LLC\nRegistrant Email: owner@example.com\n";
        let attrs = parse_whois_ownership(resp);
        assert_eq!(attrs.organization.as_deref(), Some("Example Org LLC"));
        assert_eq!(attrs.email.as_deref(), Some("owner@example.com"));
        assert!(attrs.correlation_key().unwrap().starts_with("email:"));
    }

    #[test]
    fn privacy_org_is_weak_and_ignored() {
        let resp = "Organization: REDACTED FOR PRIVACY\n";
        let attrs = parse_whois_ownership(resp);
        assert!(attrs.correlation_key().is_none());
    }

    #[test]
    fn parse_rdap_vcard_email() {
        let json = r#"{
          "entities": [{
            "vcardArray": ["vcard", [
              ["fn", {}, "text", "Alice"],
              ["email", {}, "text", "alice@example.com"]
            ]]
          }]
        }"#;
        let attrs = parse_rdap_ownership(json);
        assert_eq!(attrs.email.as_deref(), Some("alice@example.com"));
        assert_eq!(attrs.registrant.as_deref(), Some("Alice"));
    }

    #[test]
    fn parse_reverseip_handles_empty_and_lines() {
        let resp = "example.com\n\nsub.example.com\n ";
        let v = parse_reverseip_response(resp);
        assert_eq!(
            v,
            vec!["example.com".to_string(), "sub.example.com".to_string()]
        );

        let empty = "";
        let v2 = parse_reverseip_response(empty);
        assert!(v2.is_empty());
    }
}
