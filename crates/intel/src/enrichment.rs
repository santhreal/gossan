//! Typed enrichment contract for intelligence findings.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Version of the enrichment contract. Bump on breaking changes.
pub const ENRICHMENT_VERSION: u32 = 1;

/// Structured enrichment produced by an intel source.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IntelEnrichment {
    /// Contract version for forward compatibility.
    pub version: u32,
    /// Source name (e.g., "greynoise", "shodan").
    pub source: String,
    /// Target type: "ip", "domain", "url".
    pub target_type: String,
    /// Target value.
    pub target_value: String,
    /// Classification from the source (e.g., "malicious", "benign", "unknown").
    pub classification: Option<String>,
    /// ASN information.
    pub asn: Option<AsnInfo>,
    /// Geolocation.
    pub geo: Option<GeoInfo>,
    /// Open services / ports.
    pub services: Vec<ServiceInfo>,
    /// Technologies detected.
    pub technologies: Vec<String>,
    /// Passive DNS records.
    pub passive_dns: Vec<DnsRecord>,
    /// Tags / categories from the source.
    pub tags: Vec<String>,
    /// Raw metadata keyed by provider field name.
    pub raw: HashMap<String, serde_json::Value>,
    /// Unix timestamp when this enrichment was fetched.
    pub fetched_at: u64,
}

impl IntelEnrichment {
    /// Create a blank enrichment for a given target.
    pub fn new(
        source: impl Into<String>,
        target_type: impl Into<String>,
        target_value: impl Into<String>,
    ) -> Self {
        Self {
            version: ENRICHMENT_VERSION,
            source: source.into(),
            target_type: target_type.into(),
            target_value: target_value.into(),
            classification: None,
            asn: None,
            geo: None,
            services: Vec::new(),
            technologies: Vec::new(),
            passive_dns: Vec::new(),
            tags: Vec::new(),
            raw: HashMap::new(),
            fetched_at: now(),
        }
    }
}

/// ASN enrichment.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AsnInfo {
    pub asn: String,
    pub org: Option<String>,
    pub domain: Option<String>,
}

/// Geolocation enrichment.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GeoInfo {
    pub country: Option<String>,
    pub city: Option<String>,
    pub region: Option<String>,
}

/// Service detected on a target.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServiceInfo {
    pub port: u16,
    pub protocol: String,
    pub banner: Option<String>,
    pub product: Option<String>,
}

/// Passive DNS record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DnsRecord {
    pub record_type: String,
    pub value: String,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
