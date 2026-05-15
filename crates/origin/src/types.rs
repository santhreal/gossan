//! Origin discovery data types — candidate origins and evidence.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Validation state of an origin candidate.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum ValidationState {
    /// Candidate was discovered but not actively confirmed.
    Speculative,
    /// Candidate confirmed by host-header swap or 404 divergence.
    Confirmed,
    /// Candidate ruled out by validation (generic default page, no match).
    Rejected,
}

/// Represents an origin server discovered behind a CDN/WAF.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct OriginCandidate {
    /// IP address of the candidate origin server
    pub ip: IpAddr,
    /// Optional explicit port. `None` means the validator falls back to
    /// the scheme default (443 then 80). Set this when a discovery
    /// source already knows the listening port (e.g. a Censys hit on
    /// 8443 or a wiremock harness binding to an ephemeral port). An
    /// explicit port is also taken as the operator's signal that they
    /// _intend_ to probe non-routable IPs (loopback/private), so the
    /// global-routability gate in the validator is bypassed when this
    /// field is `Some`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// Discovery technique (e.g., "ssl_cert", "dns_misconfig")
    pub method: String,
    /// Confidence score (0-100)
    pub confidence: u8,
    /// Active validation result
    pub validated: ValidationState,
}

impl OriginCandidate {
    /// Create a new speculative candidate.
    pub fn new(ip: IpAddr, method: impl Into<String>, confidence: u8) -> Self {
        Self {
            ip,
            port: None,
            method: method.into(),
            confidence,
            validated: ValidationState::Speculative,
        }
    }

    /// Create a new speculative candidate at an explicit port. Use this
    /// from test harnesses (wiremock binds to an ephemeral port) and
    /// from discovery sources that already know the listener (Censys,
    /// Shodan, AXFR-derived A records on non-default ports).
    pub fn new_with_port(ip: IpAddr, port: u16, method: impl Into<String>, confidence: u8) -> Self {
        Self {
            ip,
            port: Some(port),
            method: method.into(),
            confidence,
            validated: ValidationState::Speculative,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn origin_candidate_orders_by_fields() {
        let low = OriginCandidate {
            ip: "192.0.2.1".parse().unwrap(),
            port: None,
            method: "dns".into(),
            confidence: 20,
            validated: ValidationState::Speculative,
        };
        let high = OriginCandidate {
            ip: "192.0.2.2".parse().unwrap(),
            port: None,
            method: "ssl".into(),
            confidence: 90,
            validated: ValidationState::Confirmed,
        };
        assert!(high > low);
    }

    #[test]
    fn origin_candidate_serializes_cleanly() {
        let candidate = OriginCandidate::new("192.0.2.10".parse().unwrap(), "http_header", 75);
        let value = serde_json::to_value(candidate).unwrap();
        assert_eq!(value["ip"], json!("192.0.2.10"));
        assert_eq!(value["method"], json!("http_header"));
        assert_eq!(value["confidence"], json!(75));
        assert_eq!(value["validated"], json!("Speculative"));
    }
}
