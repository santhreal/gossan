use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Represents an origin server discovered behind a CDN/WAF.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct OriginCandidate {
    /// IP address of the candidate origin server
    pub ip: IpAddr,
    /// Discovery technique (e.g., "ssl_cert", "dns_misconfig")
    pub method: String,
    /// Confidence score (0-100)
    pub confidence: u8,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn origin_candidate_orders_by_fields() {
        let low = OriginCandidate {
            ip: "192.0.2.1".parse().unwrap(),
            method: "dns".into(),
            confidence: 20,
        };
        let high = OriginCandidate {
            ip: "192.0.2.2".parse().unwrap(),
            method: "ssl".into(),
            confidence: 90,
        };
        assert!(high > low);
    }

    #[test]
    fn origin_candidate_serializes_cleanly() {
        let candidate = OriginCandidate {
            ip: "192.0.2.10".parse().unwrap(),
            method: "http_header".into(),
            confidence: 75,
        };
        let value = serde_json::to_value(candidate).unwrap();
        assert_eq!(value["ip"], json!("192.0.2.10"));
        assert_eq!(value["method"], json!("http_header"));
        assert_eq!(value["confidence"], json!(75));
    }
}
