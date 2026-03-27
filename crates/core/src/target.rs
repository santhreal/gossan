//! Target types for the Gossan scanning pipeline.
//!
//! Targets flow through the pipeline as a tagged enum ([`Target`]), with each
//! scanner stage consuming one variant and emitting the next. The progression
//! is: `Domain → Host → Service → Web`.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use url::Url;

/// How a target was discovered — preserved for auditing and deduplication.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum DiscoverySource {
    Seed,
    CertificateTransparency,
    DnsBruteforce,
    PassiveDns,
    PortScan,
    TechStack,
    JsAnalysis,
    HiddenProbe,
    /// From authenticated crawling (link following, form discovery).
    Crawl,
    // Passive sources (no API key required)
    RapidDns,
    AlienVault,
    UrlScan,
    CommonCrawl,
    // Passive sources (API key required)
    VirusTotal,
    SecurityTrails,
    Shodan,
    GitHub,
}

/// A discovered domain — the entry point for most scans.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainTarget {
    /// Fully qualified domain name (e.g. `api.example.com`).
    pub domain: String,
    /// How this domain was discovered.
    pub source: DiscoverySource,
}

/// A resolved host — an IP address with an optional reverse-DNS domain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostTarget {
    /// Resolved IP address (v4 or v6).
    pub ip: IpAddr,
    /// Associated domain, if known.
    pub domain: Option<String>,
}

/// Transport layer protocol.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    /// Transmission Control Protocol.
    Tcp,
    /// User Datagram Protocol.
    Udp,
}

/// A network service discovered on a host — port, protocol, optional banner.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceTarget {
    /// The host this service runs on.
    pub host: HostTarget,
    /// TCP/UDP port number.
    pub port: u16,
    /// Transport protocol.
    pub protocol: Protocol,
    /// Raw banner grabbed from the service (first ~1 KB).
    pub banner: Option<String>,
    /// Whether the service speaks TLS.
    pub tls: bool,
}

impl ServiceTarget {
    /// Returns `true` if this service is likely HTTP/HTTPS based on port or banner.
    pub fn is_web(&self) -> bool {
        matches!(self.port, 80 | 443 | 8080 | 8443 | 8000 | 8888)
            || self
                .banner
                .as_deref()
                .map(|b| b.starts_with("HTTP"))
                .unwrap_or(false)
    }

    /// Constructs the base URL for this service (e.g. `https://example.com:8443/`).
    ///
    /// Returns `None` if URL construction fails.
    pub fn base_url(&self) -> Option<Url> {
        let scheme = if self.tls || self.port == 443 || self.port == 8443 {
            "https"
        } else {
            "http"
        };
        let host = match &self.host.domain {
            Some(d) => d.clone(),
            None => self.host.ip.to_string(),
        };
        let port_str = match (scheme, self.port) {
            ("https", 443) | ("http", 80) => String::new(),
            _ => format!(":{}", self.port),
        };
        Url::parse(&format!("{}://{}{}", scheme, host, port_str)).ok()
    }
}

/// A detected technology fingerprint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Technology {
    pub name: String,
    pub version: Option<String>,
    pub category: TechCategory,
    /// 0–100 confidence score.
    pub confidence: u8,
}

/// Technology category for fingerprinting classification.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TechCategory {
    /// Content management system (WordPress, Drupal, etc.).
    Cms,
    /// Web framework (React, Angular, Rails, etc.).
    Framework,
    /// Programming language (PHP, Python, etc.).
    Language,
    /// Web server (Nginx, Apache, etc.).
    Server,
    /// Content delivery network (Cloudflare, Akamai, etc.).
    Cdn,
    /// Analytics and tracking (Google Analytics, Segment, etc.).
    Analytics,
    /// Security products (WAF, CAPTCHA, etc.).
    Security,
    /// Database engine (MySQL, PostgreSQL, Redis, etc.).
    Database,
    /// Operating system.
    Os,
    /// Unclassified technology.
    Other,
}

/// A confirmed HTTP(S) asset with resolved tech stack.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAssetTarget {
    pub url: Url,
    pub service: ServiceTarget,
    pub tech: Vec<Technology>,
    pub status: u16,
    pub title: Option<String>,
    /// Shodan-compatible MurmurHash3 of the favicon (i32 signed).
    /// Use this to pivot on Shodan: `http.favicon.hash:{value}`
    #[serde(skip_serializing_if = "Option::is_none")]
    pub favicon_hash: Option<i32>,
    /// HTTP response body hash (SHA-256 hex, first 16 bytes).
    /// Enables deduplication of identical pages across subdomains.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_hash: Option<String>,
    /// HTML forms discovered on this page (action URLs, methods, input fields).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub forms: Vec<DiscoveredForm>,
    /// Query/body parameters observed or brute-forced on this endpoint.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub params: Vec<DiscoveredParam>,
}

/// An HTML form discovered during crawling.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredForm {
    /// The form's action URL (absolute or relative).
    pub action: String,
    /// HTTP method (GET, POST, etc.).
    pub method: String,
    /// Input field names and types.
    pub inputs: Vec<(String, String)>,
}

/// A parameter discovered on an endpoint (query string, POST body, or brute-forced).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredParam {
    /// Parameter name.
    pub name: String,
    /// Where this parameter appears.
    pub location: ParamLocation,
    /// How it was discovered.
    pub source: ParamSource,
}

/// Where a parameter is sent.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParamLocation {
    /// In the URL query string.
    Query,
    /// In the POST body.
    Body,
    /// In a URL path segment.
    Path,
    /// In an HTTP header.
    Header,
}

/// How a parameter was discovered.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParamSource {
    /// Extracted from an HTML form.
    HtmlForm,
    /// Observed in a URL during crawling.
    UrlObserved,
    /// Discovered via brute-force probing.
    BruteForce,
    /// Extracted from an OpenAPI/Swagger spec.
    ApiSpec,
    /// Extracted from JavaScript source code.
    JsAnalysis,
}

/// The single input/output type flowing through the pipeline.
/// Every scanner consumes a Vec<Target> and emits Vec<Target> + Vec<Finding>.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Target {
    Domain(DomainTarget),
    Host(HostTarget),
    Service(ServiceTarget),
    Web(Box<WebAssetTarget>),
}

impl Target {
    /// Returns the domain name associated with this target, if any.
    pub fn domain(&self) -> Option<&str> {
        match self {
            Target::Domain(d) => Some(&d.domain),
            Target::Host(h) => h.domain.as_deref(),
            Target::Service(s) => s.host.domain.as_deref(),
            Target::Web(w) => w.url.host_str(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn host(domain: Option<&str>) -> HostTarget {
        HostTarget {
            ip: "203.0.113.10".parse().unwrap(),
            domain: domain.map(str::to_string),
        }
    }

    fn service(port: u16, tls: bool, banner: Option<&str>, domain: Option<&str>) -> ServiceTarget {
        ServiceTarget {
            host: host(domain),
            port,
            protocol: Protocol::Tcp,
            banner: banner.map(str::to_string),
            tls,
        }
    }

    #[test]
    fn service_is_web_for_common_ports() {
        for port in [80, 443, 8080, 8443, 8000, 8888] {
            assert!(
                service(port, false, None, Some("example.com")).is_web(),
                "port {port}"
            );
        }
    }

    #[test]
    fn service_is_web_for_http_banner_even_on_nonstandard_port() {
        assert!(service(12345, false, Some("HTTP/1.1 200 OK"), Some("example.com")).is_web());
    }

    #[test]
    fn service_is_not_web_for_non_http_ports_without_banner_hint() {
        assert!(!service(22, false, Some("SSH-2.0-OpenSSH_9.7"), Some("example.com")).is_web());
    }

    #[test]
    fn base_url_uses_https_for_tls_services() {
        let url = service(9443, true, None, Some("example.com"))
            .base_url()
            .unwrap();
        assert_eq!(url.as_str(), "https://example.com:9443/");
    }

    #[test]
    fn base_url_uses_https_for_implicit_tls_ports() {
        let url = service(8443, false, None, Some("example.com"))
            .base_url()
            .unwrap();
        assert_eq!(url.as_str(), "https://example.com:8443/");
    }

    #[test]
    fn base_url_omits_default_ports() {
        assert_eq!(
            service(80, false, None, Some("example.com"))
                .base_url()
                .unwrap()
                .as_str(),
            "http://example.com/"
        );
        assert_eq!(
            service(443, false, None, Some("example.com"))
                .base_url()
                .unwrap()
                .as_str(),
            "https://example.com/"
        );
    }

    #[test]
    fn base_url_falls_back_to_ip_when_domain_missing() {
        let url = service(8080, false, None, None).base_url().unwrap();
        assert_eq!(url.as_str(), "http://203.0.113.10:8080/");
    }

    #[test]
    fn target_domain_returns_expected_value_for_each_variant() {
        let domain = Target::Domain(DomainTarget {
            domain: "example.com".into(),
            source: DiscoverySource::Seed,
        });
        let host = Target::Host(host(Some("host.example.com")));
        let svc = Target::Service(service(443, true, None, Some("svc.example.com")));
        let web = Target::Web(Box::new(WebAssetTarget {
            url: Url::parse("https://web.example.com/admin").unwrap(),
            service: service(443, true, None, Some("web.example.com")),
            tech: vec![],
            status: 200,
            title: Some("Admin".into()),
            favicon_hash: Some(123),
            body_hash: Some("abcd".into()),
            forms: vec![],
            params: vec![],
        }));

        assert_eq!(domain.domain(), Some("example.com"));
        assert_eq!(host.domain(), Some("host.example.com"));
        assert_eq!(svc.domain(), Some("svc.example.com"));
        assert_eq!(web.domain(), Some("web.example.com"));
    }

    #[test]
    fn target_domain_is_none_for_host_and_service_without_domain() {
        assert_eq!(Target::Host(host(None)).domain(), None);
        assert_eq!(
            Target::Service(service(22, false, None, None)).domain(),
            None
        );
    }

    #[test]
    fn protocol_serializes_lowercase() {
        assert_eq!(serde_json::to_value(Protocol::Tcp).unwrap(), json!("tcp"));
        assert_eq!(serde_json::to_value(Protocol::Udp).unwrap(), json!("udp"));
    }

    #[test]
    fn discovery_source_serializes_snake_case() {
        assert_eq!(
            serde_json::to_value(DiscoverySource::CertificateTransparency).unwrap(),
            json!("certificate_transparency")
        );
        assert_eq!(
            serde_json::to_value(DiscoverySource::HiddenProbe).unwrap(),
            json!("hidden_probe")
        );
    }

    #[test]
    fn target_serializes_with_kind_tag() {
        let target = Target::Domain(DomainTarget {
            domain: "example.com".into(),
            source: DiscoverySource::UrlScan,
        });
        let value = serde_json::to_value(target).unwrap();
        assert_eq!(value["kind"], json!("domain"));
        assert_eq!(value["source"], json!("url_scan"));
    }
}
