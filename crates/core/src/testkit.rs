//! Shared test scaffolding. `#[doc(hidden)]`  -  not part of the public
//! API, exists only so integration tests across scanner crates stop
//! copy-pasting the same `web_target` constructor (it was duplicated
//! verbatim in 9 test files).

use crate::{HostTarget, Protocol, ServiceTarget, Target, WebAssetTarget};
use std::net::{IpAddr, Ipv4Addr};

/// A minimal `Target::Web` pointing at `url`, loopback host, port 80,
/// no TLS  -  the exact fixture the hidden/techstack integration tests
/// all hand-rolled.
///
/// Panics on an unparseable URL: callers pass literals / mock-server
/// URIs, so a parse failure is a test bug that should fail loudly.
/// `expect_used` is explicitly allowed here because this is test
/// scaffolding (the crate otherwise denies it in non-test code).
#[must_use]
#[allow(clippy::expect_used)]
pub fn web_target(url: &str) -> Target {
    Target::Web(Box::new(WebAssetTarget {
        url: url::Url::parse(url).expect("test web_target: invalid URL"),
        service: ServiceTarget {
            host: HostTarget {
                ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                domain: Some("example.com".to_string()),
            },
            port: 80,
            protocol: Protocol::Tcp,
            banner: None,
            tls: false,
        },
        tech: vec![],
        status: 200,
        title: None,
        favicon_hash: None,
        body_hash: None,
        forms: vec![],
        params: vec![],
    }))
}
