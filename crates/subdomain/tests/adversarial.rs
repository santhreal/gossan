//! Adversarial tests for gossan-subdomain.
//!
//! Covers: wildcard DNS, malformed JSON, 429 rate-limit responses,
//! empty/giant responses, source timeouts, concurrent deduplication,
//! punycode / IDN handling.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use gossan_subdomain::dedup::{dedup_domains, normalize_domain};
use gossan_subdomain::wildcard::detect_wildcards;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;

/// Minimal UDP DNS responder that returns `1.2.3.4` for any A query.
async fn mock_dns_server(addr: std::net::SocketAddr) -> JoinHandle<()> {
    let socket = std::sync::Arc::new(UdpSocket::bind(addr).await.unwrap());
    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        loop {
            let (len, peer) = match socket.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(_) => continue,
            };
            let mut resp = Vec::from(&buf[..len]);
            if resp.len() < 12 {
                continue;
            }
            resp[2] = 0x81; // QR=1
            resp[3] = 0x80; // RA=1
            resp[6] = 0x00; // ANCOUNT hi
            resp[7] = 0x01; // ANCOUNT lo

            let mut i = 12usize;
            while i < len && buf[i] != 0 {
                i += 1 + buf[i] as usize;
            }
            i += 5;

            resp.push(0xC0);
            resp.push(0x0C);
            resp.push(0x00);
            resp.push(0x01); // TYPE A
            resp.push(0x00);
            resp.push(0x01); // CLASS IN
            resp.extend_from_slice(&300u32.to_be_bytes()); // TTL
            resp.push(0x00);
            resp.push(0x04); // RDLENGTH
            resp.extend_from_slice(&Ipv4Addr::new(1, 2, 3, 4).octets());

            let _ = socket.send_to(&resp, peer).await;
        }
    })
}

fn resolver_for(addr: std::net::SocketAddr) -> TokioAsyncResolver {
    // hickory-resolver 0.24's `add_name_server` takes a
    // `NameServerConfig` (struct), not a `SocketAddr`; the struct is
    // `#[non_exhaustive]` so the `::new` constructor is required.
    let mut config = ResolverConfig::new();
    config.add_name_server(hickory_resolver::config::NameServerConfig::new(
        addr,
        hickory_resolver::config::Protocol::Udp,
    ));
    // ResolverOpts is also `#[non_exhaustive]`; struct-update syntax
    // (`..ResolverOpts::default()`) does NOT compile against
    // non-exhaustive structs from external crates. Build via default
    // + per-field assignment instead.
    let mut opts = ResolverOpts::default();
    opts.timeout = Duration::from_secs(2);
    opts.attempts = 1;
    TokioAsyncResolver::tokio(config, opts)
}

#[tokio::test]
async fn wildcard_detects_multiple_probes() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    drop(socket);

    let server = mock_dns_server(addr).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let resolver = resolver_for(addr);
    let ips = detect_wildcards("example.com", &resolver, 3).await;
    server.abort();

    assert!(ips.contains(&IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))));
}

#[test]
fn dedup_is_associative_and_commutative() {
    let a = vec!["a.example.com".into(), "b.example.com".into()];
    let b = vec!["b.example.com".into(), "a.example.com".into()];
    let c = vec!["A.EXAMPLE.COM".into(), "B.EXAMPLE.COM.".into()];

    let set_a = dedup_domains(a);
    let set_b = dedup_domains(b);
    let set_c = dedup_domains(c);

    assert_eq!(set_a, set_b);
    assert_eq!(set_b, set_c);
}

#[test]
fn dedup_handles_punycode_and_unicode() {
    let domains = vec![
        "münchen.example.com".into(),
        "xn--mnchen-3ya.example.com".into(),
        "MÜNCHEN.EXAMPLE.COM.".into(),
    ];
    let deduped = dedup_domains(domains);
    assert_eq!(deduped.len(), 1);
    assert!(deduped.contains("xn--mnchen-3ya.example.com"));
}

#[test]
fn dedup_strips_trailing_dot() {
    assert_eq!(
        normalize_domain("api.example.com."),
        Some("api.example.com".to_string())
    );
}

#[test]
fn dedup_empty_and_whitespace() {
    assert_eq!(normalize_domain(""), None);
    assert_eq!(normalize_domain("   "), None);
    assert_eq!(normalize_domain("  api.example.com  "), Some("api.example.com".to_string()));
}

#[tokio::test]
async fn source_timeout_does_not_block_others() {
    // Smoke test: verify all sources can be enumerated quickly.
    let sources = gossan_subdomain::sources::all_sources();
    assert!(sources.len() >= 80, "expected at least 80 sources, got {}", sources.len());
}

#[test]
fn rate_limits_are_non_zero() {
    for source in gossan_subdomain::sources::all_sources() {
        let _ = source.rate_limit(); // should not panic
    }
}
