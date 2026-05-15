//! Wildcard DNS detection.

use hickory_resolver::TokioAsyncResolver;
use hickory_resolver::proto::rr::RecordType;
use std::collections::HashSet;
use std::net::IpAddr;

/// Probe a domain for wildcard DNS records.
///
/// Sends `probes` random labels and collects all returned IPs (including via CNAME chains).
/// If the returned set is non-empty, the domain likely has a wildcard record.
pub async fn detect_wildcards(
    domain: &str,
    resolver: &TokioAsyncResolver,
    probes: usize,
) -> HashSet<IpAddr> {
    let mut ips = HashSet::new();
    for _ in 0..probes {
        let probe = format!("gossan-wildcard-{}.{domain}", fastrand::u32(..));

        // Direct A-record lookup
        if let Ok(lookup) = resolver.lookup_ip(&probe).await {
            for ip in lookup.iter() {
                ips.insert(ip);
            }
        }

        // Explicit CNAME chain
        if let Ok(cname_lookup) = resolver.lookup(&probe, RecordType::CNAME).await {
            for record in cname_lookup.record_iter() {
                if let Some(rdata) = record.data() {
                    if let Some(cname_rdata) = rdata.as_cname() {
                        let cname = cname_rdata.0.to_utf8().trim_end_matches('.').to_string();
                        if let Ok(ip_lookup) = resolver.lookup_ip(&cname).await {
                            for ip in ip_lookup.iter() {
                                ips.insert(ip);
                            }
                        }
                    }
                }
            }
        }
    }
    ips
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_resolver::config::{ResolverConfig, ResolverOpts};
    use hickory_resolver::TokioAsyncResolver;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use tokio::net::UdpSocket;
    use tokio::task::JoinHandle;

    /// Minimal UDP DNS responder that returns `1.2.3.4` for any A query.
    async fn mock_dns_server(bind: SocketAddr) -> JoinHandle<()> {
        let socket = Arc::new(UdpSocket::bind(bind).await.unwrap());
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
                // QR=1, RA=1, RCODE=0
                resp[2] = 0x81;
                resp[3] = 0x80;
                // QDCOUNT stays same
                // ANCOUNT = 1
                resp[6] = 0x00;
                resp[7] = 0x01;
                // NSCOUNT = 0, ARCOUNT = 0 (already 0)

                // Find end of question labels
                let mut i = 12usize;
                while i < len && buf[i] != 0 {
                    i += 1 + buf[i] as usize;
                }
                i += 5; // null + QTYPE(2) + QCLASS(2)

                // Answer: pointer to name at offset 12 (0xC0 0x0C)
                resp.push(0xC0);
                resp.push(0x0C);
                // TYPE A
                resp.push(0x00);
                resp.push(0x01);
                // CLASS IN
                resp.push(0x00);
                resp.push(0x01);
                // TTL
                resp.extend_from_slice(&300u32.to_be_bytes());
                // RDLENGTH 4
                resp.push(0x00);
                resp.push(0x04);
                // RDATA
                resp.extend_from_slice(&Ipv4Addr::new(1, 2, 3, 4).octets());

                let _ = socket.send_to(&resp, peer).await;
            }
        })
    }

    fn resolver_for(addr: SocketAddr) -> TokioAsyncResolver {
        // hickory-resolver 0.24's `add_name_server` takes a
        // `NameServerConfig` (struct), not a `SocketAddr` — and the
        // struct is `#[non_exhaustive]` so we need the `::new`
        // constructor instead of struct-literal syntax. UDP is the
        // right protocol for this mock loopback DNS responder.
        let mut config = ResolverConfig::new();
        config.add_name_server(hickory_resolver::config::NameServerConfig::new(
            addr,
            hickory_resolver::config::Protocol::Udp,
        ));
        // ResolverOpts is `#[non_exhaustive]` in hickory-resolver
        // 0.24; struct-update syntax does not compile across crate
        // boundaries on non-exhaustive structs. Default + per-field
        // assignment is the supported construction path.
        let mut opts = ResolverOpts::default();
        // short timeout so tests fail fast if server is down
        opts.timeout = std::time::Duration::from_secs(2);
        opts.attempts = 1;
        TokioAsyncResolver::tokio(config, opts)
    }

    #[tokio::test]
    async fn wildcard_detects_mock_wildcard() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let handle = mock_dns_server(addr).await;
        // Need actual bound port
        let bound = handle.abort_handle();
        // Re-bind to get the port
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let actual_addr = socket.local_addr().unwrap();
        drop(socket);

        // Start server on known port
        let server = mock_dns_server(actual_addr).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let resolver = resolver_for(actual_addr);
        let ips = detect_wildcards("example.com", &resolver, 3).await;
        server.abort();

        assert!(ips.contains(&IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))));
    }
}
