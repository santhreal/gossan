//! Wildcard DNS detection.

use futures::future::join_all;
use hickory_resolver::TokioResolver;
use std::collections::HashSet;
use std::net::IpAddr;

/// Hard cap on total probe labels. Bounds DNS spend against pathological
/// round-robin pools while still covering typical CDN IP pools.
const MAX_WILDCARD_PROBES: usize = 64;

/// Consecutive empty-growth batches required before treating the IP set
/// as stable (covers rotating A pools larger than a single batch).
const STABLE_BATCHES: usize = 3;

/// Probe a domain for wildcard DNS records.
///
/// Sends batches of random labels concurrently via `lookup_ip` (which
/// follows CNAME chains). Keeps sampling until `STABLE_BATCHES`
/// consecutive batches add no new IPs, or `MAX_WILDCARD_PROBES` is hit.
/// If the returned set is non-empty, the domain likely has a wildcard.
pub async fn detect_wildcards(
    domain: &str,
    resolver: &TokioResolver,
    probes: usize,
) -> HashSet<IpAddr> {
    let batch_size = probes.max(1);
    let mut ips = HashSet::new();
    let mut total = 0usize;
    let mut stable = 0usize;

    while total < MAX_WILDCARD_PROBES && stable < STABLE_BATCHES {
        let n = batch_size.min(MAX_WILDCARD_PROBES - total);
        let futs = (0..n).map(|_| {
            let probe = format!("gossan-wildcard-{}.{domain}", fastrand::u32(..));
            async move {
                let mut found = HashSet::new();
                if let Ok(lookup) = resolver.lookup_ip(probe.as_str()).await {
                    for ip in lookup.iter() {
                        found.insert(ip);
                    }
                }
                found
            }
        });

        let results = join_all(futs).await;
        total += n;

        let mut grew = false;
        for set in results {
            for ip in set {
                if ips.insert(ip) {
                    grew = true;
                }
            }
        }

        if ips.is_empty() {
            // No answers at all → not a wildcard; stop early.
            break;
        }

        if grew {
            stable = 0;
        } else {
            stable += 1;
        }
    }

    ips
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_resolver::config::{ResolverConfig, ResolverOpts};
    use hickory_resolver::name_server::TokioConnectionProvider;
    use hickory_resolver::TokioResolver;
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
                    Err(e) => {
                        tracing::warn!("wildcard DNS mock recv_from failed: error={}", e);
                        continue;
                    }
                };
                let mut resp = Vec::from(&buf[..len]);
                if resp.len() < 12 {
                    continue;
                }
                // QR=1, RA=1, RCODE=0
                resp[2] = 0x81;
                resp[3] = 0x80;
                // ANCOUNT = 1
                resp[6] = 0x00;
                resp[7] = 0x01;

                // Find end of question labels
                let mut i = 12usize;
                while i < len && buf[i] != 0 {
                    i += 1 + buf[i] as usize;
                }
                i += 5; // null + QTYPE(2) + QCLASS(2)
                let _ = i;

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

    /// Rotating-pool wildcard: cycles through a fixed IP pool per reply.
    async fn mock_rotating_dns_server(bind: SocketAddr, pool: Vec<Ipv4Addr>) -> JoinHandle<()> {
        let socket = Arc::new(UdpSocket::bind(bind).await.unwrap());
        let counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            loop {
                let (len, peer) = match socket.recv_from(&mut buf).await {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!("wildcard DNS mock recv_from failed: error={}", e);
                        continue;
                    }
                };
                let mut resp = Vec::from(&buf[..len]);
                if resp.len() < 12 {
                    continue;
                }
                resp[2] = 0x81;
                resp[3] = 0x80;
                resp[6] = 0x00;
                resp[7] = 0x01;

                let idx = counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % pool.len();
                let ip = pool[idx];

                resp.push(0xC0);
                resp.push(0x0C);
                resp.push(0x00);
                resp.push(0x01);
                resp.push(0x00);
                resp.push(0x01);
                resp.extend_from_slice(&300u32.to_be_bytes());
                resp.push(0x00);
                resp.push(0x04);
                resp.extend_from_slice(&ip.octets());

                let _ = socket.send_to(&resp, peer).await;
            }
        })
    }

    fn resolver_for(addr: SocketAddr) -> TokioResolver {
        let mut config = ResolverConfig::new();
        let group = hickory_resolver::config::NameServerConfigGroup::from_ips_clear(
            &[addr.ip()],
            addr.port(),
            false,
        );
        if let Some(ns) = group.into_inner().into_iter().next() {
            config.add_name_server(ns);
        }
        let mut opts = ResolverOpts::default();
        opts.timeout = std::time::Duration::from_secs(2);
        opts.attempts = 1;
        TokioResolver::builder_with_config(config, TokioConnectionProvider::default())
            .with_options(opts)
            .build()
    }

    #[tokio::test]
    async fn wildcard_detects_mock_wildcard() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let actual_addr = socket.local_addr().unwrap();
        drop(socket);

        let server = mock_dns_server(actual_addr).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let resolver = resolver_for(actual_addr);
        let ips = detect_wildcards("example.com", &resolver, 3).await;
        server.abort();

        assert!(ips.contains(&IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))));
    }

    #[tokio::test]
    async fn wildcard_covers_rotating_ip_pool() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let actual_addr = socket.local_addr().unwrap();
        drop(socket);

        let pool = vec![
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(2, 2, 2, 2),
            Ipv4Addr::new(3, 3, 3, 3),
            Ipv4Addr::new(4, 4, 4, 4),
            Ipv4Addr::new(5, 5, 5, 5),
            Ipv4Addr::new(6, 6, 6, 6),
            Ipv4Addr::new(7, 7, 7, 7),
            Ipv4Addr::new(8, 8, 8, 8),
        ];
        let server = mock_rotating_dns_server(actual_addr, pool.clone()).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let resolver = resolver_for(actual_addr);
        // Small batch (3) would miss an 8-IP pool without stabilization.
        let ips = detect_wildcards("example.com", &resolver, 3).await;
        server.abort();

        for ip in pool {
            assert!(
                ips.contains(&IpAddr::V4(ip)),
                "rotating pool IP {ip} must be sampled via stabilization"
            );
        }
    }
}
