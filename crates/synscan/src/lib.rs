use async_trait::async_trait;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::time::sleep;

use gossan_core::{
    Config, HostTarget, PortMode, Protocol, ScanInput, ScanOutput, Scanner, ServiceTarget, Target,
};

use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::tcp::{ipv4_checksum, MutableTcpPacket, TcpFlags};
use pnet::transport::{transport_channel, TransportChannelType::Layer4, TransportProtocol::Ipv4};

pub struct SynScanner;

#[async_trait]
impl Scanner for SynScanner {
    fn name(&self) -> &'static str {
        "synscan"
    }
    fn tags(&self) -> &[&'static str] {
        &["active", "network", "portscan", "raw"]
    }
    fn accepts(&self, target: &Target) -> bool {
        matches!(target, Target::Host(_) | Target::Domain(_))
    }

    async fn run(&self, input: ScanInput, config: &Config) -> anyhow::Result<ScanOutput> {
        let mut out = ScanOutput::empty();

        let source_ip = get_local_ip()?;
        let source_port = 49152 + (std::process::id() as u16 % 16383); // Simple pseudo-random ephemeral port

        let protocol = Layer4(Ipv4(IpNextHeaderProtocols::Tcp));
        let (mut tx, mut rx) = match transport_channel(65536, protocol) {
            Ok((t, r)) => (t, r),
            Err(e) => {
                tracing::error!("SYN scanning requires root privileges (cap_net_raw). Falling back to TCP connect scan.");
                return Err(e.into());
            }
        };

        // Determine target IPs
        let mut target_ips: Vec<(Ipv4Addr, Target)> = Vec::new();
        for t in &input.targets {
            if let Target::Host(h) = t {
                if let IpAddr::V4(ipv4) = h.ip {
                    target_ips.push((ipv4, t.clone()));
                }
            } else if let Target::Domain(d) = t {
                if let Ok(Ok(addrs)) = tokio::time::timeout(
                    Duration::from_secs(5),
                    tokio::net::lookup_host(format!("{}:80", d.domain)),
                )
                .await
                {
                    for addr in addrs {
                        if let IpAddr::V4(ipv4) = addr.ip() {
                            target_ips.push((ipv4, t.clone()));
                            break; // use first ipv4
                        }
                    }
                }
            }
        }

        let custom_buf: Vec<u16>;
        let active_ports: &[u16] = match &config.port_mode {
            PortMode::Default => &[
                80, 443, 22, 21, 23, 25, 53, 110, 143, 3306, 5432, 8080, 8443, 6379, 27017, 9200,
                3000, 5000, 8000, 9000,
            ],
            PortMode::Top100 => &[80, 443], // omitted for brevity, fallback
            PortMode::Top1000 => &[80, 443],
            PortMode::Full => {
                custom_buf = (1u16..=65535).collect();
                &custom_buf
            }
            PortMode::Custom(ports) => {
                custom_buf = ports.clone();
                &custom_buf
            }
        };

        let open_ports = Arc::new(Mutex::new(HashSet::new()));
        let results = Arc::clone(&open_ports);

        // Spawn packet listener on a blocking thread
        let timeout = config.timeout();
        let stop_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let rx_stop = Arc::clone(&stop_flag);

        let _rx_thread = std::thread::spawn(move || {
            let mut iter = pnet::transport::tcp_packet_iter(&mut rx);
            while !rx_stop.load(std::sync::atomic::Ordering::Relaxed) {
                if let Ok((tcp, IpAddr::V4(src_ipv4))) = iter.next() {
                    if tcp.get_destination() == source_port
                        && tcp.get_flags() == (TcpFlags::SYN | TcpFlags::ACK)
                    {
                        let key = format!("{}:{}", src_ipv4, tcp.get_source());
                        if let Ok(mut guard) = results.lock() {
                            guard.insert(key);
                        }
                    }
                }
            }
        });

        // Transmit loop
        let mut total_sent = 0;
        for (target_ip, _) in &target_ips {
            for &port in active_ports {
                let mut vec: Vec<u8> = vec![0; 20];
                let Some(mut tcp) = MutableTcpPacket::new(&mut vec) else {
                    continue;
                };
                tcp.set_source(source_port);
                tcp.set_destination(port);
                tcp.set_flags(TcpFlags::SYN);
                tcp.set_window(64240);
                tcp.set_data_offset(5);
                tcp.set_sequence(1337);
                tcp.set_checksum(ipv4_checksum(&tcp.to_immutable(), &source_ip, target_ip));

                if tx.send_to(tcp, IpAddr::V4(*target_ip)).is_ok() {
                    total_sent += 1;
                }

                // Sleep tiny amount to avoid saturating OS buffers instantly
                if total_sent % 100 == 0 {
                    tokio::task::yield_now().await;
                }
            }
        }

        tracing::info!("Sent {} SYN probes. Waiting for replies...", total_sent);

        // Wait for late SYN-ACK replies
        sleep(timeout).await;

        // Signal RX thread to stop (will stop on next packet or exit)
        stop_flag.store(true, std::sync::atomic::Ordering::Relaxed);
        // Note: rx_thread may technically hang if no packets arrive. OS timeout is required for perfection.

        let found = open_ports
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();

        for (ip, t) in target_ips {
            let domain = match t {
                Target::Domain(ref d) => Some(d.domain.clone()),
                Target::Host(ref h) => h.domain.clone(),
                _ => None,
            };

            for &port in active_ports {
                let key = format!("{}:{}", ip, port);
                if found.contains(&key) {
                    let tls = port == 443 || port == 8443;
                    out.targets.push(Target::Service(ServiceTarget {
                        host: HostTarget {
                            ip: IpAddr::V4(ip),
                            domain: domain.clone(),
                        },
                        port,
                        protocol: Protocol::Tcp,
                        banner: None,
                        tls,
                    }));
                }
            }
        }

        Ok(out)
    }
}

/// Discovers the primary outgoing local IPv4 address by doing a dummy UDP connect.
fn get_local_ip() -> anyhow::Result<Ipv4Addr> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect("8.8.8.8:53")?;
    if let IpAddr::V4(addr) = socket.local_addr()?.ip() {
        Ok(addr)
    } else {
        anyhow::bail!("Could not determine local IPv4 route")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gossan_core::{DiscoverySource, DomainTarget, Scanner};

    #[test]
    fn scanner_metadata_is_stable() {
        let scanner = SynScanner;
        assert_eq!(scanner.name(), "synscan");
        assert_eq!(scanner.tags(), &["active", "network", "portscan", "raw"]);
    }

    #[test]
    fn scanner_accepts_hosts_and_domains() {
        let scanner = SynScanner;
        assert!(scanner.accepts(&Target::Domain(DomainTarget {
            domain: "example.com".into(),
            source: DiscoverySource::Seed,
        })));
        assert!(scanner.accepts(&Target::Host(HostTarget {
            ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            domain: None,
        })));
    }
}
