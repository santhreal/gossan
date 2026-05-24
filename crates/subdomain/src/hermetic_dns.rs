//! Configurable loopback UDP DNS responder for hermetic bruteforce tests.

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use hickory_resolver::config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts};
use tokio::net::UdpSocket;
use tokio::sync::RwLock;

const QTYPE_A: u16 = 1;
const QTYPE_CNAME: u16 = 5;
const QTYPE_AAAA: u16 = 28;

/// Per-FQDN records (keys are lowercase, no trailing dot).
#[derive(Clone, Default)]
pub struct HostRecords {
    pub a: Option<Ipv4Addr>,
    pub aaaa: Option<Ipv6Addr>,
    pub cname: Option<String>,
}

/// Zone behaviour for labels with no explicit [`HostRecords`].
#[derive(Clone, Copy, Default)]
pub enum WildcardMode {
    #[default]
    NxDomain,
    /// Synthesize A (and AAAA if set) for unknown names.
    A(Ipv4Addr),
}

/// Broken-server mode for adversarial tests.
#[derive(Clone, Copy, Debug, Default)]
pub enum AdversarialMode {
    #[default]
    Normal,
    /// NOERROR + empty answer (no RRs).
    EmptyAnswer,
    /// NXDOMAIN RCODE but a CNAME in the answer section (must not invent a host).
    NxdomainWithCname,
    /// Truncated/garbage reply (must not panic the client).
    TruncatedGarbage,
}

/// Hermetic DNS zone served over UDP on loopback.
pub struct HermeticZone {
    pub hosts: HashMap<String, HostRecords>,
    pub wildcard: WildcardMode,
    pub adversarial: AdversarialMode,
}

impl HermeticZone {
    /// Bind `127.0.0.1:0` and serve this zone until the returned task is dropped.
    pub async fn serve(self) -> SocketAddr {
        let zone = Arc::new(RwLock::new(self));
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr = socket.local_addr().unwrap();
        let zone_bg = Arc::clone(&zone);
        let socket_bg = Arc::clone(&socket);
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            loop {
                let Ok((len, peer)) = socket_bg.recv_from(&mut buf).await else {
                    continue;
                };
                let response = {
                    let z = zone_bg.read().await;
                    z.respond(&buf[..len])
                };
                let Some(resp) = response else {
                    continue;
                };
                let _ = socket_bg.send_to(&resp, peer).await;
            }
        });
        addr
    }

    fn respond(&self, query: &[u8]) -> Option<Vec<u8>> {
        if query.len() < 12 {
            return None;
        }
        let qname = parse_qname(query)?;
        let qtype = qtype_from_query(query)?;
        let mut resp = Vec::from(query);

        match self.adversarial {
            AdversarialMode::TruncatedGarbage => {
                resp.truncate(8);
                resp.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
                return Some(resp);
            }
            AdversarialMode::EmptyAnswer => {
                resp[2] = 0x81;
                resp[3] = 0x80;
                resp[6] = 0x00;
                resp[7] = 0x00;
                return Some(resp);
            }
            AdversarialMode::NxdomainWithCname => {
                if qtype == QTYPE_CNAME {
                    resp[2] = 0x81;
                    resp[3] = 0x83; // NXDOMAIN + CNAME answer (broken)
                    resp[6] = 0x00;
                    resp[7] = 0x01;
                    append_cname_rr(&mut resp, "ghost.example.com");
                    return Some(resp);
                }
                resp[2] = 0x81;
                resp[3] = 0x83;
                resp[6] = 0x00;
                resp[7] = 0x00;
                return Some(resp);
            }
            AdversarialMode::Normal => {}
        }

        let records = self
            .hosts
            .get(&qname)
            .cloned()
            .or_else(|| self.wildcard_records(&qname));

        resp[2] = 0x81;
        match records {
            None => {
                resp[3] = 0x83;
                resp[6] = 0x00;
                resp[7] = 0x00;
            }
            Some(rec) => match qtype {
                QTYPE_A => {
                    if let Some(ip) = rec.a {
                        resp[3] = 0x80;
                        resp[6] = 0x00;
                        resp[7] = 0x01;
                        append_a_rr(&mut resp, ip);
                    } else if let Some(target) = rec.cname {
                        resp[3] = 0x80;
                        resp[6] = 0x00;
                        resp[7] = 0x01;
                        append_cname_rr(&mut resp, &target);
                    } else {
                        resp[3] = 0x83;
                        resp[6] = 0x00;
                        resp[7] = 0x00;
                    }
                }
                QTYPE_AAAA => {
                    if let Some(ip) = rec.aaaa {
                        resp[3] = 0x80;
                        resp[6] = 0x00;
                        resp[7] = 0x01;
                        append_aaaa_rr(&mut resp, ip);
                    } else {
                        resp[3] = 0x83;
                        resp[6] = 0x00;
                        resp[7] = 0x00;
                    }
                }
                QTYPE_CNAME => {
                    if let Some(target) = rec.cname {
                        resp[3] = 0x80;
                        resp[6] = 0x00;
                        resp[7] = 0x01;
                        append_cname_rr(&mut resp, &target);
                    } else {
                        resp[3] = 0x83;
                        resp[6] = 0x00;
                        resp[7] = 0x00;
                    }
                }
                _ => {
                    resp[3] = 0x83;
                    resp[6] = 0x00;
                    resp[7] = 0x00;
                }
            },
        }
        Some(resp)
    }

    fn wildcard_records(&self, qname: &str) -> Option<HostRecords> {
        match self.wildcard {
            WildcardMode::NxDomain => {
                let _ = qname;
                None
            }
            WildcardMode::A(ip) => Some(HostRecords {
                a: Some(ip),
                ..HostRecords::default()
            }),
        }
    }
}

pub fn resolver_for(addr: SocketAddr) -> Arc<hickory_resolver::TokioAsyncResolver> {
    let mut config = ResolverConfig::new();
    config.add_name_server(NameServerConfig::new(addr, Protocol::Udp));
    let mut opts = ResolverOpts::default();
    opts.timeout = std::time::Duration::from_secs(2);
    opts.attempts = 1;
    Arc::new(hickory_resolver::TokioAsyncResolver::tokio(config, opts))
}

/// Build a resolver via `gossan_core::net::build_resolver` targeting this hermetic server.
pub fn gossan_resolver_for(addr: SocketAddr) -> Arc<hickory_resolver::TokioAsyncResolver> {
    std::env::set_var("GOSSAN_RESOLVER_PORT", addr.port().to_string());
    let mut cfg = gossan_core::Config::default();
    cfg.resolvers = vec![addr.ip()];
    Arc::new(gossan_core::net::build_resolver(&cfg).expect("hermetic resolver"))
}

/// Serialize env-var mutation across parallel hermetic tests.
pub fn test_env_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

fn parse_qname(buf: &[u8]) -> Option<String> {
    let mut labels = Vec::new();
    let mut i = 12usize;
    while i < buf.len() && buf[i] != 0 {
        let len = buf[i] as usize;
        i += 1;
        if i + len > buf.len() {
            return None;
        }
        labels.push(std::str::from_utf8(&buf[i..i + len]).ok()?.to_string());
        i += len;
    }
    Some(labels.join("."))
}

fn qtype_from_query(buf: &[u8]) -> Option<u16> {
    let mut i = 12usize;
    while i < buf.len() && buf[i] != 0 {
        i += 1 + buf[i] as usize;
    }
    if i + 3 >= buf.len() {
        return None;
    }
    Some(u16::from_be_bytes([buf[i + 1], buf[i + 2]]))
}

fn append_a_rr(resp: &mut Vec<u8>, ip: Ipv4Addr) {
    resp.extend_from_slice(&[0xC0, 0x0C]);
    resp.extend_from_slice(&[0x00, 0x01]);
    resp.extend_from_slice(&[0x00, 0x01]);
    resp.extend_from_slice(&300u32.to_be_bytes());
    resp.extend_from_slice(&[0x00, 0x04]);
    resp.extend_from_slice(&ip.octets());
}

fn append_aaaa_rr(resp: &mut Vec<u8>, ip: Ipv6Addr) {
    resp.extend_from_slice(&[0xC0, 0x0C]);
    resp.extend_from_slice(&[0x00, 0x1C]);
    resp.extend_from_slice(&[0x00, 0x01]);
    resp.extend_from_slice(&300u32.to_be_bytes());
    resp.extend_from_slice(&[0x00, 0x10]);
    resp.extend_from_slice(&ip.octets());
}

fn append_cname_rr(resp: &mut Vec<u8>, target: &str) {
    resp.extend_from_slice(&[0xC0, 0x0C]);
    resp.extend_from_slice(&[0x00, 0x05]);
    resp.extend_from_slice(&[0x00, 0x01]);
    resp.extend_from_slice(&300u32.to_be_bytes());
    let rdata = encode_name(target);
    resp.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    resp.extend_from_slice(&rdata);
}

fn encode_name(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for label in name.trim_end_matches('.').split('.') {
        let b = label.as_bytes();
        out.push(b.len() as u8);
        out.extend_from_slice(b);
    }
    out.push(0);
    out
}
