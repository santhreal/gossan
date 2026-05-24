//! Privileged seam + driver for the stateless SYN engine.
//!
//! Everything in [`super`] is `unsafe`-free and root-free. The only
//! parts that need a raw socket live here, encapsulated by `socket2`
//! (so the crate keeps `#![forbid(unsafe_code)]`). Engine selection,
//! source-IP discovery and the drive loop are pure / privilege-free and
//! unit-tested; the raw socket itself is real code that simply cannot
//! run in CI (no `CAP_NET_RAW`).

use std::net::{IpAddr, Ipv4Addr, SocketAddrV4, UdpSocket};
use std::time::{Duration, Instant};

use super::{Outcome, StatelessScanner, SynTransport};

/// Which scan engine to drive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineKind {
    /// masscan-class stateless SYN spray (needs `CAP_NET_RAW`).
    Stateless,
    /// Legacy `connect()` scan  -  always available, RTT/FD-bound.
    Connect,
}

/// Decide the engine and, when we cannot honour a stateless request,
/// the operator-visible reason. We **never** silently downgrade: a
/// `Some(warn)` must be surfaced (`tracing::warn!`) by the caller so a
/// slow connect scan is never mistaken for the fast path having run.
#[must_use]
pub fn choose_engine(want_stateless: bool, raw_available: bool) -> (EngineKind, Option<&'static str>) {
    match (want_stateless, raw_available) {
        (true, true) => (EngineKind::Stateless, None),
        (true, false) => (
            EngineKind::Connect,
            Some(
                "stateless SYN scan requested but CAP_NET_RAW is unavailable  -  \
                 falling back to the connect scanner (orders of magnitude slower). \
                 Run with CAP_NET_RAW (e.g. `setcap cap_net_raw+ep`) for masscan-class speed.",
            ),
        ),
        (false, _) => (EngineKind::Connect, None),
    }
}

/// Discover the source IPv4 the kernel would use to reach `dst`, with a
/// zero-traffic UDP `connect` (no packet leaves the host; this only
/// consults the routing table). Privilege-free.
#[must_use]
pub fn local_source_ipv4(dst: Ipv4Addr) -> Option<Ipv4Addr> {
    let sock = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    sock.connect(SocketAddrV4::new(dst, 80)).ok()?;
    match sock.local_addr().ok()?.ip() {
        IpAddr::V4(v4) if !v4.is_unspecified() => Some(v4),
        _ => None,
    }
}

/// Drive a scan to completion against any [`SynTransport`], pacing
/// transmits to `pps` (0 = unlimited) and draining replies for `grace`
/// after the last SYN so in-flight SYN/ACKs are not missed.
///
/// Synchronous and real (the raw socket is a blocking fd); the async
/// `Scanner::run` path wraps this in `spawn_blocking`. Correctness of
/// classification/ordering is covered by [`super`]'s tests; this adds
/// the pacing + grace-drain loop.
pub fn run_blocking<T: SynTransport>(
    scanner: &mut StatelessScanner,
    transport: &mut T,
    pps: u64,
    grace: Duration,
) -> std::io::Result<Vec<Outcome>> {
    let mut out = Vec::new();
    let start = Instant::now();
    let mut sent: u64 = 0;

    while let Some(p) = scanner.next_probe() {
        let wait = super::pace(sent, start.elapsed(), pps);
        if !wait.is_zero() {
            std::thread::sleep(wait);
        }
        transport.send(p.dst, &p.bytes)?;
        sent += 1;

        // Opportunistic non-blocking drain so the inbox can't grow
        // unbounded during a long spray.
        while let Some(pkt) = transport.try_recv()? {
            if let Some(o) = scanner.classify(&pkt) {
                if let Some(o) = scanner.record(o) {
                    out.push(o);
                }
            }
        }
    }

    // Grace window: late SYN/ACKs keep arriving ~1 RTT after the last
    // SYN. Poll until `grace` elapses with nothing left to read.
    let deadline = Instant::now() + grace;
    while Instant::now() < deadline {
        match transport.try_recv()? {
            Some(pkt) => {
                if let Some(o) = scanner.classify(&pkt) {
                    if let Some(o) = scanner.record(o) {
                        out.push(o);
                    }
                }
            }
            None => std::thread::sleep(Duration::from_millis(1)),
        }
    }
    Ok(out)
}

/// Real Linux raw-socket transport. Constructed only when
/// [`raw_available`] is true; `SOCK_RAW` creation is what gates on
/// `CAP_NET_RAW`.
#[cfg(target_os = "linux")]
pub mod linux {
    use super::*;
    use socket2::{Domain, Protocol, Socket, Type};
    use std::io::Read;
    use std::net::SocketAddr;

    /// True if this process may open raw sockets (has `CAP_NET_RAW`).
    #[must_use]
    pub fn raw_available() -> bool {
        Socket::new(
            Domain::IPV4,
            Type::RAW,
            Some(Protocol::from(libc::IPPROTO_TCP)),
        )
        .is_ok()
    }

    /// TX via an `IPPROTO_RAW` socket (kernel takes our full IP header),
    /// RX via an `IPPROTO_TCP` raw socket (kernel hands us IP+TCP).
    pub struct RawSynTransport {
        tx: Socket,
        rx: Socket,
        rx_buf: Vec<u8>,
    }

    impl RawSynTransport {
        /// Open the TX/RX raw sockets. Fails (cleanly, for fallback) if
        /// `CAP_NET_RAW` is missing.
        pub fn new() -> std::io::Result<Self> {
            let tx = Socket::new(
                Domain::IPV4,
                Type::RAW,
                Some(Protocol::from(libc::IPPROTO_RAW)),
            )?;
            let rx = Socket::new(
                Domain::IPV4,
                Type::RAW,
                Some(Protocol::from(libc::IPPROTO_TCP)),
            )?;
            rx.set_nonblocking(true)?;
            rx.set_read_timeout(Some(Duration::from_millis(1)))?;
            Ok(Self {
                tx,
                rx,
                rx_buf: vec![0u8; 65_535],
            })
        }
    }

    impl SynTransport for RawSynTransport {
        fn send(&mut self, dst: SocketAddrV4, ip_tcp: &[u8]) -> std::io::Result<()> {
            // Port is irrelevant for a raw IP send; the IP header in
            // `ip_tcp` carries the real destination.
            let to: SocketAddr = SocketAddr::from(SocketAddrV4::new(*dst.ip(), 0));
            self.tx.send_to(ip_tcp, &to.into())?;
            Ok(())
        }

        fn try_recv(&mut self) -> std::io::Result<Option<Vec<u8>>> {
            // `socket2::Socket: std::io::Read`  -  no `unsafe`, no
            // `MaybeUninit`. Non-blocking: WouldBlock/timeout ⇒ None.
            match (&self.rx).read(&mut self.rx_buf) {
                Ok(0) => Ok(None),
                Ok(n) => Ok(Some(self.rx_buf[..n].to_vec())),
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    Ok(None)
                }
                Err(e) => Err(e),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stateless::cookie::SynCookie;
    use crate::stateless::MockTransport;

    #[test]
    fn engine_selection_never_silently_downgrades() {
        assert_eq!(choose_engine(true, true), (EngineKind::Stateless, None));
        assert_eq!(choose_engine(false, true).0, EngineKind::Connect);
        assert_eq!(choose_engine(false, false).0, EngineKind::Connect);
        let (kind, warn) = choose_engine(true, false);
        assert_eq!(kind, EngineKind::Connect);
        assert!(
            warn.expect("must warn on forced downgrade").contains("CAP_NET_RAW"),
            "the downgrade reason must name the missing capability"
        );
    }

    #[test]
    fn local_source_ipv4_is_routable_when_resolvable() {
        // Routing-table lookup only (no packets). In a network-less
        // sandbox this may be None; when it resolves it must not be the
        // unspecified address.
        if let Some(ip) = local_source_ipv4(Ipv4Addr::new(1, 1, 1, 1)) {
            assert!(!ip.is_unspecified());
        }
    }

    #[test]
    fn run_blocking_unlimited_pps_is_deterministic_and_complete() {
        let c = SynCookie::with_key([5; 16]);
        let open = vec![SocketAddrV4::new(Ipv4Addr::new(1, 1, 1, 1), 443)];
        let mut s = StatelessScanner::new(
            SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 40000),
            vec![Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(9, 9, 9, 9)],
            vec![80, 443],
            c.clone(),
            42,
        );
        let mut t = MockTransport::new(c, open.clone(), vec![]);
        // pps=0 (unlimited) and zero grace ⇒ no sleeping, fast + exact.
        let outs = run_blocking(&mut s, &mut t, 0, Duration::ZERO).unwrap();
        let opens: Vec<_> = outs
            .iter()
            .filter_map(|o| match o {
                Outcome::Open(a) => Some(*a),
                Outcome::Closed(_) => None,
            })
            .collect();
        assert_eq!(opens, open, "must find exactly the open port, got {outs:?}");
    }
}
