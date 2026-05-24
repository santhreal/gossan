//! Stateless SYN scan engine  -  the masscan-class fast path.
//!
//! The legacy scanner ([`crate`]'s `buffer_unordered` connect loop) is
//! bounded by RTT, the ephemeral-port range and the kernel socket
//! table: a full 3-way handshake + teardown per probe. masscan beats
//! it by being *stateless*  -  spray hand-built SYNs at a fixed packet
//! rate and recognise replies by a keyed cookie instead of a state
//! table. This module is that engine, decomposed so the entire
//! decision core is `unsafe`-free and unit-testable without root:
//!
//! - [`cookie`]  -  keyed ISN so a reply self-identifies (no state).
//! - [`blackrock`]  -  O(1)-memory pseudo-random target ordering.
//! - [`packet`]  -  IPv4/TCP SYN construction + reply parsing.
//! - [`SynTransport`]  -  the only privileged seam (raw socket); a
//!   [`MockTransport`] exercises the whole engine in tests, and the
//!   real `pnet`/AF_XDP backend wires in behind this trait with a loud
//!   fallback to the connect scanner when `CAP_NET_RAW` is absent.

pub mod blackrock;
pub mod cookie;
pub mod packet;
pub mod transport;

use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

use blackrock::Blackrock;
use cookie::SynCookie;

/// Outcome of a classified reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// SYN/ACK  -  port is open.
    Open(SocketAddrV4),
    /// RST  -  port is closed (host alive, port shut).
    Closed(SocketAddrV4),
}

/// One SYN to transmit.
#[derive(Debug, Clone)]
pub struct Probe {
    pub dst: SocketAddrV4,
    pub seq: u32,
    /// Wire bytes: IPv4 header + TCP SYN, checksums filled.
    pub bytes: Vec<u8>,
}

/// The privileged seam. The engine never touches a socket directly.
pub trait SynTransport {
    /// Transmit one already-built IPv4+TCP datagram to `dst`.
    fn send(&mut self, dst: SocketAddrV4, ip_tcp: &[u8]) -> std::io::Result<()>;
    /// Non-blocking receive of one raw IPv4 datagram; `Ok(None)` when
    /// nothing is queued.
    fn try_recv(&mut self) -> std::io::Result<Option<Vec<u8>>>;
}

/// Stateless scanner over `ips × ports`, emitting probes in a
/// blackrock-permuted order and classifying replies by cookie.
pub struct StatelessScanner {
    src: SocketAddrV4,
    ips: Vec<Ipv4Addr>,
    ports: Vec<u16>,
    cookie: SynCookie,
    perm: Blackrock,
    cursor: u64,
    total: u64,
    ttl: u8,
    window: u16,
    ip_id: u16,
    /// Targets already classified. A stateless scan never ACKs, so an
    /// open port's SYN/ACK (and a closed port's RST) is retransmitted
    /// by the responder; this gates each `(ip, port)` to one result.
    seen: HashSet<SocketAddrV4>,
}

impl StatelessScanner {
    /// `src` is our bound address (source IP + a fixed source port  - 
    /// the cookie covers the 4-tuple so a single source port is fine).
    #[must_use]
    pub fn new(
        src: SocketAddrV4,
        ips: Vec<Ipv4Addr>,
        ports: Vec<u16>,
        cookie: SynCookie,
        seed: u64,
    ) -> Self {
        let total = (ips.len() as u64).saturating_mul(ports.len() as u64);
        let perm = Blackrock::new(total, seed);
        Self {
            src,
            ips,
            ports,
            cookie,
            perm,
            cursor: 0,
            total,
            ttl: 64,
            window: 1024,
            ip_id: 1,
            seen: HashSet::new(),
        }
    }

    /// Total number of (ip, port) probes this scan will emit.
    #[must_use]
    pub fn total(&self) -> u64 {
        self.total
    }

    fn decode(&self, index: u64) -> SocketAddrV4 {
        let np = self.ports.len() as u64;
        let ip = self.ips[(index / np) as usize];
        let port = self.ports[(index % np) as usize];
        SocketAddrV4::new(ip, port)
    }

    /// Next SYN to send, in permuted order, or `None` when the space is
    /// exhausted.
    pub fn next_probe(&mut self) -> Option<Probe> {
        if self.cursor >= self.total {
            return None;
        }
        let idx = self.perm.shuffle(self.cursor);
        self.cursor += 1;
        let dst = self.decode(idx);
        let seq = self.cookie.seq(self.src, dst);
        self.ip_id = self.ip_id.wrapping_add(1);
        let bytes = packet::build_syn(self.src, dst, seq, self.ttl, self.window, self.ip_id);
        Some(Probe { dst, seq, bytes })
    }

    /// Classify a raw IPv4 datagram. Returns an [`Outcome`] only when
    /// the reply parses as TCP, is addressed to us, and carries a valid
    /// cookie (`ackno == our_isn + 1`)  -  unsolicited or spoofed packets
    /// yield `None` and never become findings.
    #[must_use]
    pub fn classify(&self, pkt: &[u8]) -> Option<Outcome> {
        let r = packet::parse_tcp_reply(pkt)?;
        if r.to.ip() != self.src.ip() || r.to.port() != self.src.port() {
            return None;
        }
        if !self.cookie.validate(self.src, r.from, r.ackno) {
            return None;
        }
        if r.is_open() {
            Some(Outcome::Open(r.from))
        } else if r.is_closed() {
            Some(Outcome::Closed(r.from))
        } else {
            None
        }
    }

    /// Idempotent result gate. `classify` is a pure function of one
    /// packet, so it (correctly) returns `Some` for *every* cookied
    /// reply. But a stateless scan never ACKs, so an open port's
    /// SYN/ACK  -  and a closed port's RST  -  is retransmitted by the
    /// responder several times (Linux default: ~5 SYN/ACKs over
    /// ~3 min for a half-open connection). Without this gate one open
    /// port becomes 3–5 duplicate "open" findings on every real scan.
    ///
    /// A target's state is fixed by the first cookied reply; later
    /// copies for the same `(ip, port)` return `None`. Keyed on the
    /// responder address only (a given `(ip, port)` has exactly one
    /// true state, and we send it exactly one SYN), so this never
    /// suppresses a *distinct* port  -  only retransmits of one.
    pub fn record(&mut self, outcome: Outcome) -> Option<Outcome> {
        let target = match outcome {
            Outcome::Open(a) | Outcome::Closed(a) => a,
        };
        if self.seen.insert(target) {
            Some(outcome)
        } else {
            None
        }
    }
}

/// Pure pacing helper: given how many packets we have sent and how long
/// the scan has been running, return how long to sleep so the average
/// rate does not exceed `pps`. `Duration::ZERO` ⇒ send now (we are
/// behind or exactly on schedule). Decoupling this from any clock makes
/// the rate logic exhaustively testable.
#[must_use]
pub fn pace(sent: u64, elapsed: Duration, pps: u64) -> Duration {
    if pps == 0 {
        return Duration::ZERO;
    }
    // Time at which packet number `sent` is *allowed* to go out.
    let earliest = Duration::from_secs_f64(sent as f64 / pps as f64);
    earliest.checked_sub(elapsed).unwrap_or(Duration::ZERO)
}

/// In-memory transport for tests: every SYN to a port in `open` is
/// answered with a correctly-cookied SYN/ACK; ports in `closed` get a
/// RST; everything else is dropped (filtered). Lets the full engine
/// run end-to-end with zero privilege.
pub struct MockTransport {
    cookie: SynCookie,
    open: Vec<SocketAddrV4>,
    closed: Vec<SocketAddrV4>,
    inbox: std::collections::VecDeque<Vec<u8>>,
    pub sent: HashMap<SocketAddrV4, u32>,
}

impl MockTransport {
    #[must_use]
    pub fn new(cookie: SynCookie, open: Vec<SocketAddrV4>, closed: Vec<SocketAddrV4>) -> Self {
        Self {
            cookie,
            open,
            closed,
            inbox: std::collections::VecDeque::new(),
            sent: HashMap::new(),
        }
    }
}

impl SynTransport for MockTransport {
    fn send(&mut self, dst: SocketAddrV4, ip_tcp: &[u8]) -> std::io::Result<()> {
        let our = packet::parse_tcp_reply(ip_tcp).expect("engine builds valid SYNs");
        self.sent.insert(dst, our.ackno /* = our seq, ack field is 0 */);
        let our_src = our.to; // SYN: IP dst is the responder, our src is IP src
        let _ = our_src;
        // Reply must ack our_seq + 1, computed with the SAME cookie.
        let isn = self.cookie.seq(our.from, dst);
        let reply_ack = isn.wrapping_add(1);
        // Swap directions: responder -> us.
        let mut reply = packet::build_syn(dst, our.from, 0xABCD_1234, 64, 512, 9);
        reply[20 + 8..20 + 12].copy_from_slice(&reply_ack.to_be_bytes());
        if self.open.contains(&dst) {
            reply[20 + 13] = 0x12; // SYN|ACK
            self.inbox.push_back(reply);
        } else if self.closed.contains(&dst) {
            reply[20 + 13] = 0x04; // RST
            self.inbox.push_back(reply);
        }
        Ok(())
    }

    fn try_recv(&mut self) -> std::io::Result<Option<Vec<u8>>> {
        Ok(self.inbox.pop_front())
    }
}

/// Drive a scan to completion against any transport (synchronous; the
/// async/raw driver layers on top). Returns the discovered outcomes.
/// This is the integration point the tests exercise end-to-end.
pub fn run_to_completion<T: SynTransport>(
    scanner: &mut StatelessScanner,
    transport: &mut T,
) -> std::io::Result<Vec<Outcome>> {
    let mut out = Vec::new();
    while let Some(p) = scanner.next_probe() {
        transport.send(p.dst, &p.bytes)?;
        while let Some(pkt) = transport.try_recv()? {
            if let Some(o) = scanner.classify(&pkt) {
                if let Some(o) = scanner.record(o) {
                    out.push(o);
                }
            }
        }
    }
    // Final drain for any late replies.
    while let Some(pkt) = transport.try_recv()? {
        if let Some(o) = scanner.classify(&pkt) {
            if let Some(o) = scanner.record(o) {
                out.push(o);
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(a: [u8; 4]) -> Ipv4Addr {
        Ipv4Addr::from(a)
    }
    fn sa(a: [u8; 4], p: u16) -> SocketAddrV4 {
        SocketAddrV4::new(ip(a), p)
    }

    fn scanner(seed: u64, cookie: &SynCookie) -> StatelessScanner {
        StatelessScanner::new(
            sa([10, 0, 0, 9], 40000),
            vec![ip([93, 184, 216, 34]), ip([1, 1, 1, 1])],
            vec![80, 443, 22, 8080],
            cookie.clone(),
            seed,
        )
    }

    #[test]
    fn emits_every_target_exactly_once_in_permuted_order() {
        let c = SynCookie::with_key([1; 16]);
        let mut s = scanner(123, &c);
        assert_eq!(s.total(), 8);
        let mut seen = std::collections::HashSet::new();
        let mut order = Vec::new();
        while let Some(p) = s.next_probe() {
            assert!(seen.insert(p.dst), "duplicate probe {}", p.dst);
            order.push(p.dst);
        }
        assert_eq!(seen.len(), 8, "must cover the whole ip×port space once");
        let sequential: Vec<SocketAddrV4> = {
            let mut s2 = scanner(123, &c);
            std::iter::from_fn(|| s2.next_probe().map(|p| p.dst)).collect()
        };
        assert_eq!(order, sequential, "deterministic for a fixed seed");
    }

    #[test]
    fn end_to_end_finds_exactly_the_open_ports() {
        let c = SynCookie::with_key([9; 16]);
        let open = vec![sa([93, 184, 216, 34], 443), sa([1, 1, 1, 1], 22)];
        let closed = vec![sa([93, 184, 216, 34], 80)];
        let mut s = scanner(777, &c);
        let mut t = MockTransport::new(c.clone(), open.clone(), closed.clone());
        let mut outcomes = run_to_completion(&mut s, &mut t).unwrap();
        outcomes.sort_by_key(|o| match o {
            Outcome::Open(a) | Outcome::Closed(a) => (*a.ip(), a.port()),
        });

        let opens: Vec<_> = outcomes
            .iter()
            .filter_map(|o| match o {
                Outcome::Open(a) => Some(*a),
                Outcome::Closed(_) => None,
            })
            .collect();
        let closes: Vec<_> = outcomes
            .iter()
            .filter_map(|o| match o {
                Outcome::Closed(a) => Some(*a),
                Outcome::Open(_) => None,
            })
            .collect();
        assert_eq!(opens.len(), 2, "exactly the two open ports: {opens:?}");
        assert!(opens.contains(&sa([93, 184, 216, 34], 443)));
        assert!(opens.contains(&sa([1, 1, 1, 1], 22)));
        assert_eq!(closes, vec![sa([93, 184, 216, 34], 80)]);
    }

    #[test]
    fn spoofed_reply_with_wrong_cookie_is_rejected() {
        // Adversarial: an off-path attacker injects a SYN/ACK for a
        // port we probed but cannot compute our per-run cookie. It must
        // NOT be reported open.
        let real = SynCookie::with_key([1; 16]);
        let mut s = scanner(5, &real);
        let p = s.next_probe().unwrap();
        // Build a SYN/ACK from the probed host with a bogus ack number.
        let mut forged = packet::build_syn(p.dst, sa([10, 0, 0, 9], 40000), 1, 64, 512, 1);
        forged[20 + 13] = 0x12; // SYN|ACK
        forged[20 + 8..20 + 12].copy_from_slice(&0xdead_beefu32.to_be_bytes());
        assert_eq!(s.classify(&forged), None, "forged cookie must be rejected");

        // The correctly-cookied reply for the same probe IS accepted.
        let mut good = packet::build_syn(p.dst, sa([10, 0, 0, 9], 40000), 1, 64, 512, 1);
        good[20 + 13] = 0x12;
        good[20 + 8..20 + 12].copy_from_slice(&p.seq.wrapping_add(1).to_be_bytes());
        assert_eq!(s.classify(&good), Some(Outcome::Open(p.dst)));
    }

    #[test]
    fn reply_addressed_to_a_different_host_is_ignored() {
        let c = SynCookie::with_key([2; 16]);
        let s = scanner(1, &c);
        // Valid-looking SYN/ACK but IP dst is not our source IP.
        let mut pkt = packet::build_syn(sa([1, 1, 1, 1], 443), sa([8, 8, 8, 8], 40000), 1, 64, 1, 1);
        pkt[20 + 13] = 0x12;
        assert_eq!(s.classify(&pkt), None);
    }

    #[test]
    fn pace_enforces_average_rate() {
        // 1000 pps: packet #1000 may go at t=1s. If only 0.5s elapsed
        // we must wait ~0.5s; if 2s elapsed we may fire immediately.
        assert_eq!(pace(0, Duration::from_secs(0), 1000), Duration::ZERO);
        let w = pace(1000, Duration::from_millis(500), 1000);
        assert!(
            (w.as_millis() as i64 - 500).abs() <= 2,
            "expected ~500ms, got {w:?}"
        );
        assert_eq!(pace(1000, Duration::from_secs(2), 1000), Duration::ZERO);
        assert_eq!(pace(5, Duration::from_secs(1), 0), Duration::ZERO); // unlimited
    }

    fn synack_for(p: &Probe) -> Vec<u8> {
        let mut pk = packet::build_syn(p.dst, sa([10, 0, 0, 9], 40000), 1, 64, 512, 1);
        pk[20 + 13] = 0x12; // SYN|ACK
        pk[20 + 8..20 + 12].copy_from_slice(&p.seq.wrapping_add(1).to_be_bytes());
        pk
    }

    /// PROVING: a stateless scan never ACKs, so the responder
    /// retransmits its SYN/ACK (Linux default ≈ 5×). Every copy carries
    /// the same valid cookie and classifies Open; the result gate must
    /// collapse them to exactly ONE finding.
    #[test]
    fn retransmitted_synack_is_reported_once() {
        let c = SynCookie::with_key([3; 16]);
        let mut s = scanner(11, &c);
        let p = s.next_probe().unwrap();
        let synack = synack_for(&p);

        let mut emitted = Vec::new();
        for _ in 0..5 {
            // `classify` (pure) still fires every time  -  proving the
            // duplication is real and the gate, not classify, fixes it.
            assert_eq!(s.classify(&synack), Some(Outcome::Open(p.dst)));
            if let Some(o) = s.classify(&synack) {
                if let Some(o) = s.record(o) {
                    emitted.push(o);
                }
            }
        }
        assert_eq!(
            emitted,
            vec![Outcome::Open(p.dst)],
            "5 retransmitted SYN/ACKs must yield exactly one Open, got {emitted:?}"
        );
    }

    /// ADVERSARIAL: the gate must dedup per `(ip, port)` only  -  it must
    /// NOT swallow *distinct* open ports. Interleaved duplicates of two
    /// different opens still yield exactly two findings.
    #[test]
    fn result_gate_is_per_target_not_global() {
        let c = SynCookie::with_key([4; 16]);
        let mut s = scanner(12, &c);
        let p1 = s.next_probe().unwrap();
        let p2 = s.next_probe().unwrap();
        assert_ne!(p1.dst, p2.dst);
        let a = synack_for(&p1);
        let b = synack_for(&p2);

        let mut emitted = Vec::new();
        for pkt in [&a, &a, &b, &a, &b, &b] {
            if let Some(o) = s.classify(pkt) {
                if let Some(o) = s.record(o) {
                    emitted.push(o);
                }
            }
        }
        assert_eq!(emitted.len(), 2, "two distinct opens must report once each: {emitted:?}");
        assert!(emitted.contains(&Outcome::Open(p1.dst)));
        assert!(emitted.contains(&Outcome::Open(p2.dst)));
    }

    /// Transport that retransmits every open port's SYN/ACK `copies`
    /// times  -  models the real kernel behaviour a stateless scan
    /// triggers (no ACK ⇒ responder keeps resending).
    struct RetxTransport {
        cookie: SynCookie,
        open: Vec<SocketAddrV4>,
        inbox: std::collections::VecDeque<Vec<u8>>,
        copies: usize,
    }

    impl SynTransport for RetxTransport {
        fn send(&mut self, dst: SocketAddrV4, ip_tcp: &[u8]) -> std::io::Result<()> {
            let our = packet::parse_tcp_reply(ip_tcp).expect("valid SYN");
            if self.open.contains(&dst) {
                let isn = self.cookie.seq(our.from, dst);
                let mut reply = packet::build_syn(dst, our.from, 0xABCD_1234, 64, 512, 9);
                reply[20 + 8..20 + 12].copy_from_slice(&isn.wrapping_add(1).to_be_bytes());
                reply[20 + 13] = 0x12; // SYN|ACK
                for _ in 0..self.copies {
                    self.inbox.push_back(reply.clone());
                }
            }
            Ok(())
        }
        fn try_recv(&mut self) -> std::io::Result<Option<Vec<u8>>> {
            Ok(self.inbox.pop_front())
        }
    }

    /// ADVERSARIAL e2e: drive the real `run_to_completion` loop against
    /// a transport that retransmits each open port's SYN/ACK 5×. The
    /// driver must surface exactly one Open per open port.
    #[test]
    fn driver_dedups_retransmitted_opens_end_to_end() {
        let c = SynCookie::with_key([8; 16]);
        let open = vec![sa([93, 184, 216, 34], 443), sa([1, 1, 1, 1], 22)];
        let mut s = scanner(99, &c);
        let mut t = RetxTransport {
            cookie: c.clone(),
            open: open.clone(),
            inbox: std::collections::VecDeque::new(),
            copies: 5,
        };
        let outs = run_to_completion(&mut s, &mut t).unwrap();
        let mut opens: Vec<_> = outs
            .iter()
            .filter_map(|o| match o {
                Outcome::Open(a) => Some(*a),
                Outcome::Closed(_) => None,
            })
            .collect();
        opens.sort_by_key(|a| (*a.ip(), a.port()));
        assert_eq!(
            opens,
            {
                let mut e = open.clone();
                e.sort_by_key(|a| (*a.ip(), a.port()));
                e
            },
            "each open port must appear exactly once despite 5 retransmits: {outs:?}"
        );
    }
}
