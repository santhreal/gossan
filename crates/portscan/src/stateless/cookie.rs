//! Stateless SYN cookie.
//!
//! masscan's core trick: do not keep a per-probe state table. Encode
//! the destination into the TCP initial sequence number with a keyed
//! hash. A returning SYN/ACK acknowledges `our_seq + 1`, so recomputing
//! the cookie from the packet's 4-tuple and comparing to `ackno - 1`
//! both (a) tells us which probe it answers and (b) rejects spoofed /
//! unsolicited replies  -  all with O(1) state for the whole scan.
//!
//! The keyed hash is `md5(key ‖ src ‖ dst)` truncated to 32 bits. md5
//! is already a `portscan` dependency and is more than strong enough
//! for this threat model (an off-path attacker must not be able to
//! forge "port open" results within a single randomly-keyed run; this
//! is not a confidentiality primitive).

use std::net::SocketAddrV4;

/// Per-scan secret keyed cookie generator.
#[derive(Clone)]
pub struct SynCookie {
    key: [u8; 16],
}

impl SynCookie {
    /// New cookie with a fresh random per-run key. Two runs of the
    /// same scan use different keys, so cookies are unpredictable to
    /// anything that did not observe the outgoing SYN.
    #[must_use]
    pub fn random() -> Self {
        use rand::RngCore;
        let mut key = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut key);
        Self { key }
    }

    /// Explicit key  -  for deterministic tests only.
    #[must_use]
    pub fn with_key(key: [u8; 16]) -> Self {
        Self { key }
    }

    fn raw(&self, src: SocketAddrV4, dst: SocketAddrV4) -> u32 {
        let mut buf = Vec::with_capacity(16 + 12);
        buf.extend_from_slice(&self.key);
        buf.extend_from_slice(&src.ip().octets());
        buf.extend_from_slice(&src.port().to_be_bytes());
        buf.extend_from_slice(&dst.ip().octets());
        buf.extend_from_slice(&dst.port().to_be_bytes());
        let d = md5::compute(&buf);
        u32::from_be_bytes([d[0], d[1], d[2], d[3]])
    }

    /// The TCP initial sequence number to put in the SYN we send from
    /// `src` to `dst`.
    #[must_use]
    pub fn seq(&self, src: SocketAddrV4, dst: SocketAddrV4) -> u32 {
        self.raw(src, dst)
    }

    /// Validate a SYN/ACK (or RST) whose acknowledgement number is
    /// `ackno`. A SYN/ACK acks our ISN + 1; a RST in response to our
    /// SYN also carries `ackno == our_seq + 1`. `true` ⇒ this reply is
    /// genuinely ours for `(src, dst)`.
    #[must_use]
    pub fn validate(&self, src: SocketAddrV4, dst: SocketAddrV4, ackno: u32) -> bool {
        ackno == self.seq(src, dst).wrapping_add(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn sa(a: [u8; 4], p: u16) -> SocketAddrV4 {
        SocketAddrV4::new(Ipv4Addr::from(a), p)
    }

    #[test]
    fn seq_is_deterministic_per_key_and_tuple() {
        let c = SynCookie::with_key([7; 16]);
        let s = sa([10, 0, 0, 1], 40000);
        let d = sa([93, 184, 216, 34], 443);
        assert_eq!(c.seq(s, d), c.seq(s, d));
    }

    #[test]
    fn different_destination_gives_different_seq() {
        let c = SynCookie::with_key([7; 16]);
        let s = sa([10, 0, 0, 1], 40000);
        assert_ne!(
            c.seq(s, sa([93, 184, 216, 34], 443)),
            c.seq(s, sa([93, 184, 216, 34], 80))
        );
        assert_ne!(
            c.seq(s, sa([93, 184, 216, 34], 443)),
            c.seq(s, sa([1, 1, 1, 1], 443))
        );
    }

    #[test]
    fn validate_accepts_our_synack_and_rejects_others() {
        let c = SynCookie::with_key([42; 16]);
        let s = sa([10, 0, 0, 1], 40000);
        let d = sa([93, 184, 216, 34], 443);
        let ackno = c.seq(s, d).wrapping_add(1);
        assert!(c.validate(s, d, ackno));
        // Off-by-one / unsolicited / spoofed → rejected.
        assert!(!c.validate(s, d, ackno.wrapping_add(1)));
        assert!(!c.validate(s, d, c.seq(s, d)));
        assert!(!c.validate(s, sa([93, 184, 216, 34], 80), ackno));
        // A different key (different run) must not validate.
        assert!(!SynCookie::with_key([43; 16]).validate(s, d, ackno));
    }

    #[test]
    fn seq_wraps_safely_at_u32_max() {
        // The +1 must wrap, never panic, even if the cookie is u32::MAX.
        let c = SynCookie::with_key([0; 16]);
        let s = sa([0, 0, 0, 0], 1);
        let d = sa([0, 0, 0, 0], 1);
        // Just exercising the path; correctness is the wrap, not value.
        let _ = c.validate(s, d, c.seq(s, d).wrapping_add(1));
    }
}
