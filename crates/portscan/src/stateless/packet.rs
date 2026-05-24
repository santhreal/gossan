//! Hand-built IPv4 + TCP SYN frames and the RFC 1071 checksum.
//!
//! The stateless engine does not use the kernel TCP stack, so it must
//! construct the SYN itself and parse the raw reply. Pure byte math  - 
//! no `unsafe`, no sockets here (transport lives behind a trait).

use std::net::SocketAddrV4;

const IPV4_HDR_LEN: usize = 20;
const TCP_HDR_LEN: usize = 20;

/// RFC 1071 one's-complement internet checksum over `data`.
#[must_use]
pub fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = data.chunks_exact(2);
    for c in &mut chunks {
        sum += u32::from(u16::from_be_bytes([c[0], c[1]]));
    }
    if let [last] = chunks.remainder() {
        sum += u32::from(u16::from_be_bytes([*last, 0]));
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Build a 40-byte IPv4+TCP SYN from `src` to `dst` carrying initial
/// sequence number `seq`. No IP/TCP options. Both checksums are filled
/// in. Suitable for an `IP_HDRINCL` raw socket (kernel adds L2).
#[must_use]
pub fn build_syn(
    src: SocketAddrV4,
    dst: SocketAddrV4,
    seq: u32,
    ttl: u8,
    window: u16,
    ip_id: u16,
) -> Vec<u8> {
    let total_len = (IPV4_HDR_LEN + TCP_HDR_LEN) as u16;
    let mut pkt = vec![0u8; IPV4_HDR_LEN + TCP_HDR_LEN];

    // ── IPv4 header ──────────────────────────────────────────────
    pkt[0] = 0x45; // version 4, IHL 5 (20 bytes)
    pkt[1] = 0; // DSCP/ECN
    pkt[2..4].copy_from_slice(&total_len.to_be_bytes());
    pkt[4..6].copy_from_slice(&ip_id.to_be_bytes());
    pkt[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // Don't Fragment
    pkt[8] = ttl;
    pkt[9] = 6; // protocol = TCP
    // pkt[10..12] checksum  -  zero for computation
    pkt[12..16].copy_from_slice(&src.ip().octets());
    pkt[16..20].copy_from_slice(&dst.ip().octets());
    let ip_csum = internet_checksum(&pkt[..IPV4_HDR_LEN]);
    pkt[10..12].copy_from_slice(&ip_csum.to_be_bytes());

    // ── TCP header ───────────────────────────────────────────────
    let t = IPV4_HDR_LEN;
    pkt[t..t + 2].copy_from_slice(&src.port().to_be_bytes());
    pkt[t + 2..t + 4].copy_from_slice(&dst.port().to_be_bytes());
    pkt[t + 4..t + 8].copy_from_slice(&seq.to_be_bytes());
    // ack number = 0
    pkt[t + 12] = 0x50; // data offset 5 (20 bytes), no options
    pkt[t + 13] = 0x02; // flags: SYN
    pkt[t + 14..t + 16].copy_from_slice(&window.to_be_bytes());
    // urgent pointer = 0

    // TCP checksum over pseudo-header + TCP segment.
    let mut pseudo = Vec::with_capacity(12 + TCP_HDR_LEN);
    pseudo.extend_from_slice(&src.ip().octets());
    pseudo.extend_from_slice(&dst.ip().octets());
    pseudo.push(0);
    pseudo.push(6); // protocol
    pseudo.extend_from_slice(&(TCP_HDR_LEN as u16).to_be_bytes());
    pseudo.extend_from_slice(&pkt[t..t + TCP_HDR_LEN]);
    let tcp_csum = internet_checksum(&pseudo);
    pkt[t + 16..t + 18].copy_from_slice(&tcp_csum.to_be_bytes());

    pkt
}

/// Parsed TCP reply fields the engine needs to classify a probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpReply {
    /// Responder address (the host we probed), from IP src + TCP sport.
    pub from: SocketAddrV4,
    /// Our address, from IP dst + TCP dport.
    pub to: SocketAddrV4,
    /// TCP acknowledgement number (a SYN/ACK or RST acks our ISN+1).
    pub ackno: u32,
    pub syn: bool,
    pub ack: bool,
    pub rst: bool,
}

impl TcpReply {
    /// An open port: SYN+ACK to our SYN.
    #[must_use]
    pub fn is_open(&self) -> bool {
        self.syn && self.ack
    }
    /// A closed port: RST to our SYN.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.rst
    }
}

/// Parse a raw IPv4+TCP packet (as delivered by a raw socket, without
/// link layer). Returns `None` for anything that is not a well-formed
/// IPv4/TCP datagram long enough to read the TCP header.
#[must_use]
pub fn parse_tcp_reply(pkt: &[u8]) -> Option<TcpReply> {
    if pkt.len() < IPV4_HDR_LEN {
        return None;
    }
    if pkt[0] >> 4 != 4 {
        return None; // not IPv4
    }
    let ihl = ((pkt[0] & 0x0f) as usize) * 4;
    if ihl < IPV4_HDR_LEN || pkt.len() < ihl + TCP_HDR_LEN {
        return None;
    }
    if pkt[9] != 6 {
        return None; // not TCP
    }
    let src_ip = std::net::Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
    let dst_ip = std::net::Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);

    let t = ihl;
    let sport = u16::from_be_bytes([pkt[t], pkt[t + 1]]);
    let dport = u16::from_be_bytes([pkt[t + 2], pkt[t + 3]]);
    let ackno = u32::from_be_bytes([pkt[t + 8], pkt[t + 9], pkt[t + 10], pkt[t + 11]]);
    let flags = pkt[t + 13];

    Some(TcpReply {
        from: SocketAddrV4::new(src_ip, sport),
        to: SocketAddrV4::new(dst_ip, dport),
        ackno,
        syn: flags & 0x02 != 0,
        ack: flags & 0x10 != 0,
        rst: flags & 0x04 != 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn sa(a: [u8; 4], p: u16) -> SocketAddrV4 {
        SocketAddrV4::new(Ipv4Addr::from(a), p)
    }

    #[test]
    fn internet_checksum_rfc1071_vector() {
        // Classic RFC 1071 example bytes; the checksum of a buffer
        // already containing its own correct checksum sums to 0.
        let data = [0x45u8, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00,
                    0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8, 0x00, 0x01,
                    0xc0, 0xa8, 0x00, 0xc7];
        let c = internet_checksum(&data);
        let mut withc = data;
        withc[10] = (c >> 8) as u8;
        withc[11] = (c & 0xff) as u8;
        assert_eq!(internet_checksum(&withc), 0, "verified checksum must be 0");
    }

    #[test]
    fn built_syn_has_valid_checksums_and_fields() {
        let src = sa([10, 0, 0, 5], 40001);
        let dst = sa([93, 184, 216, 34], 443);
        let pkt = build_syn(src, dst, 0xdead_beef, 64, 1024, 0x1234);
        assert_eq!(pkt.len(), 40);

        // IP header checksum must verify (sum incl. checksum == 0).
        assert_eq!(internet_checksum(&pkt[..20]), 0);

        // TCP checksum must verify over pseudo-header + segment.
        let mut pseudo = Vec::new();
        pseudo.extend_from_slice(&src.ip().octets());
        pseudo.extend_from_slice(&dst.ip().octets());
        pseudo.push(0);
        pseudo.push(6);
        pseudo.extend_from_slice(&20u16.to_be_bytes());
        pseudo.extend_from_slice(&pkt[20..40]);
        assert_eq!(internet_checksum(&pseudo), 0);

        // Round-trip the fields a reply parser would read.
        let r = parse_tcp_reply(&pkt).expect("our own SYN must parse");
        assert_eq!(r.from, src);
        assert_eq!(r.to, dst);
        assert!(r.syn && !r.ack && !r.rst, "must be a pure SYN");
    }

    #[test]
    fn classifies_synack_and_rst() {
        let src = sa([1, 2, 3, 4], 50000); // responder
        let dst = sa([10, 0, 0, 5], 40001); // us
        // SYN/ACK
        let mut p = build_syn(src, dst, 7, 64, 512, 1);
        p[20 + 13] = 0x12; // SYN|ACK
        let r = parse_tcp_reply(&p).unwrap();
        assert!(r.is_open() && !r.is_closed());
        // RST
        let mut p2 = build_syn(src, dst, 7, 64, 512, 1);
        p2[20 + 13] = 0x04; // RST
        let r2 = parse_tcp_reply(&p2).unwrap();
        assert!(r2.is_closed() && !r2.is_open());
    }

    #[test]
    fn rejects_garbage_and_non_tcp() {
        assert!(parse_tcp_reply(&[]).is_none());
        assert!(parse_tcp_reply(&[0u8; 19]).is_none()); // too short
        let mut not_v4 = build_syn(sa([1, 1, 1, 1], 1), sa([2, 2, 2, 2], 2), 1, 64, 1, 1);
        not_v4[0] = 0x65; // version 6
        assert!(parse_tcp_reply(&not_v4).is_none());
        let mut not_tcp = build_syn(sa([1, 1, 1, 1], 1), sa([2, 2, 2, 2], 2), 1, 64, 1, 1);
        not_tcp[9] = 17; // UDP
        assert!(parse_tcp_reply(&not_tcp).is_none());
    }
}
