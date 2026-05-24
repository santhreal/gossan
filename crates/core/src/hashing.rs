//! Canonical hashing primitives shared across scanners.
//!
//! Before this module, MurmurHash3 x86_32 was reimplemented three times
//! (`hidden::favicon`, `horizontal::conservative`,
//! `origin::scanners::favicon`). The hash *core* was byte-identical in
//! all three; only the base64 framing fed to it differed. The duplicated
//! core now lives here once.
//!
//! Use [`shodan_favicon_hash`] for any *new* favicon work  -  it matches
//! the framing Shodan's `http.favicon.hash:` actually indexes (Python
//! `base64.encodebytes`: a newline every 76 chars **and** a trailing
//! newline). Call sites that historically used a different framing keep
//! their own framing on top of [`mmh3_x86_32`] for now so this
//! extraction stays strictly behaviour-preserving; their divergence
//! from the Shodan convention is a separate, tracked correctness item.

/// MurmurHash3 x86_32, seed-parameterised, matching Python `mmh3.hash`
/// (the implementation Shodan uses for favicon hashes).
///
/// This is the exact algorithm the three former private copies all
/// implemented; consolidating here is behaviour-preserving for every
/// caller that feeds it the same bytes.
#[must_use]
pub fn mmh3_x86_32(data: &[u8], seed: u32) -> u32 {
    const C1: u32 = 0xcc9e_2d51;
    const C2: u32 = 0x1b87_3593;

    let mut h1 = seed;
    let mut chunks = data.chunks_exact(4);
    for chunk in &mut chunks {
        let mut k1 = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        k1 = k1.wrapping_mul(C1).rotate_left(15).wrapping_mul(C2);
        h1 ^= k1;
        h1 = h1.rotate_left(13).wrapping_mul(5).wrapping_add(0xe654_6b64);
    }

    let rem = chunks.remainder();
    if !rem.is_empty() {
        let mut k1: u32 = 0;
        if rem.len() >= 3 {
            k1 ^= u32::from(rem[2]) << 16;
        }
        if rem.len() >= 2 {
            k1 ^= u32::from(rem[1]) << 8;
        }
        k1 ^= u32::from(rem[0]);
        k1 = k1.wrapping_mul(C1).rotate_left(15).wrapping_mul(C2);
        h1 ^= k1;
    }

    h1 ^= data.len() as u32;
    h1 ^= h1 >> 16;
    h1 = h1.wrapping_mul(0x85eb_ca6b);
    h1 ^= h1 >> 13;
    h1 = h1.wrapping_mul(0xc2b2_ae35);
    h1 ^ (h1 >> 16)
}

/// Standard base64 alphabet, no padding-stripping. Kept local so this
/// module has no external base64 dependency (it is `core`).
fn base64_std(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(T[((n >> 18) & 63) as usize] as char);
        out.push(T[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            T[((n >> 6) & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            T[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

/// The favicon hash exactly as Shodan indexes it: standard base64 of
/// the raw icon bytes, a `\n` inserted every 76 characters **and** a
/// trailing `\n` (Python `base64.encodebytes` behaviour), MurmurHash3
/// x86_32 seed 0, returned as the signed `i32` Shodan stores.
#[must_use]
pub fn shodan_favicon_hash(raw_icon: &[u8]) -> i32 {
    let b64 = base64_std(raw_icon);
    let mut framed = String::with_capacity(b64.len() + b64.len() / 76 + 1);
    for chunk in b64.as_bytes().chunks(76) {
        framed.push_str(std::str::from_utf8(chunk).unwrap_or(""));
        framed.push('\n');
    }
    mmh3_x86_32(framed.as_bytes(), 0) as i32
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The one vector that is provably correct by definition: empty
    /// input with seed 0 finalises to 0. (Unverified string vectors
    /// are deliberately NOT asserted  -  the behaviour contract for this
    /// consolidation is "bit-identical to the three legacy copies",
    /// proved exhaustively by `mmh3_matches_legacy_private_copies`.)
    #[test]
    fn mmh3_empty_seed_zero_is_zero() {
        assert_eq!(mmh3_x86_32(b"", 0), 0);
    }

    /// The shared core must reproduce, bit-for-bit, what the three
    /// former private copies computed for the same input  -  otherwise
    /// the consolidation is not behaviour-preserving.
    #[test]
    fn mmh3_matches_legacy_private_copies() {
        // Reference reimplementation = the exact body the old copies
        // had; assert equality across a spread of lengths/alignments.
        fn legacy(data: &[u8], seed: u32) -> u32 {
            let c1: u32 = 0xcc9e_2d51;
            let c2: u32 = 0x1b87_3593;
            let mut h1 = seed;
            let chunks = data.chunks_exact(4);
            let remainder = chunks.remainder();
            for chunk in chunks {
                let mut k1 = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
                k1 = k1.wrapping_mul(c1).rotate_left(15).wrapping_mul(c2);
                h1 ^= k1;
                h1 = h1.rotate_left(13).wrapping_mul(5).wrapping_add(0xe654_6b64);
            }
            let mut k1: u32 = 0;
            match remainder.len() {
                3 => {
                    k1 ^= (remainder[2] as u32) << 16;
                    k1 ^= (remainder[1] as u32) << 8;
                    k1 ^= remainder[0] as u32;
                }
                2 => {
                    k1 ^= (remainder[1] as u32) << 8;
                    k1 ^= remainder[0] as u32;
                }
                1 => {
                    k1 ^= remainder[0] as u32;
                }
                _ => {}
            }
            if !remainder.is_empty() {
                k1 = k1.wrapping_mul(c1).rotate_left(15).wrapping_mul(c2);
                h1 ^= k1;
            }
            h1 ^= data.len() as u32;
            h1 ^= h1 >> 16;
            h1 = h1.wrapping_mul(0x85eb_ca6b);
            h1 ^= h1 >> 13;
            h1 = h1.wrapping_mul(0xc2b2_ae35);
            h1 ^= h1 >> 16;
            h1
        }
        for len in 0..200usize {
            let data: Vec<u8> = (0..len).map(|i| (i * 31 + 7) as u8).collect();
            assert_eq!(
                mmh3_x86_32(&data, 0),
                legacy(&data, 0),
                "divergence at len {len}"
            );
            assert_eq!(mmh3_x86_32(&data, 0xdead_beef), legacy(&data, 0xdead_beef));
        }
    }

    #[test]
    fn shodan_favicon_hash_is_stable() {
        // Deterministic and framing-sensitive (the trailing newline is
        // part of the Shodan convention  -  dropping it changes this).
        let icon = b"\x00\x00\x01\x00\x01\x00\x10\x10fake-ico-bytes";
        let h = shodan_favicon_hash(icon);
        assert_eq!(h, shodan_favicon_hash(icon));
        assert_ne!(h, 0);
    }
}
