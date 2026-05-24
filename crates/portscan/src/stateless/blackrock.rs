//! Stateless address-space permutation (masscan's "blackrock").
//!
//! To scan `N = ips × ports` targets in a pseudo-random, non-repeating
//! order *without storing an N-element shuffled list*, encrypt the
//! index `i ∈ [0, N)` with a tiny keyed block cipher whose block size
//! is exactly `N`. A small-domain unbalanced Feistel network is a
//! bijection on `[0, a·b)` (with `a·b ≥ N`); cycle-walking maps it down
//! to a bijection on `[0, N)`. Iterating `i = 0..N` and emitting
//! `shuffle(i)` therefore yields every target exactly once in an
//! attacker-unpredictable order with O(1) memory.
//!
//! This is the masscan `ENCRYPT` construction. Correctness (that it is
//! a true permutation for every domain shape) is asserted exhaustively
//! by the tests  -  the test is the contract; a failure means the cipher
//! is wrong and must be fixed, never the test.

/// A keyed permutation over `[0, range)`.
#[derive(Clone)]
pub struct Blackrock {
    range: u64,
    a: u64,
    b: u64,
    rounds: u32,
    seed: u64,
}

#[inline]
fn mix(mut z: u64) -> u64 {
    // splitmix64 finaliser  -  a good, cheap, dependency-free PRF body.
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

impl Blackrock {
    /// Permutation of `[0, range)` keyed by `seed`. `range == 0` is
    /// treated as an empty permutation.
    #[must_use]
    pub fn new(range: u64, seed: u64) -> Self {
        // a = floor(sqrt(range)); grow b until a·b ≥ range so the
        // Feistel domain [0, a·b) covers the range (cycle-walk handles
        // the [range, a·b) overflow).
        let mut a = (range as f64).sqrt() as u64;
        if a == 0 {
            a = 1;
        }
        let mut b = a;
        while a.saturating_mul(b) < range {
            b += 1;
        }
        Self {
            range,
            a,
            b,
            rounds: 4,
            seed,
        }
    }

    #[inline]
    fn f(&self, round: u32, r: u64) -> u64 {
        mix(r ^ self.seed ^ ((round as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15)))
    }

    fn encrypt(&self, m: u64) -> u64 {
        let mut l = m % self.a;
        let mut r = m / self.a;
        for j in 1..=self.rounds {
            let tmp = if j & 1 == 1 {
                (l + self.f(j, r)) % self.a
            } else {
                (l + self.f(j, r)) % self.b
            };
            l = r;
            r = tmp;
        }
        if self.rounds & 1 == 1 {
            self.a * l + r
        } else {
            self.a * r + l
        }
    }

    /// The image of `index` under the permutation. `index` must be in
    /// `[0, range)`; out-of-range input returns it unchanged (callers
    /// only ever feed `0..range`).
    #[must_use]
    pub fn shuffle(&self, index: u64) -> u64 {
        if index >= self.range {
            return index;
        }
        let mut c = self.encrypt(index);
        // Cycle-walk: stay in the cipher's domain until we land back
        // inside [0, range). Guaranteed to terminate because encrypt is
        // a bijection on [0, a·b) and the orbit is finite.
        while c >= self.range {
            c = self.encrypt(c);
        }
        c
    }

    /// Iterate every value in `[0, range)` exactly once, permuted.
    pub fn iter(&self) -> impl Iterator<Item = u64> + '_ {
        (0..self.range).map(move |i| self.shuffle(i))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn assert_is_permutation(range: u64, seed: u64) {
        let br = Blackrock::new(range, seed);
        let mut seen = HashSet::with_capacity(range as usize);
        for i in 0..range {
            let v = br.shuffle(i);
            assert!(v < range, "range={range} seed={seed}: {i}->{v} out of range");
            assert!(
                seen.insert(v),
                "range={range} seed={seed}: collision at output {v}"
            );
        }
        assert_eq!(seen.len() as u64, range, "range={range}: not surjective");
    }

    #[test]
    fn is_a_bijection_for_many_domain_shapes() {
        // perfect square, prime, even, odd, power of two, small, 1
        for &range in &[1u64, 2, 3, 7, 16, 100, 256, 999, 1000, 1024, 4096, 65521] {
            for &seed in &[0u64, 1, 0xdead_beef, 0xffff_ffff_ffff_ffff] {
                assert_is_permutation(range, seed);
            }
        }
    }

    #[test]
    fn deterministic_per_seed() {
        let a = Blackrock::new(10_000, 12345);
        let b = Blackrock::new(10_000, 12345);
        for i in (0..10_000).step_by(97) {
            assert_eq!(a.shuffle(i), b.shuffle(i));
        }
    }

    #[test]
    fn different_seeds_produce_different_orderings() {
        let a: Vec<u64> = Blackrock::new(5000, 1).iter().take(64).collect();
        let b: Vec<u64> = Blackrock::new(5000, 2).iter().take(64).collect();
        assert_ne!(a, b, "distinct seeds must reorder the space");
    }

    #[test]
    fn not_the_identity_permutation() {
        // A scan order equal to 0,1,2,3,… would hammer hosts
        // sequentially  -  defeating the whole point.
        let br = Blackrock::new(4096, 0xabcd);
        let identity = (0..64).all(|i| br.shuffle(i) == i);
        assert!(!identity, "permutation collapsed to identity");
    }

    #[test]
    fn empty_and_singleton_ranges_are_safe() {
        assert_eq!(Blackrock::new(0, 9).iter().count(), 0);
        let one: Vec<u64> = Blackrock::new(1, 9).iter().collect();
        assert_eq!(one, vec![0]);
    }
}
