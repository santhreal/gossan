//! Blackrock permutation for randomized scan scheduling.
//!
//! Visits every `(IP, port)` pair in a pseudorandom order using a
//! Feistel-network-based permutation. This is the same technique masscan
//! uses to avoid sequential scanning patterns that trigger IDS alerts.
//!
//! Properties:
//! - Bijective: every index maps to a unique output (no collisions, no gaps)
//! - Deterministic: same seed produces same ordering (reproducible scans)
//! - O(1) per lookup: no precomputation needed
//! - Distributes targets evenly across subnets

/// A Feistel-network-based permutation over `[0, range)`.
///
/// Maps each index to a unique pseudorandom output in the same range.
/// Used to randomize scan order without storing the full permutation in memory.
pub struct BlackrockPermutation {
    range: u64,
    half_bits: u32,
    half_mask: u64,
    seed: u64,
    rounds: u32,
}

impl BlackrockPermutation {
    /// Create a new permutation over `[0, range)` with the given seed.
    ///
    /// # Panics
    ///
    /// Panics if `range` is 0.
    #[must_use]
    pub fn new(range: u64, seed: u64) -> Self {
        assert!(range > 0, "range must be > 0");

        // Find the smallest split where left × right >= range
        // We use a balanced Feistel network with equal halves
        let total_bits = 64 - (range - 1).leading_zeros();
        let half_bits = (total_bits + 1) / 2;
        let half_mask = (1u64 << half_bits) - 1;

        Self {
            range,
            half_bits,
            half_mask,
            seed,
            rounds: 6, // 6 rounds is sufficient for good diffusion
        }
    }

    /// Permute index `i` to its randomized output.
    ///
    /// If the output falls outside `[0, range)` (due to the Feistel network
    /// operating on the next power-of-two), we "cycle walk" until we land
    /// inside the valid range.
    #[must_use]
    pub fn shuffle(&self, mut index: u64) -> u64 {
        loop {
            let permuted = self.feistel(index);
            if permuted < self.range {
                return permuted;
            }
            // Cycle walk: try next value
            index = permuted;
        }
    }

    /// Inverse permutation: given an output, recover the original index.
    #[must_use]
    pub fn unshuffle(&self, mut permuted: u64) -> u64 {
        loop {
            let index = self.feistel_inverse(permuted);
            if index < self.range {
                return index;
            }
            permuted = index;
        }
    }

    fn feistel(&self, input: u64) -> u64 {
        let mut left = input >> self.half_bits;
        let mut right = input & self.half_mask;

        for round in 0..self.rounds {
            let new_right = left ^ self.round_function(right, round);
            left = right;
            right = new_right & self.half_mask;
        }

        (left << self.half_bits) | right
    }

    fn feistel_inverse(&self, input: u64) -> u64 {
        let mut left = input >> self.half_bits;
        let mut right = input & self.half_mask;

        for round in (0..self.rounds).rev() {
            let new_left = right ^ self.round_function(left, round);
            right = left;
            left = new_left & self.half_mask;
        }

        (left << self.half_bits) | right
    }

    #[inline]
    fn round_function(&self, value: u64, round: u32) -> u64 {
        // Mix value with seed and round number
        let mut h = value.wrapping_mul(0x9E37_79B9_7F4A_7C15);
        h = h.wrapping_add(self.seed);
        h = h.wrapping_add(round as u64);
        h ^= h >> 17;
        h = h.wrapping_mul(0xBF58_476D_1CE4_E5B9);
        h ^= h >> 31;
        h
    }
}

/// Iterator that yields `(ip_index, port_index)` pairs in randomized order.
///
/// Given `N` IPs and `P` ports, iterates all `N × P` combinations
/// exactly once in a pseudorandom order.
pub struct ScanSchedule {
    permutation: BlackrockPermutation,
    num_ports: u64,
    total: u64,
    current: u64,
}

impl ScanSchedule {
    /// Create a scan schedule over `num_ips × num_ports` targets.
    #[must_use]
    pub fn new(num_ips: u64, num_ports: u64, seed: u64) -> Self {
        let total = num_ips.saturating_mul(num_ports);
        let permutation = if total > 0 {
            BlackrockPermutation::new(total, seed)
        } else {
            BlackrockPermutation::new(1, seed)
        };

        Self {
            permutation,
            num_ports,
            total,
            current: 0,
        }
    }

    /// Total number of probes in this schedule.
    #[must_use]
    pub fn total(&self) -> u64 {
        self.total
    }
}

impl Iterator for ScanSchedule {
    type Item = (u64, u64); // (ip_index, port_index)

    fn next(&mut self) -> Option<Self::Item> {
        if self.current >= self.total {
            return None;
        }

        let permuted = self.permutation.shuffle(self.current);
        self.current += 1;

        let ip_index = permuted / self.num_ports;
        let port_index = permuted % self.num_ports;
        Some((ip_index, port_index))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = (self.total - self.current) as usize;
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for ScanSchedule {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn permutation_is_bijective_small() {
        let range = 100u64;
        let perm = BlackrockPermutation::new(range, 42);
        let mut seen = HashSet::new();

        for i in 0..range {
            let out = perm.shuffle(i);
            assert!(out < range, "output {out} >= range {range} for input {i}");
            assert!(seen.insert(out), "duplicate output {out} for input {i}");
        }
        assert_eq!(seen.len(), range as usize);
    }

    #[test]
    fn permutation_is_bijective_large() {
        let range = 10_000u64;
        let perm = BlackrockPermutation::new(range, 0xDEAD_BEEF);
        let mut seen = HashSet::new();

        for i in 0..range {
            let out = perm.shuffle(i);
            assert!(out < range);
            seen.insert(out);
        }
        assert_eq!(seen.len(), range as usize);
    }

    #[test]
    fn permutation_is_deterministic() {
        let perm = BlackrockPermutation::new(1000, 42);
        let a = perm.shuffle(500);
        let b = perm.shuffle(500);
        assert_eq!(a, b);
    }

    #[test]
    fn permutation_differs_by_seed() {
        let a = BlackrockPermutation::new(1000, 1);
        let b = BlackrockPermutation::new(1000, 2);
        // Very unlikely (but not impossible) for all outputs to match
        let mismatches = (0..1000).filter(|&i| a.shuffle(i) != b.shuffle(i)).count();
        assert!(mismatches > 900, "seeds should produce different orderings");
    }

    #[test]
    fn permutation_roundtrip() {
        let perm = BlackrockPermutation::new(500, 99);
        for i in 0..500 {
            let shuffled = perm.shuffle(i);
            let unshuffled = perm.unshuffle(shuffled);
            assert_eq!(unshuffled, i, "roundtrip failed for {i}");
        }
    }

    #[test]
    fn schedule_covers_all_targets() {
        let num_ips = 10u64;
        let num_ports = 5u64;
        let schedule = ScanSchedule::new(num_ips, num_ports, 42);
        let pairs: Vec<_> = schedule.collect();

        assert_eq!(pairs.len(), 50);

        let mut seen = HashSet::new();
        for (ip, port) in &pairs {
            assert!(*ip < num_ips, "ip {ip} >= {num_ips}");
            assert!(*port < num_ports, "port {port} >= {num_ports}");
            assert!(seen.insert((*ip, *port)), "duplicate ({ip}, {port})");
        }
        assert_eq!(seen.len(), 50);
    }

    #[test]
    fn schedule_exact_size() {
        let schedule = ScanSchedule::new(100, 20, 42);
        assert_eq!(schedule.len(), 2000);
        assert_eq!(schedule.total(), 2000);
    }

    #[test]
    fn schedule_is_not_sequential() {
        let schedule = ScanSchedule::new(100, 10, 42);
        let first_ten: Vec<_> = schedule.take(10).collect();

        // Check that ip_indices are not monotonically increasing
        let sequential = first_ten.windows(2).all(|w| w[0].0 <= w[1].0);
        assert!(!sequential, "schedule should not be sequential: {first_ten:?}");
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn permutation_stays_in_range(
            range in 1u64..10_000,
            seed in any::<u64>(),
            index in 0u64..10_000,
        ) {
            let index = index % range;
            let perm = BlackrockPermutation::new(range, seed);
            let out = perm.shuffle(index);
            prop_assert!(out < range, "output {out} >= range {range}");
        }

        #[test]
        fn permutation_roundtrips(
            range in 1u64..1_000,
            seed in any::<u64>(),
            index in 0u64..1_000,
        ) {
            let index = index % range;
            let perm = BlackrockPermutation::new(range, seed);
            let shuffled = perm.shuffle(index);
            let back = perm.unshuffle(shuffled);
            prop_assert_eq!(back, index);
        }
    }
}
