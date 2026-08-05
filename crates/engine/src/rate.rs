//! Token-bucket rate limiter with sub-microsecond precision.
//!
//! Controls packet transmission rate to avoid overwhelming the NIC or
//! triggering upstream rate limits. Uses `Instant` for high-resolution
//! timing without syscall overhead.

use std::time::Instant;

/// Token-bucket rate limiter.
///
/// Refills at `rate_pps` tokens per second. Each `consume()` call
/// blocks until a token is available, providing smooth rate control.
///
/// Internal scaling: we represent both the bucket and the refill in
/// units of `1 token = SCALE`. Since refill comes in tokens-per-μs
/// (= rate_pps / 1_000_000), we pick `SCALE = 1_000_000` so the
/// per-μs refill in scaled units equals `rate_pps` exactly, no
/// truncation for rates below 1000 pps, no 1000× overshoot for
/// rates at or above 1000 pps. Earlier scaling used `SCALE = 1000`
/// and stored `rate_pps` in `refill_per_us_x1000` directly, which
/// was 1000× too fast at every rate ≥ 1000 pps.
pub struct RateLimiter {
    /// Tokens available (scaled by SCALE = 1_000_000 for sub-token precision).
    tokens_x1m: i64,
    /// Maximum tokens (burst capacity, in scaled units).
    max_tokens_x1m: i64,
    /// Tokens added per microsecond (scaled by SCALE).
    refill_per_us_x1m: i64,
    /// Last refill time.
    last_refill: Instant,
    /// Target rate in packets per second.
    rate_pps: u64,
}

const TOKEN_SCALE: i64 = 1_000_000;

impl RateLimiter {
    /// Create a new rate limiter.
    ///
    /// - `rate_pps`: target packets per second (0 = unlimited)
    /// - `burst`: maximum burst size in packets
    #[must_use]
    pub fn new(rate_pps: u64, burst: u64) -> Self {
        let burst = burst.max(1).min(i64::MAX as u64 / TOKEN_SCALE as u64);
        let refill_per_us_x1m = if rate_pps == 0 {
            i64::MAX / 2 // Effectively unlimited
        } else {
            // rate_pps tokens/sec = rate_pps / 1_000_000 tokens/μs.
            // In SCALE = 1_000_000 units that is exactly rate_pps.
            // Cap to i64::MAX before casting to avoid wrap-around on u64::MAX.
            rate_pps.min(i64::MAX as u64).max(1) as i64
        };

        Self {
            tokens_x1m: (burst as i64) * TOKEN_SCALE,
            max_tokens_x1m: (burst as i64) * TOKEN_SCALE,
            refill_per_us_x1m,
            last_refill: Instant::now(),
            rate_pps,
        }
    }

    /// Create an unlimited rate limiter (no throttling).
    #[must_use]
    pub fn unlimited() -> Self {
        Self::new(0, u64::MAX / 2)
    }

    /// Try to consume one token. Returns `true` if the token was available.
    /// Does NOT block.
    pub fn try_consume(&mut self) -> bool {
        self.refill();
        if self.tokens_x1m >= TOKEN_SCALE {
            self.tokens_x1m -= TOKEN_SCALE;
            true
        } else {
            false
        }
    }

    /// Try to consume `n` tokens. Returns the number actually consumed.
    pub fn try_consume_batch(&mut self, n: u64) -> u64 {
        self.refill();
        let available = (self.tokens_x1m / TOKEN_SCALE).max(0) as u64;
        let consumed = available.min(n);
        self.tokens_x1m -= (consumed as i64) * TOKEN_SCALE;
        consumed
    }

    /// Block until a token is available, then consume it.
    ///
    /// Uses spin-wait for sub-microsecond precision when the wait is short,
    /// and `thread::yield_now` for longer waits.
    pub fn consume_blocking(&mut self) {
        loop {
            self.refill();
            if self.tokens_x1m >= TOKEN_SCALE {
                self.tokens_x1m -= TOKEN_SCALE;
                return;
            }
            let deficit = TOKEN_SCALE - self.tokens_x1m;
            if self.refill_per_us_x1m > 0 {
                let wait_us = deficit / self.refill_per_us_x1m.max(1);
                if wait_us > 100 {
                    std::thread::yield_now();
                } else {
                    std::hint::spin_loop();
                }
            } else {
                std::hint::spin_loop();
            }
        }
    }

    /// Current target rate.
    #[must_use]
    pub fn rate_pps(&self) -> u64 {
        self.rate_pps
    }

    /// Whether this limiter is unlimited.
    #[must_use]
    pub fn is_unlimited(&self) -> bool {
        self.rate_pps == 0
    }

    /// Re-target the rate at runtime. Used by `AdaptiveLoop` to react
    /// to TX drops / ICMP-unreachable bursts without rebuilding the
    /// limiter (which would lose the bucket fill state and stutter).
    pub fn set_rate_pps(&mut self, rate_pps: u64) {
        self.rate_pps = rate_pps;
        self.refill_per_us_x1m = if rate_pps == 0 {
            i64::MAX / 2
        } else {
            // Cap to i64::MAX before casting to avoid wrap-around on u64::MAX.
            rate_pps.min(i64::MAX as u64).max(1) as i64
        };
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed_us = now.duration_since(self.last_refill).as_micros() as i64;
        if elapsed_us > 0 {
            let new_tokens = elapsed_us.saturating_mul(self.refill_per_us_x1m);
            self.tokens_x1m = self
                .tokens_x1m
                .saturating_add(new_tokens)
                .min(self.max_tokens_x1m);
            self.last_refill = now;
        }
    }
}

/// Minimum pps the adaptive controller will ever set.  Staying above
/// this floor keeps the scan alive against highly congested networks.
pub const ADAPTIVE_MIN_PPS: u64 = 1_000;

/// Number of consecutive clean (drop-free) batches before the additive-
/// increase step fires.  Derived from TCP-style AIMD: a longer streak
/// gives a wider signal window, reducing sensitivity to short noise
/// bursts.
pub const ADAPTIVE_SUCCESS_STREAK_THRESHOLD: u32 = 10;

/// Additive-increase denominator: each streak raises the rate by
/// `max_pps / ADAPTIVE_AI_DIVISOR`.  At 5 % per streak the controller
/// climbs back to ceiling in ~20 × `ADAPTIVE_SUCCESS_STREAK_THRESHOLD`
/// batches, fast enough to exploit recovered bandwidth, slow enough not
/// to re-trigger drops immediately.
pub const ADAPTIVE_AI_DIVISOR: u64 = 20;

/// Multiplicative-decrease numerator (rate ← rate × MD_NUMER /
/// MD_DENOM).  3/4 = 25 % halving, milder than TCP's ×0.5 to reduce
/// latency on transient loss while still signalling back-off clearly.
pub const ADAPTIVE_MD_NUMER: u64 = 3;
pub const ADAPTIVE_MD_DENOM: u64 = 4;

/// Adaptive rate controller that adjusts pps based on observed packet loss.
pub struct AdaptiveRate {
    /// Current target rate.
    current_pps: u64,
    /// Maximum configured rate.
    max_pps: u64,
    /// Minimum rate floor (never goes below `ADAPTIVE_MIN_PPS`).
    min_pps: u64,
    /// Consecutive successful batches.
    success_streak: u32,
    /// Consecutive failed/dropped batches.
    drop_streak: u32,
}

impl AdaptiveRate {
    /// Create a new adaptive rate controller.
    #[must_use]
    pub fn new(max_pps: u64) -> Self {
        // Floor must never exceed the configured ceiling — otherwise the
        // first report_drops() call jumps ABOVE max_pps (rate-limit bypass
        // when operators run --adaptive-rate with CLI default rate 50).
        let min_pps = if max_pps == 0 {
            0
        } else {
            ADAPTIVE_MIN_PPS.min(max_pps).max(1)
        };
        let current_pps = if max_pps == 0 {
            0
        } else {
            (max_pps / 2).max(min_pps).min(max_pps)
        };
        Self {
            current_pps,
            max_pps,
            min_pps,
            success_streak: 0,
            drop_streak: 0,
        }
    }

    /// Report a successful batch (all packets sent).
    pub fn report_success(&mut self) {
        self.drop_streak = 0;
        self.success_streak += 1;

        // Additive increase after the configured streak threshold.
        if self.success_streak >= ADAPTIVE_SUCCESS_STREAK_THRESHOLD {
            self.current_pps = (self.current_pps + self.max_pps / ADAPTIVE_AI_DIVISOR)
                .min(self.max_pps);
            self.success_streak = 0;
        }
    }

    /// Report packet drops.
    pub fn report_drops(&mut self, _drop_count: u64) {
        self.success_streak = 0;
        self.drop_streak += 1;

        // Multiplicative decrease.
        self.current_pps =
            (self.current_pps * ADAPTIVE_MD_NUMER / ADAPTIVE_MD_DENOM).max(self.min_pps);
    }

    /// Current recommended rate.
    #[must_use]
    pub fn current_pps(&self) -> u64 {
        self.current_pps
    }
}

/// Closed-loop wrapper: drives a [`RateLimiter`] from netforge
/// `EngineStats` deltas. Call [`AdaptiveLoop::tick`] every batch.
///
/// Decision rules:
///
/// * `tx_drops` increased since the last tick → packets are being lost
///   on the way out (NIC ring full, kernel back-pressure). Halve the
///   target rate via [`AdaptiveRate::report_drops`].
/// * `tx_drops` flat AND `tx_packets` increased → call
///   [`AdaptiveRate::report_success`]; after 10 clean ticks the rate
///   creeps back up by 5% of the configured ceiling.
/// * The applied rate is propagated to the wrapped [`RateLimiter`] so
///   the per-batch consume path actually slows down.
///
/// This is the interlock between the *observed* loss signal and the
/// *enforced* token bucket. Without it the bucket would stay pegged
/// at the configured ceiling regardless of what the wire is doing.
pub struct AdaptiveLoop {
    rate: AdaptiveRate,
    last_tx_packets: u64,
    last_tx_drops: u64,
    initialized: bool,
}

impl AdaptiveLoop {
    /// Construct with `max_pps` as the ceiling. Initial enforced rate
    /// starts at half (`max_pps / 2`) per [`AdaptiveRate::new`].
    #[must_use]
    pub fn new(max_pps: u64) -> Self {
        Self {
            rate: AdaptiveRate::new(max_pps),
            last_tx_packets: 0,
            last_tx_drops: 0,
            initialized: false,
        }
    }

    /// Process a fresh stats snapshot and return the enforced rate.
    ///
    /// First call seeds the baseline and returns the initial rate
    /// without classifying anything.
    pub fn tick(&mut self, tx_packets: u64, tx_drops: u64) -> u64 {
        if !self.initialized {
            self.last_tx_packets = tx_packets;
            self.last_tx_drops = tx_drops;
            self.initialized = true;
            return self.rate.current_pps();
        }
        let drop_delta = tx_drops.saturating_sub(self.last_tx_drops);
        let packet_delta = tx_packets.saturating_sub(self.last_tx_packets);
        if drop_delta > 0 {
            self.rate.report_drops(drop_delta);
        } else if packet_delta > 0 {
            self.rate.report_success();
        }
        self.last_tx_packets = tx_packets;
        self.last_tx_drops = tx_drops;
        self.rate.current_pps()
    }

    /// Apply the loop's current target to a [`RateLimiter`]. Call
    /// after every tick (cheap (one assignment) and safe).
    pub fn apply(&self, limiter: &mut RateLimiter) {
        limiter.set_rate_pps(self.rate.current_pps());
    }

    /// Current enforced rate.
    #[must_use]
    pub fn current_pps(&self) -> u64 {
        self.rate.current_pps()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limiter_unlimited_always_succeeds() {
        let mut rl = RateLimiter::unlimited();
        for _ in 0..10_000 {
            assert!(rl.try_consume());
        }
    }

    #[test]
    fn rate_limiter_respects_burst() {
        let mut rl = RateLimiter::new(1_000_000, 10);
        // Should be able to consume burst immediately
        for i in 0..10 {
            assert!(rl.try_consume(), "failed at burst token {i}");
        }
        // Next one might fail (no time for refill)
        // (depending on timing, this is non-deterministic, so we just check burst worked)
    }

    #[test]
    fn rate_limiter_batch_consume() {
        // Rate kept very low (10 pps) so refill between the two
        // synchronous calls is effectively zero; otherwise at 1M pps
        // the bucket refills to `burst` in microseconds and the second
        // batch happily consumes the full 100, not the 50 the test
        // claims it should.
        let mut rl = RateLimiter::new(10, 100);
        let consumed = rl.try_consume_batch(50);
        assert_eq!(consumed, 50);
        let consumed2 = rl.try_consume_batch(100);
        assert_eq!(consumed2, 50); // Only 50 remaining from burst
    }

    #[test]
    fn adaptive_rate_decreases_on_drops() {
        let mut ar = AdaptiveRate::new(1_000_000);
        let initial = ar.current_pps();
        ar.report_drops(100);
        assert!(ar.current_pps() < initial);
    }

    #[test]
    fn adaptive_rate_increases_on_success() {
        let mut ar = AdaptiveRate::new(1_000_000);
        let initial = ar.current_pps();
        for _ in 0..20 {
            ar.report_success();
        }
        assert!(ar.current_pps() > initial);
    }

    #[test]
    fn adaptive_rate_never_below_floor() {
        let mut ar = AdaptiveRate::new(1_000_000);
        for _ in 0..100 {
            ar.report_drops(1000);
        }
        assert!(ar.current_pps() >= 1000);
    }

    #[test]
    fn set_rate_pps_changes_refill() {
        let mut r = RateLimiter::new(1_000, 100);
        assert_eq!(r.rate_pps(), 1_000);
        r.set_rate_pps(500);
        assert_eq!(r.rate_pps(), 500);
        // zero must put the limiter into unlimited mode
        r.set_rate_pps(0);
        assert!(r.is_unlimited());
    }

    #[test]
    fn adaptive_loop_initial_tick_is_baseline_only() {
        let mut lo = AdaptiveLoop::new(1_000_000);
        let initial = lo.current_pps();
        // First tick: no classification, just baseline capture.
        let returned = lo.tick(0, 0);
        assert_eq!(returned, initial);
    }

    #[test]
    fn adaptive_loop_decreases_on_tx_drop_burst() {
        let mut lo = AdaptiveLoop::new(1_000_000);
        let before = lo.tick(0, 0); // baseline
                                    // 1000 packets sent, 50 dropped (classifier sees drops).
        let after = lo.tick(1000, 50);
        assert!(
            after < before,
            "expected rate to decrease: {after} < {before}"
        );
    }

    #[test]
    fn adaptive_loop_increases_after_clean_streak() {
        let mut lo = AdaptiveLoop::new(1_000_000);
        lo.tick(0, 0); // baseline
        let before = lo.current_pps();
        for i in 1..=15 {
            // 100 packets per tick, no drops.
            lo.tick(i * 100, 0);
        }
        assert!(
            lo.current_pps() > before,
            "expected rate to increase after streak: {} > {before}",
            lo.current_pps()
        );
    }

    #[test]
    fn adaptive_loop_apply_propagates_to_limiter() {
        let mut lo = AdaptiveLoop::new(1_000_000);
        let mut limiter = RateLimiter::new(1_000_000, 1000);
        lo.tick(0, 0);
        // Force a drop tick.
        lo.tick(1000, 100);
        lo.apply(&mut limiter);
        assert_eq!(limiter.rate_pps(), lo.current_pps());
    }

    /// Real-rate test: configure a known rate, drain the bucket, then
    /// measure how many tokens we can claim over a short window. Pre-
    /// fix the math left `refill_per_us_x1000 = rate_pps` instead of
    /// `rate_pps / 1000`, which means at e.g. 10_000 pps configured
    /// we actually let through ~10 million pps.
    #[test]
    fn rate_limiter_actually_throttles_to_configured_rate() {
        use std::time::{Duration, Instant};
        const CONFIGURED_PPS: u64 = 10_000;
        // Tiny burst so the bucket drains quickly, we want to
        // measure the steady-state refill rate, not burst capacity.
        let mut rl = RateLimiter::new(CONFIGURED_PPS, 32);

        // Drain the burst so subsequent consume calls are bounded by
        // refill alone.
        while rl.try_consume() {}

        let start = Instant::now();
        let mut consumed: u64 = 0;
        while start.elapsed() < Duration::from_millis(100) {
            if rl.try_consume() {
                consumed += 1;
            } else {
                std::hint::spin_loop();
            }
        }
        let elapsed_ms = start.elapsed().as_millis().max(1) as u64;
        let observed_pps = consumed.saturating_mul(1000) / elapsed_ms;

        // Allow 4× headroom for jitter / timer slop. If the observed
        // rate is more than 4× the configured rate the math is wrong.
        let upper_bound = CONFIGURED_PPS * 4;
        assert!(
            observed_pps <= upper_bound,
            "RateLimiter configured at {CONFIGURED_PPS} pps achieved \
             {observed_pps} pps (consumed {consumed} in {elapsed_ms}ms). \
             refill scaling regressed"
        );
    }

    #[test]
    fn adaptive_loop_converges_under_synthetic_loss_pattern() {
        // 50% packet loss → loop must clamp the rate hard.
        let mut lo = AdaptiveLoop::new(10_000_000);
        let start = lo.current_pps();
        for i in 1..=20 {
            lo.tick(i * 1000, i * 500);
        }
        let final_pps = lo.current_pps();
        assert!(
            final_pps < start / 4,
            "expected aggressive decrease: {final_pps} >= {} (start/4)",
            start / 4
        );
    }

    #[test]
    fn rate_limiter_zero_burst_does_not_panic() {
        // Adversarial: burst of zero should be clamped to 1 internally.
        let mut rl = RateLimiter::new(1000, 0);
        assert!(rl.try_consume());
    }

    #[test]
    fn adaptive_rate_zero_max_does_not_panic() {
        // Adversarial: zero max_pps should not panic and must NOT
        // invent a 1000 pps floor above the configured ceiling.
        let mut ar = AdaptiveRate::new(0);
        ar.report_drops(1);
        ar.report_success();
        assert_eq!(ar.current_pps(), 0);
    }

    #[test]
    fn adaptive_rate_floor_never_exceeds_low_ceiling() {
        // CLI default rate is 50; --adaptive-rate must not jump to 1000.
        let mut ar = AdaptiveRate::new(50);
        assert!(ar.current_pps() <= 50);
        ar.report_drops(100);
        assert!(
            ar.current_pps() <= 50,
            "floor must not raise rate above ceiling: {}",
            ar.current_pps()
        );
        assert!(ar.current_pps() >= 1);
    }

    #[test]
    fn rate_limiter_extreme_rate_does_not_panic() {
        // Adversarial: u64::MAX rate_pps should not panic.
        // With extreme rates the limiter caps internally; we only verify no panic.
        let mut rl = RateLimiter::new(u64::MAX, 1);
        let _ = rl.try_consume();
        rl.set_rate_pps(u64::MAX);
        let _ = rl.try_consume();
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn rate_limiter_batch_consume_never_exceeds_available(
            rate in 0u64..1_000_000u64,
            burst in 1u64..1000u64,
            request in 0u64..10_000u64,
        ) {
            let mut rl = RateLimiter::new(rate, burst);
            let first = rl.try_consume_batch(request);
            prop_assert!(first <= request);
            let second = rl.try_consume_batch(request);
            prop_assert!(second <= request);
            // Total consumed should never exceed burst
            prop_assert!(first + second <= burst);
        }

        #[test]
        fn adaptive_rate_pps_stays_in_bounds(
            max_pps in 0u64..10_000_000u64,
            drops in 0u64..1000u64,
            successes in 0u32..50u32,
        ) {
            let mut ar = AdaptiveRate::new(max_pps);
            for _ in 0..successes {
                ar.report_success();
            }
            ar.report_drops(drops);
            let current = ar.current_pps();
            let floor = if max_pps == 0 {
                0
            } else {
                ADAPTIVE_MIN_PPS.min(max_pps).max(1)
            };
            prop_assert!(current <= max_pps, "rate exceeded max: {current} > {max_pps}");
            prop_assert!(current >= floor, "rate below floor: {current} < {floor}");
        }

        #[test]
        fn adaptive_loop_ticks_never_panic(
            max_pps in 0u64..10_000_000u64,
            tx_packets in 0u64..u64::MAX,
            tx_drops in 0u64..u64::MAX,
        ) {
            let mut lo = AdaptiveLoop::new(max_pps);
            lo.tick(tx_packets, tx_drops);
            lo.tick(tx_packets.saturating_add(100), tx_drops);
            let _ = lo.current_pps();
        }
    }
}
