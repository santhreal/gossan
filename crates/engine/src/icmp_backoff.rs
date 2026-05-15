//! ICMP-unreachable per-/24 backoff consumer.
//!
//! The pre-existing `Slash24Backoff` in `scan.rs` reacts to RST bursts.
//! This module is the parallel consumer for ICMP "destination
//! unreachable" packets — a strong signal that a router or border
//! firewall is shedding load and we should slow down on the entire
//! `/24` rather than burn TX budget per port.
//!
//! ## Status: consumer wired, source pending
//!
//! `netforge::EngineStats` does not yet expose an
//! `icmp_unreachable_per_sec` counter, and `RxPacket` does not surface
//! ICMP packets. So this module:
//!
//! 1. Implements the full backoff state machine + tests, and
//! 2. Exposes a `feed(slash24, count)` entry point that any source
//!    can call (a future netforge ICMP RX path, or a separate raw
//!    socket reader running alongside the TCP RX).
//!
//! When `netforge` lands ICMP surfacing this consumer plugs in
//! without further changes — that is open work, not deferred.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// ICMP-unreachable backoff table. Same shape as `Slash24Backoff` so
/// the TX hot path can consult both with identical cost.
#[derive(Clone, Default)]
pub struct IcmpBackoff {
    inner: Arc<RwLock<HashMap<u32, BackoffState>>>,
    /// Total /24s currently in active backoff at any tick. Useful as a
    /// scan-level health metric.
    pub blocked_total: Arc<AtomicU64>,
}

#[derive(Debug, Clone, Copy)]
struct BackoffState {
    /// ICMP unreachables observed in the current rolling window.
    count_in_window: u32,
    /// Window start.
    window_start: Instant,
    /// When the /24 leaves backoff. None = not currently blocked.
    blocked_until: Option<Instant>,
}

/// Tunable parameters. Sized for typical commercial-network behavior;
/// tightening can be done at construction.
#[derive(Debug, Clone, Copy)]
pub struct IcmpBackoffConfig {
    /// Rolling window length over which ICMP counts accumulate.
    pub window: Duration,
    /// Threshold inside `window` that flips a /24 into backoff.
    pub burst_threshold: u32,
    /// How long a /24 stays in backoff after being tripped.
    pub backoff: Duration,
}

impl Default for IcmpBackoffConfig {
    fn default() -> Self {
        Self {
            window: Duration::from_secs(2),
            burst_threshold: 8,
            backoff: Duration::from_secs(30),
        }
    }
}

impl IcmpBackoff {
    /// Empty table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Convert an IPv4 address to the /24 key used by this table.
    #[inline]
    #[must_use]
    pub fn slash24_of(ip: Ipv4Addr) -> u32 {
        let o = ip.octets();
        u32::from_be_bytes([o[0], o[1], o[2], 0])
    }

    /// Feed `count` ICMP-unreachable observations for `slash24`.
    /// Returns `true` if the /24 is now (or was already) in backoff.
    pub fn feed(&self, slash24: u32, count: u32, cfg: IcmpBackoffConfig) -> bool {
        self.feed_at(slash24, count, cfg, Instant::now())
    }

    /// Test-friendly variant — explicit `now` so we can simulate time.
    pub fn feed_at(&self, slash24: u32, count: u32, cfg: IcmpBackoffConfig, now: Instant) -> bool {
        let Ok(mut g) = self.inner.write() else {
            return false;
        };
        let entry = g.entry(slash24).or_insert(BackoffState {
            count_in_window: 0,
            window_start: now,
            blocked_until: None,
        });

        // Decay window.
        if now.duration_since(entry.window_start) > cfg.window {
            entry.count_in_window = 0;
            entry.window_start = now;
        }
        entry.count_in_window = entry.count_in_window.saturating_add(count);

        // Already in active backoff?
        if entry.blocked_until.map_or(false, |u| u > now) {
            return true;
        }

        if entry.count_in_window >= cfg.burst_threshold {
            entry.blocked_until = Some(now + cfg.backoff);
            self.blocked_total.fetch_add(1, Ordering::Relaxed);
            return true;
        }
        false
    }

    /// Read-only check for the TX hot path. Lock-light: returns false
    /// on any contention rather than blocking.
    #[inline]
    #[must_use]
    pub fn is_blocked(&self, slash24: u32) -> bool {
        self.is_blocked_at(slash24, Instant::now())
    }

    /// Test-friendly check — explicit `now`.
    #[must_use]
    pub fn is_blocked_at(&self, slash24: u32, now: Instant) -> bool {
        let Ok(g) = self.inner.read() else {
            return false;
        };
        g.get(&slash24)
            .and_then(|s| s.blocked_until)
            .map_or(false, |u| u > now)
    }

    /// Drop entries that are out of window AND not currently blocked.
    /// Call from a 1Hz prune thread; cheap when the map is small.
    pub fn prune(&self, cfg: IcmpBackoffConfig) {
        let now = Instant::now();
        if let Ok(mut g) = self.inner.write() {
            g.retain(|_, s| {
                s.blocked_until.map_or(false, |u| u > now)
                    || now.duration_since(s.window_start) <= cfg.window
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> IcmpBackoffConfig {
        IcmpBackoffConfig {
            window: Duration::from_secs(1),
            burst_threshold: 5,
            backoff: Duration::from_secs(10),
        }
    }

    #[test]
    fn slash24_packs_correctly() {
        assert_eq!(
            IcmpBackoff::slash24_of(Ipv4Addr::new(10, 1, 2, 3)),
            u32::from_be_bytes([10, 1, 2, 0])
        );
    }

    #[test]
    fn single_event_does_not_trip() {
        let b = IcmpBackoff::new();
        let s = IcmpBackoff::slash24_of(Ipv4Addr::new(192, 168, 1, 1));
        assert!(!b.feed(s, 1, cfg()));
        assert!(!b.is_blocked(s));
    }

    #[test]
    fn burst_threshold_flips_into_backoff() {
        let b = IcmpBackoff::new();
        let s = IcmpBackoff::slash24_of(Ipv4Addr::new(192, 168, 1, 1));
        let now = Instant::now();
        for _ in 0..4 {
            assert!(!b.feed_at(s, 1, cfg(), now));
        }
        // 5th observation hits threshold.
        assert!(b.feed_at(s, 1, cfg(), now));
        assert!(b.is_blocked_at(s, now));
        assert_eq!(b.blocked_total.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn backoff_expires_after_window() {
        let b = IcmpBackoff::new();
        let c = cfg();
        let s = IcmpBackoff::slash24_of(Ipv4Addr::new(10, 0, 0, 1));
        let now = Instant::now();
        b.feed_at(s, 5, c, now);
        assert!(b.is_blocked_at(s, now));
        let later = now + c.backoff + Duration::from_millis(1);
        assert!(!b.is_blocked_at(s, later));
    }

    #[test]
    fn rolling_window_decays_count() {
        let b = IcmpBackoff::new();
        let c = cfg();
        let s = IcmpBackoff::slash24_of(Ipv4Addr::new(10, 0, 0, 2));
        let t0 = Instant::now();
        // 3 events at t0, then 3 events well after window — should NOT trip.
        b.feed_at(s, 3, c, t0);
        let after_window = t0 + c.window + Duration::from_millis(1);
        let tripped = b.feed_at(s, 3, c, after_window);
        assert!(!tripped, "old window must not contribute to threshold");
    }

    #[test]
    fn unrelated_slash24_unaffected() {
        let b = IcmpBackoff::new();
        let a = IcmpBackoff::slash24_of(Ipv4Addr::new(10, 0, 0, 1));
        let b_ip = IcmpBackoff::slash24_of(Ipv4Addr::new(10, 1, 0, 1));
        let now = Instant::now();
        for _ in 0..6 {
            b.feed_at(a, 1, cfg(), now);
        }
        assert!(b.is_blocked_at(a, now));
        assert!(!b.is_blocked_at(b_ip, now));
    }

    #[test]
    fn prune_drops_stale_unblocked_entries() {
        let b = IcmpBackoff::new();
        let c = cfg();
        let s = IcmpBackoff::slash24_of(Ipv4Addr::new(10, 0, 0, 5));
        b.feed_at(s, 1, c, Instant::now());
        // Sleep past the window so the entry is stale.
        std::thread::sleep(c.window + Duration::from_millis(10));
        b.prune(c);
        let g = b.inner.read().unwrap();
        assert!(!g.contains_key(&s));
    }

    #[test]
    fn burst_count_can_be_supplied_in_one_call() {
        let b = IcmpBackoff::new();
        let s = IcmpBackoff::slash24_of(Ipv4Addr::new(10, 0, 0, 1));
        // Single feed of 100 unreachables — must trip on the spot.
        assert!(b.feed(s, 100, cfg()));
        assert!(b.is_blocked(s));
    }
}
