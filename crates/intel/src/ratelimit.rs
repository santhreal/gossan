//! Per-service async rate limiting.

use std::num::NonZeroU32;
use std::sync::Arc;

use governor::state::keyed::DefaultKeyedStateStore;
use governor::{DefaultDirectRateLimiter, Quota, RateLimiter};

/// A keyed rate limiter where each service gets its own token bucket.
pub type ServiceRateLimiter =
    RateLimiter<String, DefaultKeyedStateStore<String>, governor::clock::DefaultClock>;

/// Build a rate limiter with a per-second quota.
///
/// Zero rates are coerced to 1 (the smallest non-zero quota) so callers
/// passing 0 by accident don't crash; if you want unlimited, build a
/// noop limiter at the call site instead.
pub fn build_limiter(per_second: u32) -> Arc<ServiceRateLimiter> {
    let n = NonZeroU32::new(per_second.max(1))
        .unwrap_or(NonZeroU32::MIN);
    let quota = Quota::per_second(n);
    Arc::new(ServiceRateLimiter::keyed(quota))
}

/// Acquire a permit for the given service key, asynchronously if needed.
pub async fn acquire(limiter: &Arc<ServiceRateLimiter>, key: &str) {
    limiter.until_key_ready(&key.to_string()).await;
}
