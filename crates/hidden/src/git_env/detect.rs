//! Detection logic for catch-all servers.

/// Checks whether the server is a catch-all (200 for nonexistent paths).
///
/// Delegates to the unified [`crate::soft404`] baseline so git/env probes
/// share one owner for catch-all detection instead of a weaker single-probe
/// status==200 heuristic.
pub async fn is_catch_all(
    client: &reqwest::Client,
    base: &str,
    rate_limiter: &crate::HostRateLimiter,
    host: &str,
) -> bool {
    rate_limiter.wait_for_host(host).await;
    let baseline = crate::soft404::establish(client, base).await;
    if let Some(ref fp) = baseline {
        rate_limiter.observe_status(host, fp.status).await;
    }
    crate::soft404::is_catch_all(baseline.as_ref())
}
