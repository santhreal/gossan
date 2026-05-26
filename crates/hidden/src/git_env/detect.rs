//! Detection logic for catch-all servers.

/// Checks if the server returns 200 for a clearly non-existent path.
pub async fn is_catch_all(
    client: &reqwest::Client,
    base: &str,
    rate_limiter: &crate::HostRateLimiter,
    host: &str,
) -> bool {
    let probe_url = format!("{}/.gossan-probe-nonexistent-xkcd7392/", base);
    rate_limiter.wait_for_host(host).await;
    match client.get(&probe_url).send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            rate_limiter.observe_status(host, status).await;
            status == 200
        }
        Err(_) => false,
    }
}
