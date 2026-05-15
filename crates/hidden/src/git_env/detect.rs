//! Detection logic for catch-all servers.

/// Checks if the server returns 200 for a clearly non-existent path.
pub async fn is_catch_all(client: &reqwest::Client, base: &str) -> bool {
    let probe_url = format!("{}/.gossan-probe-nonexistent-xkcd7392/", base);
    client
        .get(&probe_url)
        .send()
        .await
        .map(|r| r.status().as_u16() == 200)
        .unwrap_or(false)
}
