//! Quake (360) subdomain enumeration.
//! Requires a Quake API key.
//! Set via $QUAKE_API_KEY env var or config.api_keys.quake.

use gossan_core::{
    send_with_backoff, Config, DiscoverySource, DomainTarget, HostRateLimiter, Target,
};
use serde::{Deserialize, Serialize};

use crate::is_subdomain_of;

#[derive(Serialize)]
struct RequestBody {
    query: String,
    start: i32,
    size: i32,
}

#[derive(Deserialize)]
struct Response {
    data: Vec<DataItem>,
}

#[derive(Deserialize)]
struct DataItem {
    service: Service,
}

#[derive(Deserialize)]
struct Service {
    http: Option<Http>,
}

#[derive(Deserialize)]
struct Http {
    host: Option<String>,
}

pub async fn query(
    domain: &str,
    config: &Config,
    client: &reqwest::Client,
    rate_limiter: &HostRateLimiter,
) -> anyhow::Result<Vec<Target>> {
    let Some(api_key) = config.api_keys.quake.as_deref() else {
        return Ok(vec![]);
    };

    let url = "https://quake.360.net/api/v3/search/quake_service";
    let body = RequestBody {
        query: format!("domain:{}", domain),
        start: 0,
        size: 1000,
    };

    let resp: Response = send_with_backoff(url, Some(rate_limiter), || async {
        Ok::<reqwest::Response, anyhow::Error>(
            client
                .post(url)
                .header("X-QuakeToken", api_key)
                .json(&body)
                .send()
                .await?,
        )
    })
    .await?
    .json()
    .await?;

    let targets = resp
        .data
        .into_iter()
        .filter_map(|item| item.service.http.and_then(|h| h.host))
        .map(|host| host.trim().to_lowercase())
        .filter(|h| is_subdomain_of(h, domain))
        .map(|h| {
            Target::Domain(DomainTarget {
                domain: h,
                source: DiscoverySource::Quake,
            })
        })
        .collect();

    Ok(targets)
}
