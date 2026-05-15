//! WHOIS-based ownership correlation for sibling domain discovery.

use gossan_core::reqwest::Client;

/// Discovers sibling root domains sharing ownership attributes via reverse WHOIS.
pub async fn get_sibling_domains(client: &Client, domain: &str) -> anyhow::Result<Vec<String>> {
    // We'll use reverse host discovery as a proxy for ownership mapping
    let url = format!("https://api.hackertarget.com/reverseiplookup/?q={}", domain);
    let resp = {
        let r = client.get(&url).send().await?;
        gossan_core::net::bounded_text(r, 1 * 1024 * 1024).await?
    };

    let domains = parse_reverseip_response(&resp);

    Ok(domains)
}

/// Parse reverseiplookup response into domain list.
pub(crate) fn parse_reverseip_response(resp: &str) -> Vec<String> {
    resp.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| l.trim().to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_reverseip_handles_empty_and_lines() {
        let resp = "example.com\n\nsub.example.com\n ";
        let v = parse_reverseip_response(resp);
        assert_eq!(
            v,
            vec!["example.com".to_string(), "sub.example.com".to_string()]
        );

        let empty = "";
        let v2 = parse_reverseip_response(empty);
        assert!(v2.is_empty());
    }
}
