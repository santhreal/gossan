//! ASN resolution and BGP prefix lookup.

use gossan_core::reqwest::Client;

/// Retrieves all BGP prefixes associated with the ASN of the given IP.
pub async fn get_prefixes_for_ip(client: &Client, ip: &str) -> anyhow::Result<Vec<String>> {
    let asn = lookup_asn(client, ip).await?;
    get_prefixes_for_asn(client, &asn).await
}

/// Parse a HackerTarget ASN lookup response of the form "IP, ASN, Org"
/// Returns the ASN if present.
pub(crate) fn parse_asn_response(resp: &str) -> Option<String> {
    resp.split(',')
        .nth(1)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Look up the ASN for a given IP address via HackerTarget.
async fn lookup_asn(client: &Client, ip: &str) -> anyhow::Result<String> {
    let url = format!("https://api.hackertarget.com/aslookup/?q={}", ip);
    let resp = {
        let r = client.get(&url).send().await?;
        gossan_core::net::bounded_text(r, 1 * 1024 * 1024).await?
    };

    if let Some(asn) = parse_asn_response(&resp) {
        return Ok(asn);
    }
    anyhow::bail!("Failed to lookup ASN for {}", ip)
}

/// Parse a HackerTarget AS/prefix list response where each line is a prefix.
pub(crate) fn parse_prefixes_response(resp: &str) -> Vec<String> {
    resp.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| l.trim().to_string())
        .collect()
}

/// Retrieve all IPv4 prefixes for a given ASN via HackerTarget.
async fn get_prefixes_for_asn(client: &Client, asn: &str) -> anyhow::Result<Vec<String>> {
    let url = format!("https://api.hackertarget.com/aslookup/?q={}", asn);
    let resp = {
        let r = client.get(&url).send().await?;
        gossan_core::net::bounded_text(r, 1 * 1024 * 1024).await?
    };

    let prefixes = parse_prefixes_response(&resp);

    Ok(prefixes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_asn_handles_valid_and_invalid() {
        let good = "1.2.3.4, AS12345, Some Org";
        assert_eq!(parse_asn_response(good), Some("AS12345".to_string()));

        let bad = "no-asn-here";
        assert_eq!(parse_asn_response(bad), None);

        let empty = "";
        assert_eq!(parse_asn_response(empty), None);
    }

    #[test]
    fn parse_prefixes_handles_lines_and_whitespace() {
        let resp = "192.0.2.0/24\n\n198.51.100.0/24\n ";
        let v = parse_prefixes_response(resp);
        assert_eq!(
            v,
            vec!["192.0.2.0/24".to_string(), "198.51.100.0/24".to_string()]
        );
    }
}
