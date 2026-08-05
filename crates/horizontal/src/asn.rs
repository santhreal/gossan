//! ASN resolution and BGP prefix lookup.

use gossan_core::reqwest::{Client, Url};

/// Retrieves all BGP prefixes associated with the ASN of the given IP.
pub async fn get_prefixes_for_ip(client: &Client, ip: &str) -> anyhow::Result<Vec<String>> {
    get_prefixes_for_ip_with_base(client, ip, "https://api.hackertarget.com").await
}

pub async fn get_prefixes_for_ip_with_base(
    client: &Client,
    ip: &str,
    base: &str,
) -> anyhow::Result<Vec<String>> {
    let asn = lookup_asn_with_base(client, ip, base).await?;
    get_prefixes_for_asn_with_base(client, &asn, base).await
}

/// Parse a HackerTarget ASN lookup response of the form "IP, ASN, Org".
/// Returns the ASN only when it matches `AS` followed by digits.
pub fn parse_asn_response(resp: &str) -> Option<String> {
    let asn = resp.split(',').nth(1)?.trim();
    if asn.len() > 2
        && asn.as_bytes()[..2].eq_ignore_ascii_case(b"AS")
        && asn[2..].bytes().all(|b| b.is_ascii_digit())
    {
        Some(asn.to_ascii_uppercase())
    } else {
        None
    }
}

/// Look up the ASN for a given IP address via HackerTarget.
pub async fn lookup_asn(client: &Client, ip: &str) -> anyhow::Result<String> {
    lookup_asn_with_base(client, ip, "https://api.hackertarget.com").await
}

pub async fn lookup_asn_with_base(
    client: &Client,
    ip: &str,
    base: &str,
) -> anyhow::Result<String> {
    let mut url = Url::parse(&format!("{}/aslookup/", base))?;
    url.query_pairs_mut().append_pair("q", ip);
    let resp = {
        let r = client.get(url.as_str()).send().await?;
        gossan_core::net::bounded_text(r, crate::MAX_HORIZONTAL_TEXT_BYTES).await?
    };

    if let Some(asn) = parse_asn_response(&resp) {
        return Ok(asn);
    }
    anyhow::bail!("Failed to lookup ASN for {}", ip)
}

/// Parse a HackerTarget AS/prefix list response where each line is a prefix.
pub fn parse_prefixes_response(resp: &str) -> Vec<String> {
    resp.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| l.trim().to_string())
        .collect()
}

/// Retrieve all IPv4 prefixes for a given ASN via HackerTarget.
pub async fn get_prefixes_for_asn(client: &Client, asn: &str) -> anyhow::Result<Vec<String>> {
    get_prefixes_for_asn_with_base(client, asn, "https://api.hackertarget.com").await
}

pub async fn get_prefixes_for_asn_with_base(
    client: &Client,
    asn: &str,
    base: &str,
) -> anyhow::Result<Vec<String>> {
    let mut url = Url::parse(&format!("{}/aslookup/", base))?;
    url.query_pairs_mut().append_pair("q", asn);
    let resp = {
        let r = client.get(url.as_str()).send().await?;
        gossan_core::net::bounded_text(r, crate::MAX_HORIZONTAL_TEXT_BYTES).await?
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

        let lowercase = "1.2.3.4, as99, Org";
        assert_eq!(parse_asn_response(lowercase), Some("AS99".to_string()));

        // Error payloads with commas must not become fake ASNs.
        let error_csv = "error code, rate limited, try again later";
        assert_eq!(parse_asn_response(error_csv), None);

        let bare_number = "1.2.3.4, 12345, Org";
        assert_eq!(parse_asn_response(bare_number), None);

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
