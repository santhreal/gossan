//! DNSdumpster passive subdomain enumeration — scraping, no API key required.
//! https://dnsdumpster.com/

use gossan_core::{send_with_backoff, Config, DiscoverySource, DomainTarget, HostRateLimiter, Target};

use crate::is_subdomain_of;

/// Extract CSRF token from the HTML form.
fn extract_csrf_token(html: &str) -> Option<&str> {
    // Look for: <input type="hidden" name="csrfmiddlewaretoken" value="...">
    let prefix = r#"name="csrfmiddlewaretoken" value=""#;
    let start = html.find(prefix)? + prefix.len();
    let end = html[start..].find('"')?;
    Some(&html[start..start + end])
}

/// Extract subdomains from the HTML response table.
fn extract_subdomains(html: &str, domain: &str) -> Vec<Target> {
    let mut targets = Vec::new();

    // DNSdumpster returns tables with subdomain information
    // Each subdomain row typically contains the subdomain in a link or table cell
    // Pattern: subdomain.domain.com appears in various table contexts

    // Try to find subdomains in the HTML using common patterns
    for line in html.lines() {
        let line_lower = line.to_lowercase();

        // Look for table cells containing subdomain patterns
        // DNSdumpster uses <td> tags with host information
        if line_lower.contains("<td>") && line_lower.contains(domain) {
            // Extract text between HTML tags
            if let Some(subdomain) = extract_text_from_td(line) {
                let subdomain = subdomain.trim().to_lowercase();
                if !subdomain.is_empty()
                    && subdomain.ends_with(domain)
                    && is_subdomain_of(&subdomain, domain)
                {
                    targets.push(Target::Domain(DomainTarget {
                        domain: subdomain,
                        source: DiscoverySource::DnsDumpster,
                    }));
                }
            }
        }
    }

    // Deduplicate
    targets.sort_by(|a, b| {
        let a_str = a.domain().unwrap_or("");
        let b_str = b.domain().unwrap_or("");
        a_str.cmp(b_str)
    });
    targets.dedup_by(|a, b| {
        let a_str = a.domain().unwrap_or("");
        let b_str = b.domain().unwrap_or("");
        a_str == b_str
    });

    targets
}

/// Extract text content from a <td> HTML element.
fn extract_text_from_td(line: &str) -> Option<String> {
    // Find content between <td> and </td>
    let td_start = line.find("<td>")? + 4;
    let td_end = line[td_start..].find("</td>")?;
    let content = &line[td_start..td_start + td_end];

    // Strip any nested HTML tags and get the text
    let mut result = String::new();
    let mut in_tag = false;
    for ch in content.chars() {
        match ch {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => result.push(ch),
            _ => {}
        }
    }

    let trimmed = result.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

pub async fn query(
    domain: &str,
    _config: &Config,
    client: &reqwest::Client,
    rate_limiter: &HostRateLimiter,
) -> anyhow::Result<Vec<Target>> {
    const BASE_URL: &str = "https://dnsdumpster.com/";

    // Step 1: GET request to obtain CSRF token
    let get_resp = send_with_backoff(BASE_URL, Some(rate_limiter), || async {
        Ok::<reqwest::Response, anyhow::Error>(client.get(BASE_URL).send().await?)
    })
    .await?;

    let html = get_resp.text().await?;
    let csrf_token = extract_csrf_token(&html)
        .ok_or_else(|| anyhow::anyhow!("failed to extract CSRF token from DNSdumpster"))?;

    // Step 2: POST request with CSRF token and target domain
    let form_data = [
        ("csrfmiddlewaretoken", csrf_token),
        ("targetip", domain),
    ];

    let post_resp = send_with_backoff(BASE_URL, Some(rate_limiter), || async {
        Ok::<reqwest::Response, anyhow::Error>(
            client
                .post(BASE_URL)
                .header("Referer", BASE_URL)
                .form(&form_data)
                .send()
                .await?,
        )
    })
    .await?;

    let response_html = post_resp.text().await?;

    // Step 3: Parse HTML to extract subdomains
    let targets = extract_subdomains(&response_html, domain);

    Ok(targets)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_csrf_token() {
        let html = r#"<input type="hidden" name="csrfmiddlewaretoken" value="abc123xyz">"#;
        assert_eq!(extract_csrf_token(html), Some("abc123xyz"));
    }

    #[test]
    fn test_extract_csrf_token_not_found() {
        let html = r#"<div>no token here</div>"#;
        assert_eq!(extract_csrf_token(html), None);
    }

    #[test]
    fn test_extract_text_from_td() {
        let line = r#"<td>sub.example.com</td>"#;
        assert_eq!(
            extract_text_from_td(line),
            Some("sub.example.com".to_string())
        );
    }

    #[test]
    fn test_extract_text_from_td_with_link() {
        let line = r#"<td><a href="/">sub.example.com</a></td>"#;
        assert_eq!(
            extract_text_from_td(line),
            Some("sub.example.com".to_string())
        );
    }

    #[test]
    fn test_extract_subdomains() {
        let html = r#"
        <table>
            <tr><td>sub1.example.com</td></tr>
            <tr><td>sub2.example.com</td></tr>
            <tr><td>notasubdomain.com</td></tr>
        </table>
        "#;
        let targets = extract_subdomains(html, "example.com");
        assert_eq!(targets.len(), 2);
    }
}
