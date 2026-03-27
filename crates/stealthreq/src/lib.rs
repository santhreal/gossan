//! Stealth HTTP request module for gossan.
//!
//! Provides anti-detection capabilities:
//! - Random User-Agent rotation from TOML configuration
//! - Request jitter (random delays between requests)
//! - Per-request header variation
//! - Automatic retry with exponential backoff
//!
//! # Example
//!
//! ```rust,no_run
//! use gossan_stealthreq::{StealthClient, StealthConfig};
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let config = StealthConfig::default();
//!     let client = StealthClient::new(config)?;
//!     
//!     let response = client.get("https://example.com").send().await?;
//!     println!("Status: {}", response.status());
//!     
//!     Ok(())
//! }
//! ```

use rand::seq::SliceRandom;
use rand::Rng;
use serde::Deserialize;
use std::sync::OnceLock;
use std::time::Duration;
use std::collections::HashMap;

mod request;
pub use request::{StealthClient, StealthConfig, StealthRequestBuilder};

/// User-Agent definition from TOML.
#[derive(Debug, Clone, Deserialize)]
pub struct UserAgent {
    pub string: String,
    #[allow(dead_code)]
    pub browser: String,
    #[allow(dead_code)]
    pub os: String,
    /// Weight for random selection (higher = more likely)
    pub weight: u32,
}

/// TOML file containing User-Agent definitions.
#[derive(Debug, Deserialize)]
struct UserAgentsFile {
    user_agent: Vec<UserAgent>,
}

/// Built-in user_agents.toml content (embedded at compile time).
const BUILTIN_USER_AGENTS: &str = include_str!("../rules/user_agents.toml");

/// Global cache for built-in User-Agents.
static USER_AGENTS: OnceLock<Vec<UserAgent>> = OnceLock::new();

/// Initialize and return the built-in User-Agents.
fn builtin_user_agents() -> &'static Vec<UserAgent> {
    USER_AGENTS.get_or_init(|| {
        match toml::from_str::<UserAgentsFile>(BUILTIN_USER_AGENTS) {
            Ok(file) => file.user_agent,
            Err(e) => {
                tracing::error!(error = %e, "failed to parse built-in user_agents.toml");
                // Fallback to minimal hardcoded list only on parse failure
                vec![
                    UserAgent {
                        string: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36".to_string(),
                        browser: "Chrome".to_string(),
                        os: "Windows".to_string(),
                        weight: 100,
                    },
                ]
            }
        }
    })
}

/// Get a random User-Agent string based on weights.
pub fn random_user_agent() -> String {
    let agents = builtin_user_agents();
    let total_weight: u32 = agents.iter().map(|a| a.weight).sum();
    
    if total_weight == 0 {
        return agents.first()
            .map(|a| a.string.clone())
            .unwrap_or_default();
    }
    
    let mut rng = rand::thread_rng();
    let mut choice = rng.gen_range(0..total_weight);
    
    for agent in agents {
        if choice < agent.weight {
            return agent.string.clone();
        }
        choice -= agent.weight;
    }
    
    agents.first().map(|a| a.string.clone()).unwrap_or_default()
}

/// Calculate a jittered delay based on base delay and jitter factor.
/// 
/// # Example
/// - base_delay = 1000ms
/// - jitter = 0.2 (20%)
/// - Result: 800-1200ms
pub fn jittered_delay(base_delay_ms: u64, jitter_factor: f64) -> Duration {
    let mut rng = rand::thread_rng();
    let jitter = rng.gen_range(-jitter_factor..=jitter_factor);
    let delay_ms = (base_delay_ms as f64 * (1.0 + jitter)).max(0.0) as u64;
    Duration::from_millis(delay_ms)
}

/// Stealth headers that vary per request to avoid fingerprinting.
pub fn stealth_headers() -> HashMap<String, String> {
    let mut headers = HashMap::new();
    let mut rng = rand::thread_rng();
    
    // Accept headers vary by "browser personality"
    let accept_choices = [
        "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    ];
    headers.insert(
        "Accept".to_string(),
        accept_choices.choose(&mut rng).unwrap_or(&accept_choices[0]).to_string(),
    );
    
    // Accept-Language (weighted toward en-US)
    let lang_choices = [
        ("en-US,en;q=0.9", 50),
        ("en-US,en;q=0.5", 20),
        ("en-GB,en;q=0.9", 15),
        ("en-CA,en;q=0.9", 10),
        ("en-AU,en;q=0.9", 5),
    ];
    headers.insert("Accept-Language".to_string(), weighted_choice(&lang_choices).to_string());
    
    // Accept-Encoding
    headers.insert("Accept-Encoding".to_string(), "gzip, deflate, br".to_string());
    
    // DNT (Do Not Track) - randomize
    if rng.gen_bool(0.3) {
        headers.insert("DNT".to_string(), "1".to_string());
    }
    
    // Upgrade-Insecure-Requests (sometimes present)
    if rng.gen_bool(0.7) {
        headers.insert("Upgrade-Insecure-Requests".to_string(), "1".to_string());
    }
    
    // Sec-Fetch headers (Chrome-style)
    if rng.gen_bool(0.6) {
        headers.insert("Sec-Fetch-Dest".to_string(), "document".to_string());
        headers.insert("Sec-Fetch-Mode".to_string(), "navigate".to_string());
        headers.insert("Sec-Fetch-Site".to_string(), "none".to_string());
        headers.insert("Sec-Fetch-User".to_string(), "?1".to_string());
    }
    
    headers
}

/// Select a random item based on weights.
fn weighted_choice<T: Copy>(choices: &[(T, u32)]) -> T {
    let total_weight: u32 = choices.iter().map(|(_, w)| w).sum();
    let mut rng = rand::thread_rng();
    let mut choice = rng.gen_range(0..total_weight.max(1));
    
    for (item, weight) in choices {
        if choice < *weight {
            return *item;
        }
        choice -= weight;
    }
    
    choices.first().map(|(i, _)| *i).unwrap()
}

/// Sleep for a jittered duration.
pub async fn sleep_jitter(base_delay_ms: u64, jitter_factor: f64) {
    let delay = jittered_delay(base_delay_ms, jitter_factor);
    tokio::time::sleep(delay).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_agents_load_from_toml() {
        let agents = builtin_user_agents();
        assert!(!agents.is_empty(), "should have User-Agents from TOML");
        
        // Check for common browsers
        assert!(
            agents.iter().any(|a| a.browser == "Chrome"),
            "should include Chrome UAs"
        );
    }

    #[test]
    fn user_agents_have_required_fields() {
        for agent in builtin_user_agents() {
            assert!(!agent.string.is_empty(), "UA string should not be empty");
            assert!(!agent.browser.is_empty(), "browser should not be empty");
            assert!(agent.weight > 0, "weight should be > 0");
        }
    }

    #[test]
    fn random_user_agent_returns_valid_string() {
        let ua = random_user_agent();
        assert!(!ua.is_empty(), "random UA should not be empty");
        assert!(ua.contains("Mozilla/"), "UA should be Mozilla-formatted");
    }

    #[test]
    fn jittered_delay_respects_bounds() {
        let base = 1000u64;
        let jitter = 0.2f64;
        
        // Test multiple times to account for randomness
        for _ in 0..100 {
            let delay = jittered_delay(base, jitter);
            let ms = delay.as_millis() as u64;
            // Should be within 20% of base
            assert!(ms >= 800 && ms <= 1200, "delay should be within jitter bounds: got {}", ms);
        }
    }

    #[test]
    fn stealth_headers_not_empty() {
        let headers = stealth_headers();
        assert!(!headers.is_empty(), "should have stealth headers");
        assert!(headers.contains_key("Accept"), "should have Accept header");
        assert!(headers.contains_key("Accept-Language"), "should have Accept-Language header");
    }

    #[test]
    fn weighted_choice_selects_from_list() {
        let choices = [("a", 10), ("b", 20), ("c", 30)];
        let result = weighted_choice(&choices);
        assert!("abc".contains(result), "result should be one of the choices");
    }
}
