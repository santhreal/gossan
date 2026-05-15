//! Shared helpers for subdomain sources.

use gossan_core::Config;

/// Retrieve an API key from config or environment.
pub fn get_api_key(config: &Config, source_name: &str, env_name: &str) -> Option<String> {
    config
        .api_keys
        .get(source_name)
        .cloned()
        .or_else(|| std::env::var(env_name).ok())
}
