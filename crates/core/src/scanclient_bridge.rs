//! Map gossan [`Config`] onto [`scanclient::HttpConfig`] and build pooled clients.

use std::sync::Arc;

use hickory_resolver::TokioResolver;
use scanclient::{pool, HttpConfig};

use crate::config::Config;

/// Translate gossan scan settings into scanclient HTTP configuration.
#[must_use]
pub fn http_config_from_gossan(config: &Config) -> HttpConfig {
    let mut http = HttpConfig::default();
    http.timeout_secs = config.timeout_secs.max(1);
    http.connect_timeout_secs = config.timeout_secs.min(5).max(1);
    http.user_agent = config.user_agent.clone();
    http.proxy = config.proxy.clone();
    http.max_body_size = config.max_response_size;
    http.rate_limit_per_sec = Some(config.rate_limit.max(1));
    if config.insecure_tls {
        http.tls_verify = false;
        http.tls_accept_invalid_certs = true;
        http.tls_accept_invalid_hostnames = true;
    }
    if let Some(cookie) = &config.cookie {
        http.custom_headers
            .insert("cookie".to_string(), cookie.clone());
    }
    if let (Some(user), Some(pass)) = (&config.auth_user, &config.auth_pass) {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let token = STANDARD.encode(format!("{user}:{pass}"));
        http.custom_headers
            .insert("Authorization".to_string(), format!("Basic {token}"));
    } else if config.auth_user.is_some() ^ config.auth_pass.is_some() {
        tracing::warn!(
            "auth_user/auth_pass must both be set for HTTP Basic auth; ignoring partial credentials"
        );
    }
    http
}

/// Build a scanclient-pooled `reqwest::Client` with the supplied redirect policy.
pub fn build_http_client(
    config: &Config,
    resolver: Arc<TokioResolver>,
    redirect: scanclient::reqwest::redirect::Policy,
) -> scanclient::Result<scanclient::reqwest::Client> {
    pool::build_client_with_redirect(&http_config_from_gossan(config), resolver, redirect)
}
