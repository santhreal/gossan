//! Gossan error types — typed scanner failures with context.
//!
//! [`enum@Error`] covers every failure mode in the scanner pipeline:
//! network I/O, DNS resolution, TLS handshakes, rate limiting,
//! configuration, and individual scanner failures. All errors carry
//! enough context to diagnose root cause in under 60 seconds.

use thiserror::Error;

/// Typed error for gossan scanner operations.
///
/// Prefer this over `anyhow::Error` in scanner implementations so
/// callers can match on specific failure modes and decide whether
/// to retry, skip, or abort.
///
/// # Examples
///
/// ```rust
/// use gossan_core::Error;
///
/// fn check_error(e: &Error) {
///     match e {
///         Error::Timeout { .. } => eprintln!("timed out — consider increasing --timeout"),
///         Error::RateLimit { provider, .. } => eprintln!("{provider} rate limited us"),
///         _ => eprintln!("other error: {e}"),
///     }
/// }
/// ```
#[derive(Debug, Error)]
pub enum Error {
    /// DNS resolution failed for a target.
    #[error("dns resolution failed for '{target}': {reason}")]
    Dns {
        /// The target that failed to resolve.
        target: String,
        /// The underlying DNS error.
        reason: String,
    },

    /// Network I/O error (TCP connect, read, write).
    #[error("network error for '{target}': {reason}")]
    Network {
        /// The target that caused the error.
        target: String,
        /// The underlying I/O or reqwest error.
        reason: String,
    },

    /// TLS handshake or certificate validation failed.
    #[error("tls handshake failed for '{target}': {message}")]
    Tls {
        /// The target that caused the error.
        target: String,
        /// Description of the TLS failure.
        message: String,
    },

    /// Scanner timed out waiting for a response.
    #[error("timeout after {timeout_secs}s for '{target}' during {stage}")]
    Timeout {
        /// The target that timed out.
        target: String,
        /// Which pipeline stage was running.
        stage: String,
        /// How long we waited before giving up.
        timeout_secs: u64,
    },

    /// External API rate-limited the scanner.
    #[error("{provider} rate limited: retry after {retry_after_secs}s")]
    RateLimit {
        /// The API provider that throttled us.
        provider: String,
        /// How long to wait before retrying.
        retry_after_secs: u64,
    },

    /// Invalid scanner configuration.
    #[error("configuration error: {message}")]
    Configuration {
        /// Description of what's wrong.
        message: String,
    },

    /// A specific scanner module failed.
    #[error("scanner '{scanner}' failed: {message}")]
    Scanner {
        /// Which scanner module failed.
        scanner: &'static str,
        /// What went wrong.
        message: String,
    },

    /// Input parsing error (URLs, ports, etc.).
    #[error("parse error: {message}")]
    Parse {
        /// Description of the parse failure.
        message: String,
    },

    /// Proxy connection failed.
    #[error("proxy connection to '{proxy}' failed: {message}")]
    Proxy {
        /// The proxy URL that was attempted.
        proxy: String,
        /// What went wrong.
        message: String,
    },

    /// Authentication/authorization error with external APIs.
    #[error("{provider} auth failed: {message}")]
    Auth {
        /// The provider that rejected credentials.
        provider: String,
        /// What went wrong.
        message: String,
    },
}

impl Error {
    /// Whether this error is transient and the operation can be retried.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::Network { .. } | Self::Timeout { .. } | Self::RateLimit { .. } | Self::Dns { .. }
        )
    }

    /// Whether this error indicates a configuration problem that won't
    /// resolve on retry.
    #[must_use]
    pub fn is_configuration(&self) -> bool {
        matches!(self, Self::Configuration { .. } | Self::Auth { .. })
    }

    /// Convenience: create a network error from a reqwest error.
    pub fn from_reqwest(target: &str, err: crate::reqwest::Error) -> Self {
        if err.is_timeout() {
            Self::Timeout {
                target: target.to_string(),
                stage: "http".to_string(),
                timeout_secs: 0,
            }
        } else if err.is_connect() {
            Self::Network {
                target: target.to_string(),
                reason: err.to_string(),
            }
        } else {
            Self::Network {
                target: target.to_string(),
                reason: err.to_string(),
            }
        }
    }
}
