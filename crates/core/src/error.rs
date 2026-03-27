use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("dns error: {0}")]
    Dns(String),

    #[error("parse error: {0}")]
    Parse(String),

    #[error("timeout")]
    Timeout,

    #[error("scanner '{scanner}' failed: {message}")]
    Scanner {
        scanner: &'static str,
        message: String,
    },
}
