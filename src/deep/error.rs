use thiserror::Error;

/// Errors produced by the deep (semantic) scan pipeline.
///
/// Converts cleanly into [`crate::error::ZiftError`] via `#[from]` at the
/// crate boundary.
#[derive(Error, Debug)]
pub enum DeepError {
    /// Config-build-time failure. Covers both missing required fields
    /// (e.g. `--base-url` not set) AND validation failures of values that
    /// were supplied (e.g. `--base-url ftp://...`, mutually-exclusive
    /// flags, NaN cost rates). The prefix avoids "missing" because the
    /// variant fires for malformed-but-present input too.
    #[error("deep config error: {0}")]
    Config(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("model returned malformed JSON: {0}")]
    BadResponse(String),

    /// Transient upstream failure (5xx, 429, etc.). The orchestrator skips
    /// the affected candidate and continues; this is *not* hard-failed as
    /// `Config`, and unlike `BadResponse` it does NOT trigger the
    /// schema-fallback retry — removing `response_format` cannot fix a
    /// rate-limit or server outage, and retrying just doubles traffic.
    #[error("transient upstream failure: {0}")]
    Transient(String),

    #[error("cost ceiling reached after ${spent:.4} USD")]
    CostExceeded { spent: f64 },

    #[error("request timed out after {secs}s")]
    Timeout { secs: u64 },

    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
}
