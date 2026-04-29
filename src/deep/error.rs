use thiserror::Error;

/// Errors produced by the deep (semantic) scan pipeline.
///
/// Converts cleanly into [`crate::error::ZiftError`] via `#[from]` at the
/// crate boundary.
#[derive(Error, Debug)]
pub enum DeepError {
    #[error("missing config: {0}")]
    Config(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("model returned malformed JSON: {0}")]
    BadResponse(String),

    #[error("cost ceiling reached after ${spent:.4} USD")]
    CostExceeded { spent: f64 },

    #[error("request timed out after {secs}s")]
    Timeout { secs: u64 },

    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
}
