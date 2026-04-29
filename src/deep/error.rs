// Some variants are constructed only by code that lands in commits 5/6.
#![allow(dead_code)]

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
    // Http(#[from] reqwest::Error) is added in commit 5 alongside the HTTP
    // client, so we don't drag reqwest into the build before it's needed.
}
