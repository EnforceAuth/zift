use std::path::PathBuf;

use thiserror::Error;

use crate::deep::error::DeepError;
use crate::types::Language;

pub type Result<T> = std::result::Result<T, ZiftError>;

#[derive(Error, Debug)]
pub enum ZiftError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("failed to parse config file {path}: {source}")]
    ConfigParse {
        path: PathBuf,
        source: toml::de::Error,
    },

    #[error("failed to parse pattern rule {rule_id}: {message}")]
    RuleParse { rule_id: String, message: String },

    #[error("invalid tree-sitter query in rule {rule_id}: {message}")]
    QueryError { rule_id: String, message: String },

    #[error("deep scan: {0}")]
    Deep(#[from] DeepError),

    #[error("{0} is not yet supported in v0.1; support is planned for v0.2")]
    UnsupportedLanguage(Language),

    #[error("{0}")]
    General(String),
}
