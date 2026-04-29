//! Code-context expansion for deep-scan candidates.
//!
//! Two-tier strategy (see plans/todo/01-pr1-deep-http-transport.md §7):
//!
//! - **Fast path**: line-window `[start-5, end+15]` plus the first 20 lines
//!   of the file as imports. Works for all languages.
//! - **Smart path**: tree-sitter walk to enclosing function. Only available
//!   for languages with an integrated grammar (TS/JS/Java today).
//!
//! Implementation lands in commit 3.

#![allow(dead_code)]

use crate::deep::error::DeepError;
use crate::types::{Finding, Language};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct ExpandedContext {
    pub file_relative: PathBuf,
    pub language: Language,
    pub line_start: usize,
    pub line_end: usize,
    pub snippet: String,
    pub imports: Vec<String>,
}

/// Expand a structural finding's snippet to include surrounding function
/// body and file-level imports.
pub fn expand_finding(_finding: &Finding, _scan_root: &Path) -> Result<ExpandedContext, DeepError> {
    unimplemented!("expand_finding: commit 3")
}

/// Expand an arbitrary file region (used for `ColdRegion` candidates that
/// have no structural finding behind them).
pub fn expand_region(
    _file: &Path,
    _language: Language,
    _line_start: usize,
    _line_end: usize,
) -> Result<ExpandedContext, DeepError> {
    unimplemented!("expand_region: commit 3")
}
