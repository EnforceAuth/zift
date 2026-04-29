//! Deep (LLM-assisted) semantic scan.
//!
//! See [`plans/todo/01-pr1-deep-http-transport.md`] for the full design.
//! This module is being built incrementally across six commits:
//!
//! 1. CLI/config refactor (done in PR-prep commit)
//! 2. Module skeleton + config + error types (this commit)
//! 3. Candidate selection + context expansion
//! 4. Prompt rendering + JSON output schema
//! 5. OpenAI-compatible HTTP client + cost tracker
//! 6. Result merge + end-to-end wiring
//!
//! The primitives in this module are intentionally transport-agnostic so
//! that PR 2 (MCP server) and PR 3 (subprocess hook) can reuse them.

pub mod candidate;
pub mod client;
pub mod config;
pub mod context;
pub mod cost;
pub mod error;
pub mod finding;
pub mod merge;
pub mod prompt;

// Convenience re-exports (DeepRuntime, DeepError, SemanticFinding) will be
// added in commit 6 when end-to-end wiring lands and external callers
// actually use them. Adding them now triggers unused-import warnings.

use crate::deep::config::DeepRuntime;
use crate::deep::error::DeepError;
use crate::types::Finding;
use std::path::Path;

/// Run the deep (semantic) scan over a set of structural findings.
///
/// Returns additional findings with `pass: ScanPass::Semantic`. Merging into
/// the master findings vec is the caller's responsibility (use
/// [`merge::merge`]).
///
/// In commit 2 this is a no-op stub. Subsequent commits add candidate
/// selection, context expansion, prompt rendering, HTTP analyze, and result
/// merging.
pub fn run(
    _structural: &[Finding],
    _scan_root: &Path,
    _runtime: &DeepRuntime,
) -> Result<Vec<Finding>, DeepError> {
    // TODO(commits 3-6): candidate selection -> context expansion ->
    // prompt rendering -> HTTP analyze -> finding merge.
    Ok(Vec::new())
}
