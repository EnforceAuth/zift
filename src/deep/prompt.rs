//! Prompt rendering and JSON output schema for the deep scan.
//!
//! Both `SYSTEM_PROMPT` and [`output_schema`] are exported for reuse by
//! PR 2 (MCP server) and PR 3 (subprocess hook). They are the canonical
//! contract that every transport binds to.
//!
//! Implementation lands in commit 4.

#![allow(dead_code)]

use crate::deep::candidate::Candidate;
use crate::types::Finding;

/// System prompt sent on every deep-scan request. Defines the authz
/// taxonomy, calibration guidance, and the structured-output contract.
pub const SYSTEM_PROMPT: &str = ""; // commit 4

#[derive(Debug, Clone)]
pub struct PromptInputs<'a> {
    pub candidate: &'a Candidate,
    pub structural_finding: Option<&'a Finding>,
}

#[derive(Debug, Clone)]
pub struct RenderedPrompt {
    pub system: String,
    pub user: String,
    pub schema: serde_json::Value,
}

/// Build the per-candidate prompt + schema bundle.
pub fn render(_inputs: &PromptInputs) -> RenderedPrompt {
    unimplemented!("prompt::render: commit 4")
}

/// JSON Schema the model must emit. Matches [`SemanticFinding`] field-for-field.
///
/// [`SemanticFinding`]: crate::deep::finding::SemanticFinding
pub fn output_schema() -> serde_json::Value {
    unimplemented!("output_schema: commit 4")
}
