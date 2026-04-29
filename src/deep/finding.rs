//! LLM-side finding shape and translation to the canonical [`Finding`].
//!
//! Implementation of [`into_finding`] lands in commit 4.

#![allow(dead_code)]

use crate::deep::candidate::Candidate;
use crate::types::{AuthCategory, Confidence, Finding};
use serde::Deserialize;

/// LLM-side finding shape, deserialized from `output_schema()`-compliant
/// JSON returned by the agent. Translated to the canonical [`Finding`] via
/// [`into_finding`].
#[derive(Debug, Clone, Deserialize)]
pub struct SemanticFinding {
    pub line_start: usize,
    pub line_end: usize,
    pub category: AuthCategory,
    pub confidence: Confidence,
    pub description: String,
    pub reasoning: String,
    /// For `Escalation` candidates: did the model judge the seed structural
    /// finding to be a false positive? Causes the seed to be dropped during
    /// merge (see [`crate::deep::merge::merge`]).
    pub is_false_positive: bool,
}

/// Translate an LLM-emitted [`SemanticFinding`] into the canonical [`Finding`]
/// shape, computing the deterministic id hash.
pub fn into_finding(
    _sem: SemanticFinding,
    _candidate: &Candidate,
    _seed: Option<&Finding>,
) -> Finding {
    unimplemented!("into_finding: commit 4")
}
