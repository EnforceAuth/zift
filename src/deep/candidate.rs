//! Candidate selection for the deep (semantic) scan.
//!
//! See plans/todo/01-pr1-deep-http-transport.md §6 for selection rules.
//! Implementation lands in commit 3.

// Stubs are used by future commits; suppress dead-code warnings until then.
#![allow(dead_code)]

use crate::deep::config::DeepRuntime;
use crate::deep::error::DeepError;
use crate::types::{AuthCategory, Finding, Language};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateKind {
    /// Re-evaluation of a structural finding (typically low/medium confidence).
    Escalation,
    /// Cold-region scan triggered by name-based heuristics. May or may not
    /// correspond to a structural finding.
    ColdRegion,
}

#[derive(Debug, Clone)]
pub struct Candidate {
    pub kind: CandidateKind,
    pub file: PathBuf,
    pub language: Language,
    pub line_start: usize,
    pub line_end: usize,
    pub source_snippet: String,
    /// Set iff `kind == Escalation` — the structural finding's id.
    pub original_finding_id: Option<String>,
    /// Hint for prompt selection (e.g. seed an RBAC-flavored prompt).
    pub seed_category: Option<AuthCategory>,
}

/// Pick which structural findings to escalate and which file regions to
/// cold-scan. Sorted deterministically by `(file, line_start)`.
pub fn select_candidates(
    _structural: &[Finding],
    _scan_root: &Path,
    _runtime: &DeepRuntime,
) -> Result<Vec<Candidate>, DeepError> {
    // TODO(commit 3): implement escalation rules + cold-region scanning.
    Ok(Vec::new())
}
