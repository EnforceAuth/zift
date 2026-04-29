//! Deep (LLM-assisted) semantic scan.
//!
//! See [`plans/todo/01-pr1-deep-http-transport.md`] for the full design.
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

pub use config::DeepRuntime;
pub use error::DeepError;
pub use finding::SemanticFinding;

use crate::types::Finding;
use std::collections::{HashMap, HashSet};
use std::path::Path;

/// Run the deep (semantic) scan over a set of structural findings.
///
/// Takes ownership of `structural` because the deep pass may drop entries
/// the model identifies as false positives. Returns the **merged** finding
/// set (filtered structural ∪ semantic, with overlap dedup applied).
///
/// Errors:
/// - `DeepError::Config`: missing config or HTTP client construction failure (hard fail)
/// - `DeepError::CostExceeded`: cap reached mid-run; returns immediately (hard fail)
/// - `DeepError::Io`: filesystem error reading source files (hard fail)
///
/// Per-candidate `Http`, `BadResponse`, and `Timeout` errors are logged
/// and the candidate is skipped — best-effort enrichment, not all-or-nothing.
pub fn run(
    structural: Vec<Finding>,
    scan_root: &Path,
    runtime: &DeepRuntime,
) -> Result<Vec<Finding>, DeepError> {
    let candidates = candidate::select_candidates(&structural, scan_root, runtime)?;
    if candidates.is_empty() {
        tracing::info!("deep: no candidates to analyze; returning structural findings as-is");
        return Ok(structural);
    }
    tracing::info!(
        "deep: analyzing {} candidate(s) (cap: {})",
        candidates.len(),
        runtime.max_candidates
    );

    let client = client::OpenAiCompatibleClient::new(runtime)?;
    let cost_tracker = cost::CostTracker::new(runtime);

    // Index structural findings by id so we can look up the seed Finding for
    // escalation candidates (used by prompt rendering and false-positive drops).
    let structural_by_id: HashMap<String, Finding> =
        structural.into_iter().map(|f| (f.id.clone(), f)).collect();

    let mut semantic_findings: Vec<Finding> = Vec::new();
    let mut false_positive_seeds: HashSet<String> = HashSet::new();

    for candidate in &candidates {
        let seed = candidate
            .original_finding_id
            .as_deref()
            .and_then(|id| structural_by_id.get(id));

        let prompt = prompt::render(&prompt::PromptInputs {
            candidate,
            structural_finding: seed,
        });

        let response = match client.analyze(&prompt) {
            Ok(r) => r,
            Err(DeepError::Http(e)) => {
                tracing::warn!(
                    "deep: HTTP error on {}:{} (skipping): {e}",
                    candidate.file.display(),
                    candidate.line_start
                );
                continue;
            }
            Err(DeepError::BadResponse(msg)) => {
                tracing::warn!(
                    "deep: bad response on {}:{} (skipping): {msg}",
                    candidate.file.display(),
                    candidate.line_start
                );
                continue;
            }
            Err(DeepError::Timeout { secs }) => {
                tracing::warn!(
                    "deep: timeout ({}s) on {}:{} (skipping)",
                    secs,
                    candidate.file.display(),
                    candidate.line_start
                );
                continue;
            }
            // Config / CostExceeded / Io are hard fails — propagate.
            Err(other) => return Err(other),
        };

        cost_tracker.record(&response.usage)?;

        for sem in response.findings {
            if sem.is_false_positive {
                if let Some(seed_id) = &candidate.original_finding_id {
                    false_positive_seeds.insert(seed_id.clone());
                }
                continue;
            }
            let f = finding::into_finding(sem, candidate, seed, scan_root);
            semantic_findings.push(f);
        }
    }

    tracing::info!(
        "deep: {} semantic finding(s); {} structural false-positive(s); spent ${:.4}",
        semantic_findings.len(),
        false_positive_seeds.len(),
        cost_tracker.spent_usd()
    );

    // Drop structural findings the model rejected, then merge semantic in.
    let filtered_structural: Vec<Finding> = structural_by_id
        .into_values()
        .filter(|f| !false_positive_seeds.contains(&f.id))
        .collect();

    Ok(merge::merge(filtered_structural, semantic_findings))
}
