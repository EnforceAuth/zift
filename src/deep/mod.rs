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
/// - `DeepError::Io`: filesystem error reading source files (hard fail)
///
/// `DeepError::CostExceeded` is **not** propagated as an error — when the cap
/// trips mid-run we stop dispatching new candidates but still merge the
/// already-collected semantic findings back into the structural set, so the
/// user keeps the work paid for. The cap breach is logged at `warn`.
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

    // TODO(deep-concurrency): honor `runtime.max_concurrent` via
    // `std::thread::scope` over `reqwest::blocking::Client` (clone-cheap).
    // Localhost endpoints auto-cap to 1 anyway; remote fan-out is the win.
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
            Err(DeepError::Transient(msg)) => {
                tracing::warn!(
                    "deep: transient upstream failure on {}:{} (skipping): {msg}",
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
            // Config / Io are hard fails — propagate.
            // (CostExceeded comes from cost_tracker.record below, not from
            // analyze, so it's handled separately to preserve in-flight findings.)
            Err(other) => return Err(other),
        };

        // Cap breach stops new dispatch, but the findings already merged in
        // earlier iterations (and the ones in this very response) are still
        // worth surfacing — the user paid for them. Break out of the loop
        // instead of returning the error and discarding the work.
        if let Err(DeepError::CostExceeded { spent }) = cost_tracker.record(&response.usage) {
            tracing::warn!(
                "deep: cost ceiling reached after ${spent:.4} USD — stopping new requests; \
                 returning {} semantic finding(s) collected so far",
                semantic_findings.len() + response.findings.len(),
            );
            // Drain the in-flight response too — same candidate window.
            for sem in response.findings {
                if sem.is_false_positive {
                    if let Some(seed_id) = &candidate.original_finding_id {
                        false_positive_seeds.insert(seed_id.clone());
                    }
                    continue;
                }
                let Some(sem) = clamp_to_candidate(sem, candidate) else {
                    continue;
                };
                let f = finding::into_finding(sem, candidate, seed, scan_root);
                semantic_findings.push(f);
            }
            break;
        }

        for sem in response.findings {
            if sem.is_false_positive {
                if let Some(seed_id) = &candidate.original_finding_id {
                    false_positive_seeds.insert(seed_id.clone());
                }
                continue;
            }
            // Validate model-reported ranges against the candidate window.
            // Even with a strict JSON schema, the model can return reversed
            // ranges or numbers outside the analyzed snippet — we don't
            // want those flowing into merge/sort/snippet extraction as
            // bogus findings.
            let Some(sem) = clamp_to_candidate(sem, candidate) else {
                continue;
            };
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
    // HashMap iteration order is randomized, so we must re-sort the merged
    // result to match the deterministic (file, line_start) ordering the
    // structural pass establishes — otherwise `--deep` produces different
    // output orderings between runs over the same input.
    let filtered_structural: Vec<Finding> = structural_by_id
        .into_values()
        .filter(|f| !false_positive_seeds.contains(&f.id))
        .collect();

    let mut merged = merge::merge(filtered_structural, semantic_findings);
    merged.sort_by(|a, b| {
        a.file
            .cmp(&b.file)
            .then(a.line_start.cmp(&b.line_start))
            .then(a.line_end.cmp(&b.line_end))
    });
    Ok(merged)
}

/// Clamp a [`SemanticFinding`]'s line range to the candidate's analyzed
/// window. Drops the finding entirely when:
///
/// - `line_start == 0` (schema requires `>= 1`, but be defensive),
/// - `line_end < line_start`,
/// - the entire range falls outside the candidate's window.
///
/// Otherwise pulls the range into `[candidate.line_start, candidate.line_end]`,
/// logs the clamp, and returns the normalized finding.
fn clamp_to_candidate(
    sem: SemanticFinding,
    candidate: &candidate::Candidate,
) -> Option<SemanticFinding> {
    if sem.line_start == 0 || sem.line_end < sem.line_start {
        tracing::warn!(
            file = %candidate.file.display(),
            reported = format!("{}-{}", sem.line_start, sem.line_end),
            "deep: dropping finding with invalid line range",
        );
        return None;
    }
    // Whole range outside the candidate window? Drop.
    if sem.line_end < candidate.line_start || sem.line_start > candidate.line_end {
        tracing::warn!(
            file = %candidate.file.display(),
            reported = format!("{}-{}", sem.line_start, sem.line_end),
            window = format!("{}-{}", candidate.line_start, candidate.line_end),
            "deep: dropping finding outside candidate window",
        );
        return None;
    }
    let line_start = sem.line_start.max(candidate.line_start);
    let line_end = sem.line_end.min(candidate.line_end).max(line_start);
    if line_start != sem.line_start || line_end != sem.line_end {
        tracing::debug!(
            file = %candidate.file.display(),
            reported = format!("{}-{}", sem.line_start, sem.line_end),
            clamped = format!("{line_start}-{line_end}"),
            "deep: clamped finding range to candidate window",
        );
    }
    Some(SemanticFinding {
        line_start,
        line_end,
        ..sem
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deep::candidate::CandidateKind;
    use crate::types::{AuthCategory, Confidence, Language};
    use std::path::PathBuf;

    fn cand(line_start: usize, line_end: usize) -> candidate::Candidate {
        candidate::Candidate {
            kind: CandidateKind::ColdRegion,
            file: PathBuf::from("a.ts"),
            language: Language::TypeScript,
            line_start,
            line_end,
            source_snippet: String::new(),
            imports: Vec::new(),
            original_finding_id: None,
            seed_category: None,
        }
    }

    fn sem(line_start: usize, line_end: usize) -> SemanticFinding {
        SemanticFinding {
            line_start,
            line_end,
            category: AuthCategory::Rbac,
            confidence: Confidence::High,
            description: "x".into(),
            reasoning: "y".into(),
            is_false_positive: false,
        }
    }

    #[test]
    fn clamp_drops_reversed_range() {
        assert!(clamp_to_candidate(sem(20, 10), &cand(1, 100)).is_none());
    }

    #[test]
    fn clamp_drops_zero_line_start() {
        assert!(clamp_to_candidate(sem(0, 5), &cand(1, 100)).is_none());
    }

    #[test]
    fn clamp_drops_range_entirely_outside_window() {
        assert!(clamp_to_candidate(sem(200, 250), &cand(1, 100)).is_none());
        assert!(clamp_to_candidate(sem(1, 5), &cand(50, 100)).is_none());
    }

    #[test]
    fn clamp_pulls_overshooting_range_into_window() {
        let out = clamp_to_candidate(sem(50, 200), &cand(40, 80)).unwrap();
        assert_eq!(out.line_start, 50);
        assert_eq!(out.line_end, 80);
    }

    #[test]
    fn clamp_pulls_undershooting_range_into_window() {
        let out = clamp_to_candidate(sem(5, 60), &cand(40, 80)).unwrap();
        assert_eq!(out.line_start, 40);
        assert_eq!(out.line_end, 60);
    }

    #[test]
    fn clamp_passes_through_in_window_range() {
        let out = clamp_to_candidate(sem(50, 60), &cand(40, 80)).unwrap();
        assert_eq!(out.line_start, 50);
        assert_eq!(out.line_end, 60);
    }
}
