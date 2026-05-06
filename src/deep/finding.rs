//! LLM-side finding shape and translation to the canonical [`Finding`].

use crate::deep::candidate::Candidate;
use crate::scanner::matcher::compute_finding_id;
use crate::types::{AuthCategory, Confidence, Finding, ScanPass, Surface};
use serde::Deserialize;
use std::path::Path;

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
    /// Model's reasoning chain. Logged via `tracing` for debugging; not
    /// stored on the canonical [`Finding`] (no field for it). Step-by-step
    /// reasoning helps the model produce calibrated output even when we
    /// don't read it back.
    pub reasoning: String,
    /// For `Escalation` candidates: the model judges the seed structural
    /// finding to be a false positive. Causes the seed to be dropped at
    /// merge time (see [`crate::deep::merge::merge`]).
    pub is_false_positive: bool,
}

/// Translate a model-emitted [`SemanticFinding`] into the canonical
/// [`Finding`] shape.
///
/// `scan_root` is required to read the file at `candidate.file` (relative)
/// to populate `code_snippet` from the lines the model identified. If the
/// file is unreadable (e.g. moved between scan and analyze), the snippet
/// falls back to slicing [`Candidate::source_snippet`] for the same line
/// range — that buffer was loaded by the structural pass so it's already
/// in memory and represents the same source the model just analyzed.
/// Empty `code_snippet` remains the last resort; downstream tools that
/// surface "what was flagged" need *something* on every finding (corpus
/// shakedown turned up 28 semantic findings with `code_snippet: ""`,
/// which made deep-only buckets unreviewable).
pub fn into_finding(
    sem: SemanticFinding,
    candidate: &Candidate,
    seed: Option<&Finding>,
    scan_root: &Path,
) -> Finding {
    // `reasoning` can mirror back scanned source or secrets the model saw in
    // the snippet. The canonical `Finding` already drops it; persisting the
    // verbatim text in tracing logs would undo that. Log only the length so
    // operators can still spot suspicious blank/oversize reasoning chains.
    tracing::debug!(
        file = %candidate.file.display(),
        lines = format!("{}-{}", sem.line_start, sem.line_end),
        category = ?sem.category,
        confidence = ?sem.confidence,
        is_false_positive = sem.is_false_positive,
        reasoning_len = sem.reasoning.len(),
        "semantic finding"
    );

    // Synthetic rule id used both for the deterministic finding id hash AND
    // for the displayed `pattern_rule` field. Semantic findings cannot honestly
    // claim the structural rule verbatim — the model can re-categorize, drop,
    // or re-scope the seed (e.g. an `ownership` seed coming back as
    // `feature_gate`). Surfacing the seed's bare rule id would tell consumers
    // "this finding came from rule ts-ownership-check" when it didn't.
    //
    // Three branches:
    // 1. Escalation seed exists AND the model's reported range overlaps the
    //    seed's range → genuine re-evaluation of the seed; tag `{rule}-semantic`.
    // 2. Escalation candidate but the model's range is OUTSIDE the seed's
    //    range → an incidental finding the model spotted in the surrounding
    //    context window. Treat as if it were a cold-region hit; tag
    //    `semantic-{category}` so the lineage doesn't falsely impersonate the
    //    seed rule. (Manual subprocess walkthrough caught this: an ownership
    //    escalation's expanded window covered an unrelated checkPermission
    //    function and that feature_gate finding was getting stamped
    //    `ts-ownership-check-semantic`.)
    // 3. No seed (cold-region candidate) → synthesize from the model's category.
    let rule_id = match (
        seed.and_then(|s| s.pattern_rule.as_deref()),
        seed.map(|s| (s.line_start, s.line_end)),
    ) {
        (Some(pr), Some((s_start, s_end)))
            if ranges_overlap(s_start, s_end, sem.line_start, sem.line_end) =>
        {
            format!("{pr}-semantic")
        }
        _ => format!("semantic-{}", sem.category.slug()),
    };

    // Try the filesystem first — that's the source of truth and produces the
    // same byte range a structural finding would. Fall back to slicing the
    // candidate's expanded snippet (already in memory) when the file moved,
    // permissions changed, or extract_lines bailed for any other reason.
    // Last resort: empty string. We never *fail* a finding on snippet read.
    let code_snippet = extract_lines(scan_root, &candidate.file, sem.line_start, sem.line_end)
        .or_else(|| slice_candidate_snippet(candidate, sem.line_start, sem.line_end))
        .unwrap_or_default();

    let id = compute_finding_id(
        &rule_id,
        &candidate.file,
        sem.line_start,
        sem.line_end,
        &code_snippet,
    );

    Finding {
        id,
        file: candidate.file.clone(),
        line_start: sem.line_start,
        line_end: sem.line_end,
        code_snippet,
        language: candidate.language,
        category: sem.category,
        confidence: sem.confidence,
        description: sem.description,
        // Use the synthetic id (e.g. `ts-ownership-check-semantic` or
        // `semantic-rbac`) so a consumer grouping by `pattern_rule` sees that
        // this finding is the model's verdict, not the structural rule's.
        pattern_rule: Some(rule_id),
        rego_stub: None, // structural-only; semantic findings have no rego template
        cedar_stub: None,
        pass: ScanPass::Semantic,
        // Surface follows the source file, not the pass — same path
        // heuristic as structural findings so a deep-pass `web/src/foo.ts`
        // finding is tagged Frontend just like its structural twin would be.
        surface: Surface::classify(&candidate.file),
    }
}

/// Slice [`candidate.source_snippet`] to the model-reported line range,
/// translating absolute (1-based, file-relative) line numbers into offsets
/// within the snippet. Returns `None` if the snippet is empty, the model's
/// range falls outside the candidate window, or the requested offsets land
/// past the end of the snippet (which can happen when the snippet was
/// truncated to fit `max_prompt_chars`).
///
/// `clamp_to_candidate` (in `deep::mod`) already keeps `sem` inside the
/// candidate window before this gets called, but we re-check defensively
/// rather than panic if a future caller skips the clamp.
fn slice_candidate_snippet(
    candidate: &crate::deep::candidate::Candidate,
    sem_start: usize,
    sem_end: usize,
) -> Option<String> {
    if candidate.source_snippet.is_empty() {
        return None;
    }
    if sem_start == 0
        || sem_end < sem_start
        || sem_start < candidate.line_start
        || sem_end > candidate.line_end
    {
        return None;
    }
    let lines: Vec<&str> = candidate.source_snippet.lines().collect();
    if lines.is_empty() {
        return None;
    }
    // Translate file-relative 1-based line numbers into snippet-relative
    // 0-based offsets. Snippet line 0 corresponds to `candidate.line_start`.
    let start_idx = sem_start - candidate.line_start;
    let end_idx = sem_end - candidate.line_start;
    if start_idx >= lines.len() {
        return None;
    }
    let end_inclusive = end_idx.min(lines.len() - 1);
    Some(lines[start_idx..=end_inclusive].join("\n"))
}

/// Read the file at `scan_root.join(relative)` and return lines `[start, end]`
/// joined by `\n`. Returns `None` on read error or out-of-range input.
fn extract_lines(scan_root: &Path, relative: &Path, start: usize, end: usize) -> Option<String> {
    if start == 0 || end < start {
        return None;
    }
    let content = std::fs::read_to_string(scan_root.join(relative)).ok()?;
    let lines: Vec<&str> = content.lines().collect();
    if lines.is_empty() {
        return None;
    }
    // Bail (instead of clamping to the last line) when the requested range
    // starts past the end of the file. Otherwise the caller's fallback chain
    // — `extract_lines(...).or_else(slice_candidate_snippet(...))` in
    // `build_finding_from_semantic` — never reaches the candidate snippet on
    // a shrunken/replaced file, and we'd silently attach an unrelated
    // last-line excerpt to the finding.
    if start > lines.len() {
        return None;
    }
    let s = start - 1;
    let e = end.min(lines.len()).max(s + 1);
    Some(lines[s..e].join("\n"))
}

// Canonical slug lookup lives on `AuthCategory::slug()` (src/types.rs) so
// every site that needs the snake_case wire form goes through one source of
// truth.

/// Inclusive integer-range overlap: do `[a_start, a_end]` and
/// `[b_start, b_end]` share any line? Used to decide whether a model-reported
/// finding actually re-evaluates its escalation seed (overlapping ranges) or
/// is an incidental finding from the surrounding context window (no overlap).
fn ranges_overlap(a_start: usize, a_end: usize, b_start: usize, b_end: usize) -> bool {
    a_start <= b_end && b_start <= a_end
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deep::candidate::CandidateKind;
    use crate::types::Language;
    use std::fs;
    use std::path::PathBuf;
    use tempfile::tempdir;

    fn make_candidate(file: &str, language: Language) -> Candidate {
        Candidate {
            kind: CandidateKind::Escalation,
            file: PathBuf::from(file),
            language,
            line_start: 1,
            line_end: 100,
            source_snippet: String::new(),
            imports: Vec::new(),
            original_finding_id: Some("structural-1".into()),
            seed_category: Some(AuthCategory::Custom),
        }
    }

    fn make_seed(pattern_rule: Option<&str>) -> Finding {
        Finding {
            id: "structural-1".into(),
            file: PathBuf::from("src/auth.ts"),
            line_start: 5,
            line_end: 5,
            code_snippet: String::new(),
            language: Language::TypeScript,
            category: AuthCategory::Custom,
            confidence: Confidence::Low,
            description: "matched custom rule".into(),
            pattern_rule: pattern_rule.map(String::from),
            rego_stub: None,
            cedar_stub: None,
            pass: ScanPass::Structural,
            surface: Surface::Backend,
        }
    }

    fn make_semantic(line_start: usize, line_end: usize) -> SemanticFinding {
        SemanticFinding {
            line_start,
            line_end,
            category: AuthCategory::Rbac,
            confidence: Confidence::High,
            description: "isAdmin role check".into(),
            reasoning: "function name + return value structure indicates rbac".into(),
            is_false_positive: false,
        }
    }

    fn write_file(dir: &Path, name: &str, content: &str) -> PathBuf {
        let p = dir.join(name);
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&p, content).unwrap();
        p
    }

    #[test]
    fn into_finding_marks_pass_semantic() {
        let dir = tempdir().unwrap();
        write_file(
            dir.path(),
            "src/auth.ts",
            "line one\nline two\nline three\n",
        );
        let cand = make_candidate("src/auth.ts", Language::TypeScript);
        let sem = make_semantic(1, 2);
        let f = into_finding(sem, &cand, None, dir.path());
        assert_eq!(f.pass, ScanPass::Semantic);
    }

    #[test]
    fn into_finding_marks_seed_lineage_when_ranges_overlap() {
        // Regression: semantic findings used to inherit the seed's
        // `pattern_rule` verbatim, so a model-recategorized finding (e.g.
        // ownership seed → feature_gate verdict) would still display
        // `Rule: ts-ownership-check`. The fix preserves lineage but makes
        // clear the model produced the finding, not the structural rule.
        // Lineage only attaches when the model's range overlaps the seed —
        // this is the genuine re-evaluation case.
        let dir = tempdir().unwrap();
        write_file(dir.path(), "src/auth.ts", "line\n");
        let cand = make_candidate("src/auth.ts", Language::TypeScript);
        let seed = make_seed(Some("ts-foo")); // seed at line 5
        let sem = SemanticFinding {
            line_start: 4,
            line_end: 7,
            ..make_semantic(0, 0)
        }; // overlaps seed range 5-5
        let f = into_finding(sem, &cand, Some(&seed), dir.path());
        assert_eq!(f.pattern_rule.as_deref(), Some("ts-foo-semantic"));
    }

    #[test]
    fn into_finding_drops_seed_lineage_when_ranges_disjoint() {
        // Regression caught during manual walkthrough: an escalation
        // candidate's expanded context window covered an unrelated function
        // (`checkPermission` 17-23 lines below the seed at line 7), the model
        // returned a `feature_gate` finding for that incidental region, and
        // the finding was getting stamped `ts-ownership-check-semantic` —
        // misleading because that finding has nothing to do with the
        // ownership rule. Disjoint ranges → fall through to `semantic-{cat}`.
        let dir = tempdir().unwrap();
        write_file(dir.path(), "src/auth.ts", "line\n");
        let cand = make_candidate("src/auth.ts", Language::TypeScript);
        let seed = make_seed(Some("ts-ownership-check")); // seed at line 5
        let sem = SemanticFinding {
            line_start: 17,
            line_end: 23,
            category: AuthCategory::FeatureGate,
            ..make_semantic(0, 0)
        }; // entirely past the seed window
        let f = into_finding(sem, &cand, Some(&seed), dir.path());
        assert_eq!(f.pattern_rule.as_deref(), Some("semantic-feature_gate"));
    }

    #[test]
    fn into_finding_uses_synthetic_rule_id_for_cold_regions() {
        let dir = tempdir().unwrap();
        write_file(dir.path(), "src/auth.ts", "line\n");
        let cand = make_candidate("src/auth.ts", Language::TypeScript);
        let sem = make_semantic(1, 1); // category = Rbac
        let f = into_finding(sem, &cand, None, dir.path());
        // No structural seed → synthesize from the model's category so
        // consumers grouping by `pattern_rule` can still bucket cold-region
        // findings instead of seeing a raw `null`.
        assert_eq!(f.pattern_rule.as_deref(), Some("semantic-rbac"));
        // Determinism: two cold-regions at the same location produce the
        // same id (the rule id flows into the hash).
        let f2 = into_finding(make_semantic(1, 1), &cand, None, dir.path());
        assert_eq!(f.id, f2.id);
    }

    #[test]
    fn into_finding_id_differs_when_lines_differ() {
        let dir = tempdir().unwrap();
        write_file(
            dir.path(),
            "src/auth.ts",
            &(1..=20)
                .map(|i| format!("line {i}"))
                .collect::<Vec<_>>()
                .join("\n"),
        );
        let cand = make_candidate("src/auth.ts", Language::TypeScript);
        let f1 = into_finding(make_semantic(1, 1), &cand, None, dir.path());
        let f2 = into_finding(make_semantic(5, 5), &cand, None, dir.path());
        assert_ne!(f1.id, f2.id);
    }

    #[test]
    fn into_finding_extracts_code_snippet_from_file() {
        let dir = tempdir().unwrap();
        let content = (1..=10)
            .map(|i| format!("line {i}"))
            .collect::<Vec<_>>()
            .join("\n");
        write_file(dir.path(), "src/auth.ts", &content);
        let cand = make_candidate("src/auth.ts", Language::TypeScript);
        let f = into_finding(make_semantic(3, 5), &cand, None, dir.path());
        assert!(f.code_snippet.contains("line 3"));
        assert!(f.code_snippet.contains("line 4"));
        assert!(f.code_snippet.contains("line 5"));
        assert!(!f.code_snippet.contains("line 2"));
        assert!(!f.code_snippet.contains("line 6"));
    }

    #[test]
    fn into_finding_falls_back_to_empty_snippet_on_read_error() {
        let dir = tempdir().unwrap();
        // File doesn't exist AND the candidate has no source_snippet to
        // fall back to → last-resort empty string.
        let cand = make_candidate("nonexistent.ts", Language::TypeScript);
        let f = into_finding(make_semantic(1, 5), &cand, None, dir.path());
        assert_eq!(f.code_snippet, "");
        // Other fields are still populated.
        assert_eq!(f.pass, ScanPass::Semantic);
        assert_eq!(f.line_start, 1);
        assert_eq!(f.line_end, 5);
    }

    #[test]
    fn into_finding_falls_back_to_candidate_snippet_when_file_unreadable() {
        // Regression for corpus shakedown: 28 semantic findings shipped with
        // `code_snippet: ""` because filesystem read failed and we had no
        // fallback. The candidate's `source_snippet` is the same source the
        // model just analyzed — slice it instead of dropping the snippet.
        let dir = tempdir().unwrap();
        // Note: file is *not* created — extract_lines must fail.
        let mut cand = make_candidate("missing.ts", Language::TypeScript);
        cand.line_start = 10;
        cand.line_end = 14;
        cand.source_snippet = "line 10\nline 11\nline 12\nline 13\nline 14".to_string();

        // Model reports lines 11-12 within the candidate window.
        let sem = make_semantic(11, 12);
        let f = into_finding(sem, &cand, None, dir.path());

        assert!(f.code_snippet.contains("line 11"));
        assert!(f.code_snippet.contains("line 12"));
        assert!(!f.code_snippet.contains("line 10"));
        assert!(!f.code_snippet.contains("line 13"));
    }

    #[test]
    fn slice_candidate_snippet_rejects_ranges_outside_window() {
        let cand = Candidate {
            kind: CandidateKind::ColdRegion,
            file: PathBuf::from("a.ts"),
            language: Language::TypeScript,
            line_start: 10,
            line_end: 14,
            source_snippet: "line 10\nline 11\nline 12\nline 13\nline 14".to_string(),
            imports: Vec::new(),
            original_finding_id: None,
            seed_category: None,
        };
        // Below window.
        assert!(slice_candidate_snippet(&cand, 5, 8).is_none());
        // Above window.
        assert!(slice_candidate_snippet(&cand, 20, 22).is_none());
        // Reversed.
        assert!(slice_candidate_snippet(&cand, 12, 11).is_none());
        // Zero start (defensive — clamp_to_candidate normally drops these).
        assert!(slice_candidate_snippet(&cand, 0, 12).is_none());
        // Empty snippet.
        let mut empty = cand.clone();
        empty.source_snippet.clear();
        assert!(slice_candidate_snippet(&empty, 11, 12).is_none());
    }

    #[test]
    fn slice_candidate_snippet_clamps_when_snippet_was_truncated() {
        // Truncation at `max_prompt_chars` can leave the snippet shorter
        // than `[candidate.line_start, candidate.line_end]` would imply.
        // Tail offsets must clamp instead of panicking on out-of-bounds.
        let cand = Candidate {
            kind: CandidateKind::ColdRegion,
            file: PathBuf::from("a.ts"),
            language: Language::TypeScript,
            line_start: 10,
            line_end: 20, // candidate window claims 11 lines …
            source_snippet: "line 10\nline 11\nline 12".to_string(), // … but snippet has 3
            imports: Vec::new(),
            original_finding_id: None,
            seed_category: None,
        };
        // Model points at lines 11-15 — only 11 and 12 are in the truncated
        // snippet, so we should get those two and not panic.
        let got = slice_candidate_snippet(&cand, 11, 15).unwrap();
        assert!(got.contains("line 11"));
        assert!(got.contains("line 12"));
    }

    #[test]
    fn ranges_overlap_covers_inclusive_boundaries() {
        // Inclusive on both ends: touching at a single line counts as overlap.
        assert!(ranges_overlap(5, 10, 10, 15)); // touch at 10
        assert!(ranges_overlap(10, 15, 5, 10)); // symmetric
        assert!(ranges_overlap(5, 10, 7, 7)); // contained
        assert!(ranges_overlap(7, 7, 5, 10)); // contained, symmetric
        assert!(ranges_overlap(1, 100, 50, 60)); // wide vs narrow
        assert!(!ranges_overlap(5, 10, 11, 20)); // adjacent but disjoint
        assert!(!ranges_overlap(11, 20, 5, 10)); // adjacent but disjoint, sym
        assert!(!ranges_overlap(5, 5, 6, 6)); // single-line gap
    }

    #[test]
    fn category_slugs_round_trip() {
        // Slugs match output_schema enum values. Canonical impl moved to
        // `AuthCategory::slug` in src/types.rs.
        assert_eq!(AuthCategory::Rbac.slug(), "rbac");
        assert_eq!(AuthCategory::Abac.slug(), "abac");
        assert_eq!(AuthCategory::Middleware.slug(), "middleware");
        assert_eq!(AuthCategory::BusinessRule.slug(), "business_rule");
        assert_eq!(AuthCategory::Ownership.slug(), "ownership");
        assert_eq!(AuthCategory::FeatureGate.slug(), "feature_gate");
        assert_eq!(AuthCategory::Custom.slug(), "custom");
    }
}
