//! Merge semantic findings into the structural-pass finding set.
//!
//! Rules:
//!
//! - A semantic finding overlapping a structural finding's range (>= 50%
//!   overlap, same file) **replaces** the structural one iff
//!   `semantic.confidence >= structural.confidence`.
//! - A semantic finding with no overlap is appended.
//!
//! Overlap is computed as `intersection / max(range_a, range_b)`. Using max
//! (rather than min) is the conservative choice — a tiny semantic finding
//! that lands inside a sprawling structural one only counts as a near-match
//! if the larger range is also small.
//!
//! False-positive drops happen *before* merge in the orchestrator
//! ([`crate::deep::run`]), so the structural slice arriving here has already
//! had model-rejected entries removed.

use crate::types::Finding;

pub fn merge(mut structural: Vec<Finding>, semantic: Vec<Finding>) -> Vec<Finding> {
    for sem in semantic {
        let replace_idx = structural.iter().position(|s| {
            s.file == sem.file
                && range_overlap_fraction(s.line_start, s.line_end, sem.line_start, sem.line_end)
                    >= 0.5
                && sem.confidence >= s.confidence
        });
        match replace_idx {
            Some(idx) => {
                tracing::debug!(
                    "merge: semantic finding replaces structural at {}:{}-{}",
                    sem.file.display(),
                    sem.line_start,
                    sem.line_end
                );
                structural[idx] = sem;
            }
            None => structural.push(sem),
        }
    }
    structural
}

fn range_overlap_fraction(a_start: usize, a_end: usize, b_start: usize, b_end: usize) -> f32 {
    let overlap_start = a_start.max(b_start);
    let overlap_end = a_end.min(b_end);
    if overlap_start > overlap_end {
        return 0.0;
    }
    let overlap_lines = (overlap_end - overlap_start + 1) as f32;
    let max_range = (a_end - a_start + 1).max(b_end - b_start + 1) as f32;
    overlap_lines / max_range
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{AuthCategory, Confidence, Language, ScanPass, Surface};
    use std::path::PathBuf;

    fn finding(
        file: &str,
        start: usize,
        end: usize,
        confidence: Confidence,
        pass: ScanPass,
    ) -> Finding {
        Finding {
            id: format!("{file}-{start}-{end}-{pass:?}"),
            file: PathBuf::from(file),
            line_start: start,
            line_end: end,
            code_snippet: String::new(),
            language: Language::TypeScript,
            category: AuthCategory::Custom,
            confidence,
            description: String::new(),
            pattern_rule: None,
            policy_outputs: vec![],
            pass,
            surface: Surface::Backend,
            provenance: None,
        }
    }

    #[test]
    fn non_overlapping_findings_both_kept() {
        let s = finding("a.ts", 10, 15, Confidence::Medium, ScanPass::Structural);
        let sem = finding("a.ts", 50, 60, Confidence::High, ScanPass::Semantic);
        let merged = merge(vec![s], vec![sem]);
        assert_eq!(merged.len(), 2);
    }

    #[test]
    fn overlapping_higher_confidence_replaces() {
        let s = finding("a.ts", 10, 15, Confidence::Low, ScanPass::Structural);
        let sem = finding("a.ts", 10, 15, Confidence::High, ScanPass::Semantic);
        let merged = merge(vec![s], vec![sem]);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].pass, ScanPass::Semantic);
        assert_eq!(merged[0].confidence, Confidence::High);
    }

    #[test]
    fn overlapping_equal_confidence_replaces() {
        // Equal confidence still replaces — semantic has more reasoning attached.
        let s = finding("a.ts", 10, 15, Confidence::Medium, ScanPass::Structural);
        let sem = finding("a.ts", 10, 15, Confidence::Medium, ScanPass::Semantic);
        let merged = merge(vec![s], vec![sem]);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].pass, ScanPass::Semantic);
    }

    #[test]
    fn overlapping_lower_confidence_keeps_both() {
        let s = finding("a.ts", 10, 15, Confidence::High, ScanPass::Structural);
        let sem = finding("a.ts", 10, 15, Confidence::Low, ScanPass::Semantic);
        let merged = merge(vec![s], vec![sem]);
        assert_eq!(merged.len(), 2);
        assert!(merged.iter().any(|f| f.pass == ScanPass::Structural));
        assert!(merged.iter().any(|f| f.pass == ScanPass::Semantic));
    }

    #[test]
    fn different_files_never_merge() {
        let s = finding("a.ts", 10, 15, Confidence::Low, ScanPass::Structural);
        let sem = finding("b.ts", 10, 15, Confidence::High, ScanPass::Semantic);
        let merged = merge(vec![s], vec![sem]);
        assert_eq!(merged.len(), 2);
    }

    #[test]
    fn partial_overlap_below_threshold_keeps_both() {
        // Structural: lines 10-30 (21 lines)
        // Semantic: lines 28-32 (5 lines)
        // Overlap: 28-30 = 3 lines, max range = 21 → 3/21 ≈ 14% — keeps both.
        let s = finding("a.ts", 10, 30, Confidence::Low, ScanPass::Structural);
        let sem = finding("a.ts", 28, 32, Confidence::High, ScanPass::Semantic);
        let merged = merge(vec![s], vec![sem]);
        assert_eq!(merged.len(), 2);
    }

    #[test]
    fn substantial_overlap_above_threshold_replaces() {
        // Structural: lines 10-20 (11 lines)
        // Semantic: lines 11-19 (9 lines)
        // Overlap: 11-19 = 9 lines, max range = 11 → 9/11 ≈ 82% — replaces.
        let s = finding("a.ts", 10, 20, Confidence::Low, ScanPass::Structural);
        let sem = finding("a.ts", 11, 19, Confidence::High, ScanPass::Semantic);
        let merged = merge(vec![s], vec![sem]);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].pass, ScanPass::Semantic);
    }

    #[test]
    fn empty_inputs_return_empty() {
        assert!(merge(vec![], vec![]).is_empty());
    }

    #[test]
    fn semantic_only_returns_semantic() {
        let sem = finding("a.ts", 10, 15, Confidence::High, ScanPass::Semantic);
        let merged = merge(vec![], vec![sem]);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].pass, ScanPass::Semantic);
    }

    #[test]
    fn structural_only_returns_structural() {
        let s = finding("a.ts", 10, 15, Confidence::Medium, ScanPass::Structural);
        let merged = merge(vec![s], vec![]);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].pass, ScanPass::Structural);
    }

    #[test]
    fn overlap_fraction_computation() {
        // Identical ranges → 1.0
        assert!((range_overlap_fraction(10, 20, 10, 20) - 1.0).abs() < 1e-6);
        // No overlap → 0.0
        assert_eq!(range_overlap_fraction(10, 20, 30, 40), 0.0);
        // 50% overlap, equal-sized: 5/10 = 0.5
        let f = range_overlap_fraction(10, 19, 15, 24);
        assert!((f - 0.5).abs() < 1e-6, "expected 0.5, got {f}");
    }
}
