//! LLM-side finding shape and translation to the canonical [`Finding`].

use crate::deep::candidate::Candidate;
use crate::scanner::matcher::compute_finding_id;
use crate::types::{AuthCategory, Confidence, Finding, ScanPass};
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
/// file is unreadable (e.g. moved between scan and analyze), `code_snippet`
/// falls back to the empty string — best-effort, do not fail the finding.
pub fn into_finding(
    sem: SemanticFinding,
    candidate: &Candidate,
    seed: Option<&Finding>,
    scan_root: &Path,
) -> Finding {
    tracing::debug!(
        file = %candidate.file.display(),
        lines = format!("{}-{}", sem.line_start, sem.line_end),
        category = ?sem.category,
        confidence = ?sem.confidence,
        is_false_positive = sem.is_false_positive,
        reasoning = %sem.reasoning,
        "semantic finding"
    );

    let rule_id = match seed.and_then(|s| s.pattern_rule.as_deref()) {
        Some(pr) => format!("{pr}-semantic"),
        None => format!("semantic-{}", category_slug(sem.category)),
    };

    let code_snippet =
        extract_lines(scan_root, &candidate.file, sem.line_start, sem.line_end).unwrap_or_default();

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
        pattern_rule: seed.and_then(|s| s.pattern_rule.clone()),
        rego_stub: None, // structural-only; semantic findings have no rego template
        pass: ScanPass::Semantic,
    }
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
    let s = (start - 1).min(lines.len() - 1);
    let e = end.min(lines.len()).max(s + 1);
    Some(lines[s..e].join("\n"))
}

fn category_slug(cat: AuthCategory) -> &'static str {
    match cat {
        AuthCategory::Rbac => "rbac",
        AuthCategory::Abac => "abac",
        AuthCategory::Middleware => "middleware",
        AuthCategory::BusinessRule => "business_rule",
        AuthCategory::Ownership => "ownership",
        AuthCategory::FeatureGate => "feature_gate",
        AuthCategory::Custom => "custom",
    }
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
            pass: ScanPass::Structural,
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
    fn into_finding_inherits_pattern_rule_from_seed() {
        let dir = tempdir().unwrap();
        write_file(dir.path(), "src/auth.ts", "line\n");
        let cand = make_candidate("src/auth.ts", Language::TypeScript);
        let sem = make_semantic(1, 1);
        let seed = make_seed(Some("ts-foo"));
        let f = into_finding(sem, &cand, Some(&seed), dir.path());
        assert_eq!(f.pattern_rule.as_deref(), Some("ts-foo"));
    }

    #[test]
    fn into_finding_uses_synthetic_rule_id_for_cold_regions() {
        let dir = tempdir().unwrap();
        write_file(dir.path(), "src/auth.ts", "line\n");
        let cand = make_candidate("src/auth.ts", Language::TypeScript);
        let sem = make_semantic(1, 1);
        let f = into_finding(sem, &cand, None, dir.path());
        // No structural seed, no pattern_rule on the resulting Finding.
        assert!(f.pattern_rule.is_none());
        // But the deterministic id is computed using a "semantic-rbac"-style
        // synthetic rule id (we can't observe this directly, but we can
        // observe that two cold-regions in the same place produce the same id).
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
        // File doesn't exist.
        let cand = make_candidate("nonexistent.ts", Language::TypeScript);
        let f = into_finding(make_semantic(1, 5), &cand, None, dir.path());
        assert_eq!(f.code_snippet, "");
        // Other fields are still populated.
        assert_eq!(f.pass, ScanPass::Semantic);
        assert_eq!(f.line_start, 1);
        assert_eq!(f.line_end, 5);
    }

    #[test]
    fn category_slugs_round_trip() {
        // Slugs match output_schema enum values.
        assert_eq!(category_slug(AuthCategory::Rbac), "rbac");
        assert_eq!(category_slug(AuthCategory::Abac), "abac");
        assert_eq!(category_slug(AuthCategory::Middleware), "middleware");
        assert_eq!(category_slug(AuthCategory::BusinessRule), "business_rule");
        assert_eq!(category_slug(AuthCategory::Ownership), "ownership");
        assert_eq!(category_slug(AuthCategory::FeatureGate), "feature_gate");
        assert_eq!(category_slug(AuthCategory::Custom), "custom");
    }
}
