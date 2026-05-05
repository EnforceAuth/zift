//! Code-context expansion for deep-scan candidates.
//!
//! Two-tier strategy (see plans/todo/01-pr1-deep-http-transport.md §7):
//!
//! - **Fast path**: line-window `[start-5, end+15]` plus the first 20 lines
//!   of the file as imports. Works for all languages. **Implemented here.**
//! - **Smart path**: tree-sitter walk to enclosing function. Only available
//!   for languages with an integrated grammar. **TODO**:
//!   land in a follow-up commit; primary path is fast-path which is
//!   sufficient for v1. Most local 7B-14B models can figure out function
//!   boundaries from a generous line window with imports included.

use crate::deep::error::DeepError;
use crate::types::{Finding, Language};
use std::path::{Path, PathBuf};

const LINES_BEFORE: usize = 5;
const LINES_AFTER: usize = 15;
const IMPORT_LINES: usize = 20;
/// Per-import-line cap so a single 100KB minified line can't dominate the
/// imports payload.
const IMPORT_LINE_MAX_CHARS: usize = 200;
/// Cap the imports payload at this fraction of `max_chars` so it can never
/// crowd out the actual snippet. The remaining budget goes to snippet + marker.
const IMPORTS_BUDGET_FRACTION: f32 = 0.25;
const TRUNCATION_MARKER: &str = "\n// [truncated by zift deep-mode max_prompt_chars]";

/// Build at most `IMPORT_LINES` import strings whose combined length stays
/// within `total_budget`. Each line is also clamped to
/// `IMPORT_LINE_MAX_CHARS` so a single huge line can't consume the whole
/// budget. Truncation is rounded down to a UTF-8 char boundary so multi-byte
/// chars never split.
fn build_bounded_imports(lines: &[&str], total_budget: usize) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(IMPORT_LINES.min(lines.len()));
    let mut spent: usize = 0;
    for raw in lines.iter().take(IMPORT_LINES) {
        let mut line = (*raw).to_string();
        if line.len() > IMPORT_LINE_MAX_CHARS {
            let cut = line.floor_char_boundary(IMPORT_LINE_MAX_CHARS);
            line.truncate(cut);
        }
        // +1 accounts for the "\n" separator the caller adds when joining.
        let added = line.len() + 1;
        if spent.saturating_add(added) > total_budget {
            break;
        }
        spent += added;
        out.push(line);
    }
    out
}

#[derive(Debug, Clone)]
pub struct ExpandedContext {
    pub file_relative: PathBuf,
    pub language: Language,
    pub line_start: usize,
    pub line_end: usize,
    pub snippet: String,
    pub imports: Vec<String>,
}

/// Expand a structural finding's snippet to include surrounding lines and
/// file-level imports. `finding.file` is interpreted as relative to
/// `scan_root`.
///
/// Verifies that the resolved file path stays inside `scan_root` after
/// canonicalization — defense against absolute paths, `..` traversal, or
/// symlinks pointing outside the scanned tree leaking arbitrary local
/// files into deep-mode prompts.
pub fn expand_finding(
    finding: &Finding,
    scan_root: &Path,
    max_chars: usize,
) -> Result<ExpandedContext, DeepError> {
    let abs_path = ensure_within_scan_root(scan_root, &finding.file)?;
    expand_inner(
        &abs_path,
        finding.file.clone(),
        finding.language,
        finding.line_start,
        finding.line_end,
        max_chars,
    )
}

/// Resolve `scan_root.join(relative)` and verify the canonical result is a
/// descendant of canonical `scan_root`. Returns the canonical absolute path
/// on success; [`DeepError::Config`] on traversal attempts (so the error is
/// distinguishable from genuine I/O failures and the user-facing message
/// names the offending path).
fn ensure_within_scan_root(scan_root: &Path, relative: &Path) -> Result<PathBuf, DeepError> {
    let candidate = scan_root.join(relative);
    let canonical_root = scan_root.canonicalize()?;
    let canonical_path = candidate.canonicalize()?;
    if !canonical_path.starts_with(&canonical_root) {
        return Err(DeepError::Config(format!(
            "finding path {} resolves outside scan_root {}",
            canonical_path.display(),
            canonical_root.display(),
        )));
    }
    Ok(canonical_path)
}

/// Expand an arbitrary file region (used for `ColdRegion` candidates that
/// have no structural finding behind them). `file_absolute` must be readable;
/// `file_relative` is the path used in [`ExpandedContext::file_relative`].
pub fn expand_region(
    file_absolute: &Path,
    file_relative: PathBuf,
    language: Language,
    line_start: usize,
    line_end: usize,
    max_chars: usize,
) -> Result<ExpandedContext, DeepError> {
    expand_inner(
        file_absolute,
        file_relative,
        language,
        line_start,
        line_end,
        max_chars,
    )
}

fn expand_inner(
    file_absolute: &Path,
    file_relative: PathBuf,
    language: Language,
    line_start: usize,
    line_end: usize,
    max_chars: usize,
) -> Result<ExpandedContext, DeepError> {
    let content = std::fs::read_to_string(file_absolute)?;
    let lines: Vec<&str> = content.lines().collect();
    let total = lines.len();

    if total == 0 {
        return Ok(ExpandedContext {
            file_relative,
            language,
            line_start: 1,
            line_end: 1,
            snippet: String::new(),
            imports: Vec::new(),
        });
    }

    // Clamp inputs to the file.
    let start_1based = line_start.max(1).min(total);
    let end_1based = line_end.max(start_1based).min(total);

    // Apply line window. 1-based inclusive throughout.
    let window_start = start_1based.saturating_sub(LINES_BEFORE).max(1);
    let window_end = (end_1based + LINES_AFTER).min(total);

    // Build imports first so we know how much budget they consume against
    // `max_chars`. Cap each line at `IMPORT_LINE_MAX_CHARS` and the total at
    // `IMPORTS_BUDGET_FRACTION * max_chars` so a file full of giant generated
    // lines (minified bundles, codegen) can't blow the prompt size budget.
    let imports_budget = (max_chars as f32 * IMPORTS_BUDGET_FRACTION) as usize;
    let imports = build_bounded_imports(&lines, imports_budget);
    let imports_len: usize = imports.iter().map(|s| s.len()).sum::<usize>() + imports.len(); // +1 per for "\n" join

    // 0-based indexing into `lines`.
    let snippet_slice = &lines[(window_start - 1)..window_end];
    let mut snippet = snippet_slice.join("\n");

    // Truncate at max_chars (favors keeping the head — the part most likely
    // to contain the actual auth check; trailing context is more discardable).
    // Reserve space for both the truncation marker and the imports payload so
    // the combined `snippet + imports + marker` cannot exceed `max_chars`.
    // Round down to a UTF-8 char boundary to avoid `String::truncate` panics
    // on multi-byte chars (e.g. Unicode comments/identifiers in source).
    let snippet_budget = max_chars
        .saturating_sub(TRUNCATION_MARKER.len())
        .saturating_sub(imports_len);
    if snippet.len() > snippet_budget {
        let cut = snippet.floor_char_boundary(snippet_budget);
        snippet.truncate(cut);
        snippet.push_str(TRUNCATION_MARKER);
    }

    Ok(ExpandedContext {
        file_relative,
        language,
        line_start: window_start,
        line_end: window_end,
        snippet,
        imports,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{AuthCategory, Confidence, ScanPass, Surface};
    use std::fs;
    use std::path::PathBuf;
    use tempfile::tempdir;

    fn make_finding(file: PathBuf, line_start: usize, line_end: usize) -> Finding {
        Finding {
            id: "test".into(),
            file,
            line_start,
            line_end,
            code_snippet: String::new(),
            language: Language::TypeScript,
            category: AuthCategory::Custom,
            confidence: Confidence::Low,
            description: String::new(),
            pattern_rule: None,
            rego_stub: None,
            pass: ScanPass::Structural,
            surface: Surface::Backend,
        }
    }

    fn write_file(dir: &Path, name: &str, content: &str) -> PathBuf {
        let path = dir.join(name);
        fs::write(&path, content).unwrap();
        path
    }

    fn numbered_lines(n: usize) -> String {
        (1..=n)
            .map(|i| format!("line {i}"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn fast_path_basic_window() {
        let dir = tempdir().unwrap();
        write_file(dir.path(), "a.ts", &numbered_lines(50));
        let finding = make_finding(PathBuf::from("a.ts"), 20, 22);

        let ctx = expand_finding(&finding, dir.path(), 16_000).unwrap();
        assert_eq!(ctx.line_start, 15); // 20 - 5
        assert_eq!(ctx.line_end, 37); // 22 + 15
        assert!(ctx.snippet.contains("line 20"));
        assert!(ctx.snippet.contains("line 15"));
        assert!(ctx.snippet.contains("line 37"));
        assert!(!ctx.snippet.contains("line 14"));
        assert!(!ctx.snippet.contains("line 38"));
    }

    #[test]
    fn window_clamps_at_file_start() {
        let dir = tempdir().unwrap();
        write_file(dir.path(), "a.ts", &numbered_lines(50));
        let finding = make_finding(PathBuf::from("a.ts"), 1, 1);

        let ctx = expand_finding(&finding, dir.path(), 16_000).unwrap();
        assert_eq!(ctx.line_start, 1);
        assert_eq!(ctx.line_end, 16); // 1 + 15
    }

    #[test]
    fn window_clamps_at_file_end() {
        let dir = tempdir().unwrap();
        write_file(dir.path(), "a.ts", &numbered_lines(20));
        let finding = make_finding(PathBuf::from("a.ts"), 18, 20);

        let ctx = expand_finding(&finding, dir.path(), 16_000).unwrap();
        assert_eq!(ctx.line_start, 13); // 18 - 5
        assert_eq!(ctx.line_end, 20); // clamped at total
    }

    #[test]
    fn line_beyond_eof_is_clamped() {
        let dir = tempdir().unwrap();
        write_file(dir.path(), "a.ts", &numbered_lines(10));
        let finding = make_finding(PathBuf::from("a.ts"), 999, 1000);

        let ctx = expand_finding(&finding, dir.path(), 16_000).unwrap();
        // Should not panic. Clamped to file length.
        assert_eq!(ctx.line_start, 5); // 10 - 5
        assert_eq!(ctx.line_end, 10);
    }

    #[test]
    fn empty_file_returns_empty_snippet() {
        let dir = tempdir().unwrap();
        write_file(dir.path(), "a.ts", "");
        let finding = make_finding(PathBuf::from("a.ts"), 1, 1);

        let ctx = expand_finding(&finding, dir.path(), 16_000).unwrap();
        assert!(ctx.snippet.is_empty());
        assert!(ctx.imports.is_empty());
    }

    #[test]
    fn imports_are_first_20_lines() {
        let dir = tempdir().unwrap();
        write_file(dir.path(), "a.ts", &numbered_lines(100));
        let finding = make_finding(PathBuf::from("a.ts"), 50, 50);

        let ctx = expand_finding(&finding, dir.path(), 16_000).unwrap();
        assert_eq!(ctx.imports.len(), 20);
        assert_eq!(ctx.imports[0], "line 1");
        assert_eq!(ctx.imports[19], "line 20");
    }

    #[test]
    fn imports_capped_at_file_length() {
        let dir = tempdir().unwrap();
        write_file(dir.path(), "a.ts", &numbered_lines(5));
        let finding = make_finding(PathBuf::from("a.ts"), 1, 1);

        let ctx = expand_finding(&finding, dir.path(), 16_000).unwrap();
        assert_eq!(ctx.imports.len(), 5);
    }

    #[test]
    fn truncation_at_max_chars() {
        let dir = tempdir().unwrap();
        let content = (1..=200)
            .map(|i| format!("a long line of repeated text {i} ").repeat(20))
            .collect::<Vec<_>>()
            .join("\n");
        write_file(dir.path(), "a.ts", &content);
        let finding = make_finding(PathBuf::from("a.ts"), 100, 100);

        let ctx = expand_finding(&finding, dir.path(), 500).unwrap();
        // snippet + imports + marker is the full prompt-payload budget.
        let imports_len: usize =
            ctx.imports.iter().map(|s| s.len()).sum::<usize>() + ctx.imports.len();
        assert!(
            ctx.snippet.len() + imports_len <= 500,
            "snippet({}) + imports({}) exceeded max_chars=500",
            ctx.snippet.len(),
            imports_len,
        );
        assert!(ctx.snippet.contains("[truncated"));
    }

    #[test]
    fn combined_budget_includes_marker_and_imports() {
        // Snippet truncation must reserve room for the marker AND the
        // imports payload — otherwise concatenated payload busts max_chars.
        let dir = tempdir().unwrap();
        // Long imports + long snippet, both pressuring the budget.
        let mut content = String::new();
        for i in 1..=20 {
            content.push_str(&format!("import line {i} ").repeat(30));
            content.push('\n');
        }
        content.push_str(&"x".repeat(5_000));
        write_file(dir.path(), "a.ts", &content);
        let finding = make_finding(PathBuf::from("a.ts"), 21, 21);

        let max = 1_000;
        let ctx = expand_finding(&finding, dir.path(), max).unwrap();
        let imports_len: usize =
            ctx.imports.iter().map(|s| s.len()).sum::<usize>() + ctx.imports.len();
        assert!(
            ctx.snippet.len() + imports_len <= max,
            "snippet({}) + imports({}) > max_chars={max}",
            ctx.snippet.len(),
            imports_len,
        );
    }

    #[test]
    fn long_imports_clamped_per_line() {
        // A single 100KB minified line in the imports region must not
        // explode the prompt size.
        let dir = tempdir().unwrap();
        let mut content = String::new();
        content.push_str(&"x".repeat(100_000));
        content.push('\n');
        content.push_str(&numbered_lines(50));
        write_file(dir.path(), "a.ts", &content);
        let finding = make_finding(PathBuf::from("a.ts"), 30, 30);

        let ctx = expand_finding(&finding, dir.path(), 16_000).unwrap();
        for (i, imp) in ctx.imports.iter().enumerate() {
            assert!(
                imp.len() <= IMPORT_LINE_MAX_CHARS,
                "import[{i}] length {} > {IMPORT_LINE_MAX_CHARS}",
                imp.len(),
            );
        }
    }

    #[test]
    fn truncation_does_not_panic_on_multibyte_boundary() {
        // Build a snippet whose byte length exceeds max_chars and whose
        // truncation point lands inside a multi-byte char. Naive truncate
        // would panic.
        let dir = tempdir().unwrap();
        let mut content = String::new();
        // 198 ascii bytes, then a 4-byte emoji that crosses byte 200.
        content.push_str(&"a".repeat(198));
        content.push('🦀');
        content.push_str(&"b".repeat(200));
        write_file(dir.path(), "a.ts", &content);
        let finding = make_finding(PathBuf::from("a.ts"), 1, 1);

        // No panic — boundary-rounded truncate keeps us valid.
        let ctx = expand_finding(&finding, dir.path(), 200).unwrap();
        assert!(ctx.snippet.contains("[truncated"));
    }

    #[test]
    fn expand_finding_rejects_dotdot_traversal() {
        // Layout: scan_root/inner/, with secret outside scan_root that the
        // attacker tries to read via `../secret.txt`.
        let dir = tempdir().unwrap();
        let scan_root = dir.path().join("inner");
        fs::create_dir_all(&scan_root).unwrap();
        write_file(dir.path(), "secret.txt", "leaked");
        // Need a file inside scan_root for canonicalize to succeed at all,
        // otherwise the test fails for the wrong reason.
        write_file(&scan_root, "ok.ts", "x");

        let finding = make_finding(PathBuf::from("../secret.txt"), 1, 1);
        let err = expand_finding(&finding, &scan_root, 16_000).unwrap_err();
        assert!(
            matches!(err, DeepError::Config(ref msg) if msg.contains("outside scan_root")),
            "expected Config error, got: {err:?}",
        );
    }

    #[test]
    fn expand_finding_rejects_absolute_path_outside_scan_root() {
        let dir = tempdir().unwrap();
        let scan_root = dir.path().join("inner");
        fs::create_dir_all(&scan_root).unwrap();
        let outside = write_file(dir.path(), "outside.ts", "x");
        write_file(&scan_root, "ok.ts", "x");

        let finding = make_finding(outside.clone(), 1, 1);
        let err = expand_finding(&finding, &scan_root, 16_000).unwrap_err();
        assert!(
            matches!(err, DeepError::Config(ref msg) if msg.contains("outside scan_root")),
            "expected Config error, got: {err:?}",
        );
    }

    #[test]
    fn expand_region_uses_relative_path_in_output() {
        let dir = tempdir().unwrap();
        let abs_path = write_file(dir.path(), "auth.py", &numbered_lines(30));

        let ctx = expand_region(
            &abs_path,
            PathBuf::from("auth.py"),
            Language::Python,
            10,
            12,
            16_000,
        )
        .unwrap();
        assert_eq!(ctx.file_relative, PathBuf::from("auth.py"));
        assert_eq!(ctx.language, Language::Python);
        assert_eq!(ctx.line_start, 5);
        assert_eq!(ctx.line_end, 27);
    }
}
