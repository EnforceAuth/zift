//! Code-context expansion for deep-scan candidates.
//!
//! Two-tier strategy (see plans/todo/01-pr1-deep-http-transport.md §7):
//!
//! - **Fast path**: line-window `[start-5, end+15]` plus the first 20 lines
//!   of the file as imports. Works for all languages. **Implemented here.**
//! - **Smart path**: tree-sitter walk to enclosing function. Only available
//!   for languages with an integrated grammar (TS/JS/Java today). **TODO**:
//!   land in a follow-up commit; primary path is fast-path which is
//!   sufficient for v1. Most local 7B-14B models can figure out function
//!   boundaries from a generous line window with imports included.

use crate::deep::error::DeepError;
use crate::types::{Finding, Language};
use std::path::{Path, PathBuf};

const LINES_BEFORE: usize = 5;
const LINES_AFTER: usize = 15;
const IMPORT_LINES: usize = 20;

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
pub fn expand_finding(
    finding: &Finding,
    scan_root: &Path,
    max_chars: usize,
) -> Result<ExpandedContext, DeepError> {
    let abs_path = scan_root.join(&finding.file);
    expand_inner(
        &abs_path,
        finding.file.clone(),
        finding.language,
        finding.line_start,
        finding.line_end,
        max_chars,
    )
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

    // 0-based indexing into `lines`.
    let snippet_slice = &lines[(window_start - 1)..window_end];
    let mut snippet = snippet_slice.join("\n");

    // Truncate at max_chars (favors keeping the head — the part most likely
    // to contain the actual auth check; trailing context is more discardable).
    // Round down to a UTF-8 char boundary to avoid `String::truncate` panics
    // on multi-byte chars (e.g. Unicode comments/identifiers in source).
    if snippet.len() > max_chars {
        let cut = snippet.floor_char_boundary(max_chars);
        snippet.truncate(cut);
        snippet.push_str("\n// [truncated by zift deep-mode max_prompt_chars]");
    }

    let imports: Vec<String> = lines
        .iter()
        .take(IMPORT_LINES)
        .map(|s| (*s).to_string())
        .collect();

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
    use crate::types::{AuthCategory, Confidence, ScanPass};
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
        assert!(ctx.snippet.len() < 600); // 500 + tail marker
        assert!(ctx.snippet.contains("[truncated"));
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
