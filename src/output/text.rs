use std::io::Write;
use std::path::Path;

use crate::error::Result;
use crate::types::{Finding, Surface};

pub fn print(
    findings: &[Finding],
    _scan_root: &Path,
    enforcement_points: usize,
    writer: &mut dyn Write,
) -> Result<()> {
    let total = findings.len() + enforcement_points;

    if total == 0 {
        writeln!(writer, "No authorization patterns found.")?;
        return Ok(());
    }

    // Headline: the externalization percentage. This is the unit of
    // progress the v0.1 launch asks every adopter to share back, so it
    // leads the report and is emitted unconditionally — including the
    // 0% case, which is the case worth shouting about.
    let pct = super::externalized_pct(enforcement_points, findings.len());
    writeln!(
        writer,
        "Externalization: {pct}% ({enforcement_points} externalized / {total} enforcement points)",
    )?;
    writeln!(writer)?;

    if findings.is_empty() {
        // 100% externalized — headline says it all, nothing to enumerate.
        return Ok(());
    }

    for (i, finding) in findings.iter().enumerate() {
        if i > 0 {
            writeln!(writer, "---")?;
            writeln!(writer)?;
        }

        // Tag frontend-surface findings inline so reviewers can scan past
        // the UI-state noise (e.g. `web/src/foo.ts` ownership matches that
        // are "is this me?" checks, not security gates) without diving into
        // the JSON. Backend is the default — no tag, less visual noise.
        let surface_tag = match finding.surface {
            Surface::Frontend => "  [frontend]",
            Surface::Backend => "",
        };
        writeln!(
            writer,
            "  {}:{}  [{}]  {}{}",
            finding.file.display(),
            finding.line_start,
            finding.category,
            finding.confidence,
            surface_tag,
        )?;

        writeln!(writer, "  {}", finding.description)?;

        if let Some(rule) = &finding.pattern_rule {
            writeln!(writer, "  Rule: {rule}")?;
        }

        writeln!(writer)?;

        // Print code snippet with line numbers
        let lines: Vec<&str> = finding.code_snippet.lines().collect();
        for (offset, line) in lines.iter().enumerate() {
            let line_num = finding.line_start + offset;
            writeln!(writer, "    {line_num:>4} | {line}")?;
        }

        writeln!(writer)?;
    }

    // Summary
    let high = findings
        .iter()
        .filter(|f| f.confidence == crate::types::Confidence::High)
        .count();
    let medium = findings
        .iter()
        .filter(|f| f.confidence == crate::types::Confidence::Medium)
        .count();
    let low = findings
        .iter()
        .filter(|f| f.confidence == crate::types::Confidence::Low)
        .count();
    let file_count = {
        let mut files = std::collections::HashSet::new();
        for f in findings {
            files.insert(&f.file);
        }
        files.len()
    };

    write!(
        writer,
        "Summary: {} findings in {} files",
        findings.len(),
        file_count,
    )?;

    let mut parts = Vec::new();
    if high > 0 {
        parts.push(format!("{high} high"));
    }
    if medium > 0 {
        parts.push(format!("{medium} medium"));
    }
    if low > 0 {
        parts.push(format!("{low} low"));
    }
    if !parts.is_empty() {
        write!(writer, " ({})", parts.join(", "))?;
    }
    writeln!(writer)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{AuthCategory, Confidence, Finding, Language, ScanPass};
    use std::path::PathBuf;

    fn finding(confidence: Confidence) -> Finding {
        Finding {
            id: "x".into(),
            file: PathBuf::from("src/foo.rs"),
            line_start: 1,
            line_end: 1,
            code_snippet: "if user.is_admin {}".into(),
            language: Language::Java,
            category: AuthCategory::Rbac,
            confidence,
            description: "embedded role check".into(),
            pattern_rule: None,
            rego_stub: None,
            pass: ScanPass::Structural,
        }
    }

    fn render(findings: &[Finding], enforcement_points: usize) -> String {
        let mut buf: Vec<u8> = Vec::new();
        print(findings, Path::new("."), enforcement_points, &mut buf).unwrap();
        String::from_utf8(buf).unwrap()
    }

    #[test]
    fn no_signal_emits_no_patterns_message() {
        let out = render(&[], 0);
        assert_eq!(out, "No authorization patterns found.\n");
    }

    #[test]
    fn zero_pct_still_emits_headline() {
        // The case worth shouting about: every authz site is embedded.
        let out = render(&[finding(Confidence::High), finding(Confidence::Low)], 0);
        assert!(
            out.starts_with("Externalization: 0% (0 externalized / 2 enforcement points)\n"),
            "got: {out}"
        );
    }

    #[test]
    fn full_externalization_emits_only_headline_and_returns() {
        // Regression: previously `findings.is_empty()` short-circuited
        // before the externalization line, so 100% scans printed nothing.
        let out = render(&[], 5);
        assert_eq!(
            out,
            "Externalization: 100% (5 externalized / 5 enforcement points)\n\n"
        );
    }

    #[test]
    fn mixed_headline_uses_rounded_pct() {
        // 1 externalized of 3 total → 33%.
        let out = render(&[finding(Confidence::High), finding(Confidence::Medium)], 1);
        assert!(
            out.starts_with("Externalization: 33% (1 externalized / 3 enforcement points)\n"),
            "got: {out}"
        );
        // Per-finding details still rendered.
        assert!(out.contains("Summary: 2 findings"));
    }
}
