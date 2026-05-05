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
    if findings.is_empty() {
        writeln!(writer, "No authorization patterns found.")?;
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

    if enforcement_points > 0 {
        let total = findings.len() + enforcement_points;
        let pct = (enforcement_points as f64 / total as f64 * 100.0).round() as usize;
        writeln!(
            writer,
            "       {enforcement_points} enforcement points (already using a policy engine, not flagged) — {pct}% externalized",
        )?;
    }

    Ok(())
}
