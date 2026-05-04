use std::io::Write;
use std::path::Path;

use crate::error::Result;
use crate::types::Finding;

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
    let pct = (enforcement_points as f64 / total as f64 * 100.0).round() as usize;
    writeln!(
        writer,
        "Externalization: {pct}%  ({enforcement_points} externalized / {total} enforcement points)",
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

        writeln!(
            writer,
            "  {}:{}  [{}]  {}",
            finding.file.display(),
            finding.line_start,
            finding.category,
            finding.confidence,
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
