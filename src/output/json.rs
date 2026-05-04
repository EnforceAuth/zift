use std::collections::HashMap;
use std::io::Write;
use std::path::Path;

use serde::Serialize;

use crate::error::Result;
use crate::types::Finding;

#[derive(Serialize)]
struct ScanReport<'a> {
    version: &'static str,
    scan_root: &'a Path,
    /// Top-level headline so `jq .headline scan.json` is the one-liner for
    /// "share the externalization number back". Mirrors the leading line of
    /// the text formatter. The same numbers also appear inside `summary`,
    /// so existing consumers keep working.
    headline: Headline,
    findings: &'a [Finding],
    summary: Summary,
}

#[derive(Serialize)]
struct Headline {
    /// Fraction of identified enforcement points that already consult an
    /// external policy engine, as a 0–100 integer percentage.
    externalized_pct: usize,
    /// Enforcement points that were detected as already going through an
    /// external policy engine (numerator).
    enforcement_points: usize,
    /// Authorization decisions found embedded in source code (i.e. the
    /// findings count) — the piece of the surface still to externalize.
    embedded_findings: usize,
    /// `enforcement_points + embedded_findings` — the denominator behind
    /// `externalized_pct`.
    total_enforcement_points: usize,
}

#[derive(Serialize)]
struct Summary {
    total_findings: usize,
    enforcement_points: usize,
    externalized_pct: usize,
    by_category: HashMap<String, usize>,
    by_confidence: HashMap<String, usize>,
    files_with_findings: usize,
}

pub fn print(
    findings: &[Finding],
    scan_root: &Path,
    enforcement_points: usize,
    writer: &mut dyn Write,
) -> Result<()> {
    let mut by_category: HashMap<String, usize> = HashMap::new();
    let mut by_confidence: HashMap<String, usize> = HashMap::new();
    let mut files = std::collections::HashSet::new();

    for f in findings {
        // Use the canonical snake_case wire form so summary keys round-trip
        // against `findings[].category` in the same document. The Display impl
        // produces a human-friendly form (`"Business Rule"` → lowercased
        // `"business rule"` with a space), which disagrees with the serde
        // form (`"business_rule"`) on multi-word variants and breaks
        // consumers grouping the summary by category.
        *by_category
            .entry(f.category.slug().to_string())
            .or_default() += 1;
        *by_confidence.entry(f.confidence.to_string()).or_default() += 1;
        files.insert(&f.file);
    }

    let total = findings.len() + enforcement_points;
    let externalized_pct = if total == 0 {
        0
    } else {
        (enforcement_points as f64 / total as f64 * 100.0).round() as usize
    };

    let report = ScanReport {
        version: env!("CARGO_PKG_VERSION"),
        scan_root,
        headline: Headline {
            externalized_pct,
            enforcement_points,
            embedded_findings: findings.len(),
            total_enforcement_points: total,
        },
        findings,
        summary: Summary {
            total_findings: findings.len(),
            enforcement_points,
            externalized_pct,
            by_category,
            by_confidence,
            files_with_findings: files.len(),
        },
    };

    serde_json::to_writer_pretty(writer, &report)?;
    Ok(())
}

impl From<serde_json::Error> for crate::error::ZiftError {
    fn from(e: serde_json::Error) -> Self {
        crate::error::ZiftError::General(format!("JSON serialization error: {e}"))
    }
}
