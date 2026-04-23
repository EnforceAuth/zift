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
    findings: &'a [Finding],
    summary: Summary,
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
        *by_category
            .entry(f.category.to_string().to_lowercase())
            .or_default() += 1;
        *by_confidence.entry(f.confidence.to_string()).or_default() += 1;
        files.insert(&f.file);
    }

    let report = ScanReport {
        version: env!("CARGO_PKG_VERSION"),
        scan_root,
        findings,
        summary: Summary {
            total_findings: findings.len(),
            enforcement_points,
            externalized_pct: if findings.is_empty() && enforcement_points == 0 {
                0
            } else {
                let total = findings.len() + enforcement_points;
                (enforcement_points as f64 / total as f64 * 100.0).round() as usize
            },
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
