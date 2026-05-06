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
    /// the text formatter.
    ///
    /// `externalized_pct` is also exposed inside `summary` for back-compat,
    /// and `summary.enforcement_points` carries the same count as
    /// `headline.externalized` (under its older, narrower name).
    /// `embedded_findings` and `total_enforcement_points` are headline-only.
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
    /// external policy engine (numerator behind `externalized_pct`).
    externalized: usize,
    /// Authorization decisions found embedded in source code (i.e. the
    /// findings count) — the piece of the surface still to externalize.
    embedded_findings: usize,
    /// `externalized + embedded_findings` — every place an authorization
    /// decision is made, externalized or not. Denominator behind
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
    let externalized_pct = super::externalized_pct(enforcement_points, findings.len());

    let report = ScanReport {
        version: env!("CARGO_PKG_VERSION"),
        scan_root,
        headline: Headline {
            externalized_pct,
            externalized: enforcement_points,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{AuthCategory, Confidence, Language, ScanPass, Surface};
    use std::path::PathBuf;

    fn finding() -> Finding {
        Finding {
            id: "x".into(),
            file: PathBuf::from("src/foo.rs"),
            line_start: 1,
            line_end: 1,
            code_snippet: "if user.is_admin {}".into(),
            language: Language::Java,
            category: AuthCategory::Rbac,
            confidence: Confidence::High,
            description: "embedded role check".into(),
            pattern_rule: None,
            rego_stub: None,
            cedar_stub: None,
            pass: ScanPass::Structural,
            surface: Surface::Backend,
        }
    }

    fn render(findings: &[Finding], enforcement_points: usize) -> serde_json::Value {
        let mut buf: Vec<u8> = Vec::new();
        print(findings, Path::new("."), enforcement_points, &mut buf).unwrap();
        serde_json::from_slice(&buf).unwrap()
    }

    #[test]
    fn headline_no_signal() {
        let v = render(&[], 0);
        let h = &v["headline"];
        assert_eq!(h["externalized_pct"], 0);
        assert_eq!(h["externalized"], 0);
        assert_eq!(h["embedded_findings"], 0);
        assert_eq!(h["total_enforcement_points"], 0);
    }

    #[test]
    fn headline_zero_pct() {
        let v = render(&[finding(), finding()], 0);
        let h = &v["headline"];
        assert_eq!(h["externalized_pct"], 0);
        assert_eq!(h["externalized"], 0);
        assert_eq!(h["embedded_findings"], 2);
        assert_eq!(h["total_enforcement_points"], 2);
    }

    #[test]
    fn headline_full_externalization() {
        let v = render(&[], 5);
        let h = &v["headline"];
        assert_eq!(h["externalized_pct"], 100);
        assert_eq!(h["externalized"], 5);
        assert_eq!(h["embedded_findings"], 0);
        assert_eq!(h["total_enforcement_points"], 5);
    }

    #[test]
    fn headline_mixed_rounded() {
        // 1 externalized of 3 → 33%.
        let v = render(&[finding(), finding()], 1);
        let h = &v["headline"];
        assert_eq!(h["externalized_pct"], 33);
        assert_eq!(h["externalized"], 1);
        assert_eq!(h["embedded_findings"], 2);
        assert_eq!(h["total_enforcement_points"], 3);
    }

    #[test]
    fn summary_keeps_back_compat_fields() {
        // `summary.enforcement_points` and `summary.externalized_pct` must
        // continue to carry the same counts as the headline so existing
        // consumers don't break.
        let v = render(&[finding(), finding()], 1);
        assert_eq!(v["summary"]["enforcement_points"], 1);
        assert_eq!(v["summary"]["externalized_pct"], 33);
        assert_eq!(v["summary"]["total_findings"], 2);
    }
}
