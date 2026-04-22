pub mod discovery;
pub mod imports;
pub mod matcher;
pub mod parser;

use std::collections::HashMap;
use std::path::Path;

use crate::cli::ScanArgs;
use crate::config::ZiftConfig;
use crate::error::Result;
use crate::rules::PatternRule;
use crate::types::{Finding, Language};

/// Result of a scan, including findings and enforcement point count.
pub struct ScanResult {
    pub findings: Vec<Finding>,
    pub enforcement_points: usize,
}

pub fn scan(
    root: &Path,
    rules: &[PatternRule],
    args: &ScanArgs,
    config: &ZiftConfig,
) -> Result<ScanResult> {
    // Merge exclude patterns from config and CLI
    let mut excludes = config.scan.exclude.clone();
    excludes.extend(args.exclude.iter().cloned());

    // Discover files
    let files = discovery::discover_files(root, &excludes, &args.language);
    tracing::info!("discovered {} files to scan", files.len());

    if files.is_empty() {
        return Ok(ScanResult {
            findings: Vec::new(),
            enforcement_points: 0,
        });
    }

    // Pre-compile queries per (language, tsx/jsx) variant to avoid recompiling per file
    // Key: (Language, is_tsx_jsx)
    let mut compiled_cache: HashMap<(Language, bool), Vec<matcher::CompiledRule<'_>>> =
        HashMap::new();

    // Determine which language variants we'll need
    let mut needed_variants: std::collections::HashSet<(Language, bool)> =
        std::collections::HashSet::new();
    for file in &files {
        needed_variants.insert((file.language, file.is_tsx_jsx));
    }

    // Pre-compile all rules for each needed language variant
    for (lang, is_tsx_jsx) in &needed_variants {
        let ts_lang = parser::get_language(*lang, *is_tsx_jsx);
        let mut compiled_rules = Vec::new();

        for rule in rules {
            if !rule.languages.contains(lang) {
                continue;
            }
            match matcher::compile_rule(rule, &ts_lang) {
                Ok(c) => compiled_rules.push(c),
                Err(e) => {
                    tracing::warn!("skipping rule {} for {lang}: {e}", rule.id);
                }
            }
        }

        compiled_cache.insert((*lang, *is_tsx_jsx), compiled_rules);
    }

    let mut ts_parser = tree_sitter::Parser::new();
    let mut all_findings = Vec::new();
    let mut enforcement_points: usize = 0;
    let mut seen_enforcement: std::collections::HashSet<(std::path::PathBuf, usize)> =
        std::collections::HashSet::new();

    for file in &files {
        let source = match std::fs::read_to_string(&file.path) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("skipping {}: {}", file.path.display(), e);
                continue;
            }
        };

        let tree = match parser::parse_source(
            &mut ts_parser,
            source.as_bytes(),
            file.language,
            file.is_tsx_jsx,
        ) {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!("skipping {}: {}", file.path.display(), e);
                continue;
            }
        };

        if tree.root_node().has_error() {
            tracing::debug!("parse errors in {}, scanning anyway", file.path.display());
        }

        let rel_path = file.path.strip_prefix(root).unwrap_or(&file.path);

        // Check for policy-engine imports in this file
        let policy_imports = imports::find_policy_imports(&tree, source.as_bytes(), file.language);

        let compiled_rules = &compiled_cache[&(file.language, file.is_tsx_jsx)];
        for compiled in compiled_rules {
            let findings = matcher::execute_query(
                compiled,
                &tree,
                source.as_bytes(),
                rel_path,
                file.language,
            );

            // Separate enforcement points from inline auth findings
            if policy_imports.is_empty() {
                all_findings.extend(findings);
            } else {
                for finding in findings {
                    if imports::is_enforcement_point(&finding.code_snippet, &policy_imports) {
                        let key = (finding.file.clone(), finding.line_start);
                        if seen_enforcement.insert(key) {
                            enforcement_points += 1;
                            tracing::debug!(
                                "skipping enforcement point: {}:{}",
                                finding.file.display(),
                                finding.line_start,
                            );
                        }
                    } else {
                        all_findings.push(finding);
                    }
                }
            }
        }
    }

    // Dedup
    all_findings = matcher::dedup_findings(all_findings);

    // Filter by confidence and category
    let min_confidence = args.confidence.or_else(|| {
        config
            .scan
            .min_confidence
            .as_deref()
            .and_then(|s| s.parse().ok())
    });

    all_findings = matcher::filter_findings(all_findings, min_confidence, &args.category);

    // Sort by file, then line
    all_findings.sort_by(|a, b| a.file.cmp(&b.file).then(a.line_start.cmp(&b.line_start)));

    tracing::info!(
        "found {} findings, {} enforcement points",
        all_findings.len(),
        enforcement_points,
    );
    Ok(ScanResult {
        findings: all_findings,
        enforcement_points,
    })
}
