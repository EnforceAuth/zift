pub mod discovery;
pub mod imports;
pub mod matcher;
pub mod parser;

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

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
        let ts_lang = parser::get_language(*lang, *is_tsx_jsx)?;
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

    // Pre-compute per-Go-package policy bindings. Go's scoping makes the
    // package directory the natural propagation domain — bindings declared
    // in one file are visible to siblings via package-private identifiers.
    // Without this pass, a consumer file with no policy imports of its own
    // would never recognize a call like `d.accessFactory()` even when a
    // sibling file wired `accessFactory: authz.NewAccess`.
    let go_package_bindings = build_go_package_bindings(root, &files);

    let mut ts_parser = tree_sitter::Parser::new();
    let mut all_findings = Vec::new();
    // `enforcement_points` counts call sites that *would* have matched a
    // structural rule, but resolve to a name imported from a path containing
    // a policy-engine indicator (`authz`, `opa`, `policy`, `rego`,
    // `enforce`, `open-policy-agent` — see `scanner::imports`). Those calls
    // are already routed through a policy engine, so we suppress the inline
    // finding and count them here instead — that's what feeds
    // `summary.externalized_pct` in the JSON output. Some rules are
    // explicitly marked `externalized = true` for known policy engines and
    // managed services (OPA/Cedar/AWS Verified Permissions); those count
    // directly because the matched API call is the external enforcement
    // point. Import-statement detection remains the fallback for custom
    // policy wrappers. Pinned by `tests/scanner_enforcement_points.rs`.
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

        // Files that live *inside* a policy-engine implementation directory
        // (`internal/authz/**`, `pkg/policy/**`, etc.) are themselves the
        // policy engine, not consumers of one. Structural rules flag the
        // embedded-authz shape, so running them here is guaranteed noise.
        // Skip the file entirely — these don't count as findings or as
        // enforcement points; they don't participate in the externalization
        // metric at all.
        if imports::is_policy_implementation_path(rel_path) {
            tracing::debug!(
                "skipping policy implementation file: {}",
                rel_path.display(),
            );
            continue;
        }

        // Check for policy-engine imports. For Go we use the package-level
        // binding set computed in the pre-pass (a superset of this file's
        // local bindings, including any propagated from sibling files). For
        // every other language we stay per-file — cross-file flow there
        // needs a project-wide symbol table that isn't built yet.
        let policy_imports = if file.language == Language::Go {
            file.path
                .parent()
                .and_then(|d| go_package_bindings.get(d))
                .cloned()
                .unwrap_or_default()
        } else {
            imports::find_policy_imports(&tree, source.as_bytes(), file.language)
        };

        let compiled_rules = &compiled_cache[&(file.language, file.is_tsx_jsx)];
        for compiled in compiled_rules {
            let findings = matcher::execute_query(
                compiled,
                &tree,
                source.as_bytes(),
                rel_path,
                file.language,
            )?;

            // Separate enforcement points from inline auth findings
            if policy_imports.is_empty() && !compiled.rule.externalized {
                all_findings.extend(findings);
            } else {
                for finding in findings {
                    if compiled.rule.externalized
                        || imports::is_enforcement_point(&finding.code_snippet, &policy_imports)
                    {
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

/// Group Go files by their parent directory (=Go package) and compute the
/// union of imports + propagation edges across each group, returning the
/// per-package binding set keyed by directory.
///
/// Files inside policy-engine implementation directories (`internal/authz/`
/// etc.) are skipped here for the same reason the main loop skips them: the
/// files themselves *are* the policy engine, and any bindings they contribute
/// are noise relative to consumer-side detection.
///
/// We re-parse Go files here rather than threading a tree cache through the
/// main loop. The double parse is cheap (tree-sitter Go is fast and the
/// number of `.go` files in real repos is bounded) and the simpler control
/// flow is worth it; if profiling later flags this, the obvious next step
/// is to pre-parse once and pass the trees through.
fn build_go_package_bindings(
    root: &Path,
    files: &[discovery::DiscoveredFile],
) -> HashMap<PathBuf, HashSet<String>> {
    let mut by_dir: HashMap<PathBuf, Vec<&Path>> = HashMap::new();
    for file in files {
        if file.language != Language::Go {
            continue;
        }
        let rel = file.path.strip_prefix(root).unwrap_or(&file.path);
        if imports::is_policy_implementation_path(rel) {
            continue;
        }
        let Some(dir) = file.path.parent() else {
            continue;
        };
        by_dir
            .entry(dir.to_path_buf())
            .or_default()
            .push(&file.path);
    }

    let mut result: HashMap<PathBuf, HashSet<String>> = HashMap::new();
    let mut ts_parser = tree_sitter::Parser::new();

    for (dir, paths) in by_dir {
        let mut parsed: Vec<(tree_sitter::Tree, Vec<u8>)> = Vec::with_capacity(paths.len());
        for path in paths {
            let source = match std::fs::read_to_string(path) {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!("skipping {} during package scan: {}", path.display(), e);
                    continue;
                }
            };
            let tree = match parser::parse_source(
                &mut ts_parser,
                source.as_bytes(),
                Language::Go,
                false,
            ) {
                Ok(t) => t,
                Err(e) => {
                    tracing::warn!("skipping {} during package scan: {}", path.display(), e);
                    continue;
                }
            };
            parsed.push((tree, source.into_bytes()));
        }
        let bindings =
            imports::find_go_package_policy_imports(parsed.iter().map(|(t, s)| (t, s.as_slice())));
        if !bindings.is_empty() {
            result.insert(dir, bindings);
        }
    }
    result
}
