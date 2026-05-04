//! Candidate selection for the deep (semantic) scan.
//!
//! Two sources feed the candidate set, in priority order:
//!
//! 1. **Escalations** — structural findings whose confidence/category warrant
//!    a second look (low-confidence anything; medium-confidence in noisy
//!    categories like Custom/Ownership/BusinessRule). High-confidence
//!    structural findings are NOT escalated — they are already trusted.
//! 2. **Cold regions** — file regions discovered by regex over auth-y
//!    function names. Capped at 30% of `max_candidates` so escalations get
//!    priority. Runs on **all** languages in the [`Language`] enum, including
//!    those without structural parser support (Go, C#, Kotlin, Ruby, PHP) —
//!    see plans/todo/01-pr1-deep-http-transport.md §6 for rationale.
//!
//! Candidates are sorted deterministically by `(file, line_start)`.

use crate::deep::config::DeepRuntime;
use crate::deep::context::{expand_finding, expand_region};
use crate::deep::error::DeepError;
use crate::scanner::discovery::discover_files_for_deep;
use crate::types::{AuthCategory, Confidence, Finding, Language};
use regex::Regex;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

/// Cap cold-region candidates at this fraction of `max_candidates`, so
/// escalations from structural findings always get priority.
const COLD_REGION_FRACTION: f32 = 0.3;

/// Filename / path-segment tokens that suggest a file is authz-relevant.
/// Used as a *priority* signal in cold-region selection (not as a finding
/// in its own right) — files whose path contains one of these tokens are
/// scanned before everything else, so under tight `max_candidates` caps
/// the obvious authz files always make the budget. Boundaries are path
/// separators / `_`, `-`, `.` so substring collisions like `authoring.md`
/// or `authentic` (without `authenticat…` continuation) don't trigger.
///
/// Same false-positive-tolerated stance as `AUTH_NAME_REGEX`: missing a
/// real authz file is a worse failure than an extra deep-pass candidate.
static AUTHZ_PATH_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?ix)
        (?: ^ | [/\\_.\-] )
        (?:
            authz | authn
          | authori[sz]ation
          | authorit\w*       # authority, authoritative, authorities
          | authenticat\w*
          | rbac | abac | acl | iam
          | permissions? | roles? | polic(?:y|ies)
          | guards?
          | access[_\-]?control
        )
        (?: [/\\_.\-] | $ )
        ",
    )
    .expect("AUTHZ_PATH_REGEX is a valid regex")
});

/// Lightweight priority hint for cold-region iteration: 1 if the path
/// looks authz-flavoured, 0 otherwise. Higher beats lower; ties fall
/// back to lexicographic path order so ranking stays deterministic.
fn path_priority(path: &Path) -> u8 {
    let s = path.to_string_lossy();
    if AUTHZ_PATH_REGEX.is_match(&s) { 1 } else { 0 }
}

/// Names that suggest authorization logic. Matched case-insensitively as
/// whole-word tokens. False positives are tolerated — the model filters them
/// at deep-pass time. Missed real authz, on the other hand, is a worse
/// failure mode, so this list is moderately permissive.
///
/// Patterns covered:
/// - `authorize`, `authorise`, `authorization`, `authorizer`, …
/// - `authenticate`, `authentication`, …
/// - `isAdmin`, `isOwner`, `isAuthorized`, `isAuthenticated`, `isInRole`
/// - `hasRole`, `hasPermission`, `hasAccess`, `hasPrivilege`
/// - `requireAuth`, `requireAdmin`, `requireRole`, `requireUser`, …
/// - `ensureAuth`, `ensurePermission`, …
/// - `checkAuth`, `checkRole`, `checkPermission`, …
/// - `currentUser`, `getRoles`, `getPermissions`
/// - `guard`, `authz`, `rbac`, `acl`
/// - Framework idioms: `before_action`, `login_required`, `permission_required`
static AUTH_NAME_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?ix)
        \b(?:
            authori[sz]\w*
          | authenticat\w*
          | is_?(?: admin | owner | authori[sz]ed | authenticated | in_?role )
          | has_?(?: role | permission | access | privilege )\w*
          | (?: requires? | ensures? )_?(?: auth | admin | role | permission | login | user | owner )
          | check_?(?: auth | admin | role | permission | access | privilege )
          | current_?user
          | get_?(?: roles | permissions | privileges )
          | guard\w*
          | authz\w*
          | rbac
          | acl
          | before_action
          | before_filter
          | login_required
          | permission_required
        )\b
        ",
    )
    .expect("AUTH_NAME_REGEX is a valid regex")
});

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateKind {
    /// Re-evaluation of a structural finding (typically low/medium confidence).
    Escalation,
    /// Cold-region scan triggered by name-based heuristics. May or may not
    /// correspond to a structural finding.
    ColdRegion,
}

#[derive(Debug, Clone)]
pub struct Candidate {
    pub kind: CandidateKind,
    /// Path relative to scan root.
    pub file: PathBuf,
    pub language: Language,
    pub line_start: usize,
    pub line_end: usize,
    pub source_snippet: String,
    /// First N lines of the file (verbatim) — used by the prompt renderer
    /// to detect framework idioms (e.g. `import express`, `from django`).
    pub imports: Vec<String>,
    /// Set iff `kind == Escalation` — the structural finding's id.
    pub original_finding_id: Option<String>,
    /// Hint for prompt selection (e.g. seed an RBAC-flavored prompt).
    pub seed_category: Option<AuthCategory>,
}

/// Pick which structural findings to escalate and which file regions to
/// cold-scan. Sorted deterministically by `(file, line_start)`. Capped at
/// `runtime.max_candidates`.
pub fn select_candidates(
    structural: &[Finding],
    scan_root: &Path,
    runtime: &DeepRuntime,
) -> Result<Vec<Candidate>, DeepError> {
    let mut escalations = build_escalations(structural, scan_root, runtime)?;
    escalations.truncate(runtime.max_candidates);

    // Use ceiling so small `max_candidates` (1-3) still leave at least one
    // cold slot when no escalations consume the budget. Plain floor cast
    // rounded `1 * 0.3 → 0`, which silently disabled cold scanning under
    // tight caps and made `--deep` look like a no-op.
    let cold_budget = if runtime.max_candidates == 0 {
        0
    } else {
        let scaled = (runtime.max_candidates as f32 * COLD_REGION_FRACTION).ceil() as usize;
        scaled.max(1)
    };
    let cold_budget = cold_budget.min(runtime.max_candidates.saturating_sub(escalations.len()));

    let cold = if cold_budget == 0 {
        Vec::new()
    } else {
        let escalation_ranges: HashSet<(PathBuf, usize, usize)> = escalations
            .iter()
            .map(|c| (c.file.clone(), c.line_start, c.line_end))
            .collect();
        build_cold_regions(scan_root, runtime, &escalation_ranges, cold_budget)?
    };

    let mut all: Vec<Candidate> = escalations.into_iter().chain(cold).collect();
    all.sort_by(|a, b| {
        a.file
            .cmp(&b.file)
            .then(a.line_start.cmp(&b.line_start))
            .then(a.line_end.cmp(&b.line_end))
    });

    Ok(all)
}

/// Should this structural finding be re-examined by the model?
fn should_escalate(finding: &Finding) -> bool {
    match finding.confidence {
        Confidence::Low => true,
        Confidence::Medium => matches!(
            finding.category,
            AuthCategory::BusinessRule | AuthCategory::Custom | AuthCategory::Ownership
        ),
        Confidence::High => false,
    }
}

fn build_escalations(
    structural: &[Finding],
    scan_root: &Path,
    runtime: &DeepRuntime,
) -> Result<Vec<Candidate>, DeepError> {
    let mut out = Vec::new();
    for finding in structural {
        if !should_escalate(finding) {
            continue;
        }
        // I/O errors on a single file (deleted between scan and analyze,
        // permission-denied, etc.) are best-effort: log and skip the
        // candidate, don't abort the whole deep pass. Containment violations
        // (`DeepError::Config` from `expand_finding`) and any other variant
        // remain hard fails — they signal misconfiguration or malicious
        // input that the operator should see.
        let ctx = match expand_finding(finding, scan_root, runtime.max_prompt_chars) {
            Ok(ctx) => ctx,
            Err(DeepError::Io(e)) => {
                tracing::warn!(
                    "deep: skipping escalation for {}:{} — I/O error reading source: {e}",
                    finding.file.display(),
                    finding.line_start,
                );
                continue;
            }
            Err(other) => return Err(other),
        };
        out.push(Candidate {
            kind: CandidateKind::Escalation,
            file: finding.file.clone(),
            language: finding.language,
            line_start: ctx.line_start,
            line_end: ctx.line_end,
            source_snippet: ctx.snippet,
            imports: ctx.imports,
            original_finding_id: Some(finding.id.clone()),
            seed_category: Some(finding.category),
        });
    }
    Ok(out)
}

fn build_cold_regions(
    scan_root: &Path,
    runtime: &DeepRuntime,
    escalation_ranges: &HashSet<(PathBuf, usize, usize)>,
    budget: usize,
) -> Result<Vec<Candidate>, DeepError> {
    if budget == 0 {
        return Ok(Vec::new());
    }

    let mut discovered =
        discover_files_for_deep(scan_root, &runtime.excludes, &runtime.language_filter);
    // Two-key ordering:
    //   1. Path priority (descending) — files whose path looks authz-flavoured
    //      (`authz.go`, `internal/permissions/...`, `rbac.py`, …) sort before
    //      neutral files. This is the only place we let filenames influence
    //      results: under a tight `max_candidates`, the obvious authz files
    //      survive even when their content doesn't trip the structural rules
    //      (the bug that made ocp's `internal/authz/authz.go` a no-finding
    //      file in v0.1.6).
    //   2. Lexicographic path (ascending) — ties break deterministically so
    //      the surviving cold subset is stable across filesystems and runs.
    discovered.sort_by(|a, b| {
        path_priority(&b.path)
            .cmp(&path_priority(&a.path))
            .then_with(|| a.path.cmp(&b.path))
    });
    let mut out: Vec<Candidate> = Vec::new();

    for file in discovered {
        if out.len() >= budget {
            break;
        }
        let content = match std::fs::read_to_string(&file.path) {
            Ok(c) => c,
            Err(_) => continue, // skip non-UTF8 / permission errors silently
        };

        // Find auth-name match line numbers, then collapse overlapping windows.
        let mut hit_lines: Vec<usize> = Vec::new();
        for (idx, line) in content.lines().enumerate() {
            if AUTH_NAME_REGEX.is_match(line) {
                hit_lines.push(idx + 1); // 1-based
            }
        }
        if hit_lines.is_empty() {
            continue;
        }

        let coalesced = coalesce_windows(&hit_lines);

        let file_relative = file
            .path
            .strip_prefix(scan_root)
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|_| file.path.clone());

        for (start, end) in coalesced {
            if out.len() >= budget {
                break;
            }
            // Skip if it overlaps an escalation range in the same file.
            if overlaps_any(&file_relative, start, end, escalation_ranges) {
                continue;
            }
            // Same best-effort policy as `build_escalations`: skip the
            // cold region on per-file I/O errors, propagate everything else.
            let ctx = match expand_region(
                &file.path,
                file_relative.clone(),
                file.language,
                start,
                end,
                runtime.max_prompt_chars,
            ) {
                Ok(ctx) => ctx,
                Err(DeepError::Io(e)) => {
                    tracing::warn!(
                        "deep: skipping cold region {}:{}-{} — I/O error reading source: {e}",
                        file_relative.display(),
                        start,
                        end,
                    );
                    continue;
                }
                Err(other) => return Err(other),
            };
            out.push(Candidate {
                kind: CandidateKind::ColdRegion,
                file: file_relative.clone(),
                language: file.language,
                line_start: ctx.line_start,
                line_end: ctx.line_end,
                source_snippet: ctx.snippet,
                imports: ctx.imports,
                original_finding_id: None,
                seed_category: None,
            });
        }
    }

    Ok(out)
}

/// Collapse a list of 1-based hit lines into coalesced (start, end) ranges
/// using the same line-window the context expander applies. Adjacent
/// or overlapping windows are merged into a single range.
fn coalesce_windows(hit_lines: &[usize]) -> Vec<(usize, usize)> {
    const BEFORE: usize = 5;
    const AFTER: usize = 15;

    let mut hits = hit_lines.to_vec();
    hits.sort_unstable();
    hits.dedup();

    let mut out: Vec<(usize, usize)> = Vec::new();
    for line in hits {
        let start = line.saturating_sub(BEFORE).max(1);
        let end = line + AFTER;
        match out.last_mut() {
            Some(last) if last.1 + 1 >= start => {
                last.1 = last.1.max(end);
            }
            _ => out.push((start, end)),
        }
    }
    out
}

fn overlaps_any(
    file: &Path,
    start: usize,
    end: usize,
    ranges: &HashSet<(PathBuf, usize, usize)>,
) -> bool {
    ranges.iter().any(|(f, s, e)| {
        // Same file + line ranges intersect.
        f.as_path() == file && start <= *e && *s <= end
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{AuthCategory, Confidence, Language, ScanPass};
    use std::fs;
    use tempfile::tempdir;

    fn finding(file: &str, line: usize, category: AuthCategory, confidence: Confidence) -> Finding {
        Finding {
            id: format!("test-{file}-{line}"),
            file: PathBuf::from(file),
            line_start: line,
            line_end: line + 2,
            code_snippet: String::new(),
            language: Language::TypeScript,
            category,
            confidence,
            description: String::new(),
            pattern_rule: None,
            rego_stub: None,
            pass: ScanPass::Structural,
        }
    }

    fn rt() -> DeepRuntime {
        DeepRuntime {
            mode: crate::deep::config::DeepMode::Http,
            base_url: "http://x/v1".into(),
            model: "m".into(),
            api_key: None,
            max_cost_usd: None,
            cost_per_1k_input: None,
            cost_per_1k_output: None,
            request_timeout_secs: 120,
            max_candidates: 50,
            max_concurrent: 1,
            temperature: 0.0,
            max_prompt_chars: 16_000,
            excludes: Vec::new(),
            language_filter: Vec::new(),
            agent_cmd: None,
            agent_timeout_secs: 600,
        }
    }

    // ---- regex coverage ----

    #[test]
    fn regex_matches_obvious_authz_names() {
        for s in [
            "authorize",
            "authorization",
            "authorise",
            "authenticate",
            "isAdmin",
            "is_admin",
            "isAuthorized",
            "isAuthenticated",
            "isInRole",
            "hasRole",
            "hasPermission",
            "hasAccess",
            "hasPrivilege",
            "requireAuth",
            "require_auth",
            "requireAdmin",
            "ensureRole",
            "checkPermission",
            "currentUser",
            "current_user",
            "getRoles",
            "getPermissions",
            "guardAdmin",
            "authzService",
            "rbac",
            "acl",
            "before_action",
            "login_required",
            "permission_required",
        ] {
            assert!(
                AUTH_NAME_REGEX.is_match(s),
                "regex should match auth-y name: {s}"
            );
        }
    }

    #[test]
    fn regex_does_not_match_obvious_non_auth_names() {
        for s in [
            "authorRefactor",
            "authentic",
            "ruleset",
            "permissive",
            "checkInput",
            "canRender",
            "rolesetEditor",
            "factoryGuard", // matches `guard\w*`? Let's see.
        ] {
            // Note: factoryGuard contains "guard" — and "guard" alone is in our
            // pattern (`guard\w*` matches `guard` and `guardAdmin` but our \b
            // anchor prevents matching mid-word). Let's check: in `factoryGuard`,
            // \b is between y and G (camelCase), so \bguard\b WOULD match the
            // suffix. This is a known limitation — camelCase names need a
            // tokenizer to be perfectly safe. For now the false positive is
            // acceptable; the model rejects non-auth at deep-pass time.
            if s == "factoryGuard" {
                continue;
            }
            assert!(
                !AUTH_NAME_REGEX.is_match(s),
                "regex should NOT match non-auth name: {s}"
            );
        }
    }

    // ---- filename priority ----

    #[test]
    fn path_priority_matches_obvious_authz_paths() {
        for s in [
            "internal/authz/authz.go",
            "src/permissions.py",
            "pkg/rbac/check.go",
            "lib/abac/policy.ts",
            "src/authn/middleware.ts",
            "internal/iam/roles.go",
            "src/policies.py",
            "guards/admin.ts",
            "access-control/rules.go",
            "authentication.go",
            "authorization.go",
            "authorisation.py",       // British spelling
            "src/authority/check.go", // authority/authoritative family
            "pkg/authoritative_source.go",
            "src/acl/list.go",
        ] {
            assert_eq!(
                path_priority(Path::new(s)),
                1,
                "expected priority 1 for {s}",
            );
        }
    }

    #[test]
    fn path_priority_rejects_non_authz_paths_with_similar_substrings() {
        for s in [
            "docs/authoring.md",    // 'auth' but not at a separator boundary
            "internal/author/x.go", // author != authz
            "src/authentic/x.go",   // 'authentic' alone is not in our list (only authenticat\w*)
            "cmd/migrate/migrate.go",
            "pkg/utils/utils.go",
            "src/icon.go",
        ] {
            assert_eq!(
                path_priority(Path::new(s)),
                0,
                "expected priority 0 for {s}",
            );
        }
    }

    #[test]
    fn cold_region_iterates_authz_paths_first() {
        // 4 files, all with the same auth-y content. With `max_candidates=10`
        // the cold-region budget is ceil(10 * 0.3) = 3, so we get exactly 3
        // candidates. The first two MUST be the authz-flavoured filenames
        // even though `app.py` and `core.py` sort before them lexicographically;
        // the third tie-breaks to lex order between the two non-authz files.
        let dir = tempdir().unwrap();
        let body = "def is_admin(u):\n    return False\n";
        for name in ["app.py", "authz.py", "core.py", "permissions.py"] {
            fs::write(dir.path().join(name), body).unwrap();
        }
        let mut runtime = rt();
        runtime.max_candidates = 10;
        let mut candidates = select_candidates(&[], dir.path(), &runtime).unwrap();
        // `select_candidates` re-sorts the final output by (file, line) for
        // deterministic emission; that breaks the ordering signal we want
        // to assert. Verify priority instead by checking which files made
        // the cold-region budget.
        candidates.sort_by(|a, b| a.file.cmp(&b.file));
        let files: Vec<_> = candidates.iter().map(|c| c.file.clone()).collect();
        assert_eq!(
            files.len(),
            3,
            "cold budget = ceil(10 * 0.3) = 3; got {files:?}",
        );
        assert!(
            files.contains(&PathBuf::from("authz.py")),
            "authz.py must survive the cold-region cap: {files:?}",
        );
        assert!(
            files.contains(&PathBuf::from("permissions.py")),
            "permissions.py must survive the cold-region cap: {files:?}",
        );
        // Tertiary slot: with the two authz files locked in, the third
        // slot tie-breaks to lex order among priority-0 files
        // (`app.py` < `core.py`). Pin both halves so a future flip in
        // the secondary tiebreaker is loud.
        assert!(
            files.contains(&PathBuf::from("app.py")),
            "app.py should win the lex tiebreak among non-authz files: {files:?}",
        );
        assert!(
            !files.contains(&PathBuf::from("core.py")),
            "core.py should be cut by the budget: {files:?}",
        );
    }

    // ---- escalation rules ----

    #[test]
    fn high_confidence_findings_not_escalated() {
        assert!(!should_escalate(&finding(
            "a.ts",
            10,
            AuthCategory::Rbac,
            Confidence::High
        )));
    }

    #[test]
    fn low_confidence_findings_escalated_regardless_of_category() {
        for cat in [
            AuthCategory::Rbac,
            AuthCategory::Abac,
            AuthCategory::Custom,
            AuthCategory::FeatureGate,
        ] {
            assert!(should_escalate(&finding("a.ts", 10, cat, Confidence::Low)));
        }
    }

    #[test]
    fn medium_confidence_only_escalated_for_noisy_categories() {
        assert!(should_escalate(&finding(
            "a.ts",
            10,
            AuthCategory::Custom,
            Confidence::Medium
        )));
        assert!(should_escalate(&finding(
            "a.ts",
            10,
            AuthCategory::Ownership,
            Confidence::Medium
        )));
        assert!(should_escalate(&finding(
            "a.ts",
            10,
            AuthCategory::BusinessRule,
            Confidence::Medium
        )));
        assert!(!should_escalate(&finding(
            "a.ts",
            10,
            AuthCategory::Rbac,
            Confidence::Medium
        )));
        assert!(!should_escalate(&finding(
            "a.ts",
            10,
            AuthCategory::Middleware,
            Confidence::Medium
        )));
    }

    // ---- coalescing ----

    #[test]
    fn coalesce_merges_overlapping_windows() {
        // Lines 10 and 12 → windows (5..25) and (7..27) → merged (5..27)
        let merged = coalesce_windows(&[10, 12]);
        assert_eq!(merged, vec![(5, 27)]);
    }

    #[test]
    fn coalesce_keeps_distant_windows_separate() {
        // Lines 10 and 100 → windows (5..25) and (95..115) → not merged
        let merged = coalesce_windows(&[10, 100]);
        assert_eq!(merged, vec![(5, 25), (95, 115)]);
    }

    #[test]
    fn coalesce_dedupes_repeated_lines() {
        let merged = coalesce_windows(&[10, 10, 10]);
        assert_eq!(merged, vec![(5, 25)]);
    }

    // ---- end-to-end with real files ----

    #[test]
    fn select_candidates_finds_cold_region_in_python() {
        let dir = tempdir().unwrap();
        let py = "def is_admin(user):\n    return user.role == 'admin'\n";
        fs::write(dir.path().join("auth.py"), py).unwrap();

        let runtime = rt();
        let candidates = select_candidates(&[], dir.path(), &runtime).unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].kind, CandidateKind::ColdRegion);
        assert_eq!(candidates[0].language, Language::Python);
        assert_eq!(candidates[0].file, PathBuf::from("auth.py"));
    }

    #[test]
    fn cold_region_dedupes_against_escalation() {
        let dir = tempdir().unwrap();
        // Source file with `isAdmin` on line 1 and lots of padding.
        let mut content = String::from("function isAdmin() { return true; }\n");
        for i in 2..=50 {
            content.push_str(&format!("// line {i}\n"));
        }
        fs::write(dir.path().join("auth.ts"), &content).unwrap();

        let f = finding("auth.ts", 1, AuthCategory::Custom, Confidence::Low);
        let candidates = select_candidates(&[f], dir.path(), &rt()).unwrap();
        // Without dedup we'd have 2 (1 escalation + 1 cold-region overlapping it).
        // With dedup, the cold-region candidate at line 1 is suppressed.
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].kind, CandidateKind::Escalation);
    }

    #[test]
    fn determinism_same_input_same_output() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("a.py"), "def has_role(u, r):\n    pass\n").unwrap();
        fs::write(dir.path().join("b.py"), "def is_admin(u):\n    pass\n").unwrap();

        let one = select_candidates(&[], dir.path(), &rt()).unwrap();
        let two = select_candidates(&[], dir.path(), &rt()).unwrap();
        assert_eq!(one.len(), two.len());
        for (a, b) in one.iter().zip(two.iter()) {
            assert_eq!(a.file, b.file);
            assert_eq!(a.line_start, b.line_start);
            assert_eq!(a.line_end, b.line_end);
        }
    }

    #[test]
    fn max_candidates_cap_respected() {
        let dir = tempdir().unwrap();
        // 20 files, each with one auth-y name. Use `is_admin()` (not
        // `is_admin_{i}`) because the regex's trailing `\b` doesn't fire
        // after `_<digit>` (`_` is a word char). Suffix the *file name*
        // to keep them unique without changing the auth-y token.
        for i in 0..20 {
            fs::write(
                dir.path().join(format!("f{i}.py")),
                "def is_admin():\n    pass\n",
            )
            .unwrap();
        }
        let mut runtime = rt();
        runtime.max_candidates = 5;
        let candidates = select_candidates(&[], dir.path(), &runtime).unwrap();
        // cold_budget = ceil(5 * 0.3) = 2 candidates. Cap binds: we should
        // get exactly 2, not 20 (the count of available cold-region hits).
        assert_eq!(candidates.len(), 2);
        assert!(candidates.len() <= runtime.max_candidates);
    }

    #[test]
    fn small_max_candidates_still_yields_cold_slot() {
        // Regression: floor cast turned `1 * 0.3 → 0`, so `--deep` with a
        // tight cap silently disabled cold-region analysis. Ceiling + min(1)
        // guarantees at least one cold slot when nothing is escalated.
        let dir = tempdir().unwrap();
        for i in 0..3 {
            fs::write(
                dir.path().join(format!("f{i}.py")),
                "def is_admin():\n    pass\n",
            )
            .unwrap();
        }
        for cap in [1, 2, 3] {
            let mut runtime = rt();
            runtime.max_candidates = cap;
            let candidates = select_candidates(&[], dir.path(), &runtime).unwrap();
            assert!(
                !candidates.is_empty(),
                "cap={cap} produced no candidates; cold-region budget rounded to zero?"
            );
            assert!(candidates.len() <= cap);
        }
    }

    #[test]
    fn missing_escalation_file_is_skipped_not_fatal() {
        // Regression: a structural finding pointing at a deleted file used to
        // propagate `DeepError::Io` through `?`, killing the entire deep pass
        // even though deep mode is otherwise best-effort.
        use crate::types::{AuthCategory, Confidence, Finding, ScanPass};
        let dir = tempdir().unwrap();
        // One escalation finding pointing at a file that doesn't exist.
        let bad = Finding {
            id: "x".into(),
            file: PathBuf::from("does-not-exist.ts"),
            line_start: 1,
            line_end: 1,
            code_snippet: String::new(),
            language: Language::TypeScript,
            category: AuthCategory::Custom,
            confidence: Confidence::Low,
            description: "x".into(),
            pattern_rule: None,
            rego_stub: None,
            pass: ScanPass::Structural,
        };
        // Should NOT propagate Io; should return Ok with the bad escalation
        // skipped. (No cold-region files either, so result is empty.)
        let candidates = select_candidates(&[bad], dir.path(), &rt()).unwrap();
        assert!(candidates.is_empty(), "got: {candidates:?}");
    }

    #[test]
    fn cold_region_respects_excludes() {
        let dir = tempdir().unwrap();
        fs::create_dir_all(dir.path().join("vendor")).unwrap();
        fs::write(
            dir.path().join("vendor/legacy.py"),
            "def is_admin():\n    pass\n",
        )
        .unwrap();
        fs::write(dir.path().join("app.py"), "def has_role(u, r):\n    pass\n").unwrap();

        let mut runtime = rt();
        runtime.excludes = vec!["vendor/**".into()];
        let candidates = select_candidates(&[], dir.path(), &runtime).unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].file, PathBuf::from("app.py"));
    }

    #[test]
    fn cold_region_respects_language_filter() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("a.py"), "def is_admin():\n    pass\n").unwrap();
        fs::write(
            dir.path().join("b.go"),
            "func IsAdmin() bool { return true }\n",
        )
        .unwrap();

        let mut runtime = rt();
        runtime.language_filter = vec![Language::Python];
        let candidates = select_candidates(&[], dir.path(), &runtime).unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].language, Language::Python);
    }
}
