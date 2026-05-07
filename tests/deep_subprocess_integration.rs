//! End-to-end integration tests for the subprocess transport.
//!
//! These exercise [`zift::deep::run`] (not just the client) against
//! shell-script fixtures, to catch regressions that pure unit tests
//! would miss — e.g. the orchestrator's per-candidate skip path, the
//! merge of agent-emitted findings into the structural set, and the
//! mode-aware dispatch in [`zift::deep::run`].
//!
//! Gated to Unix because the fixtures are POSIX shell snippets. The
//! Rust-binary-fixture alternative would be portable but materially
//! heavier; subprocess support is documented Unix-first for v0.1.4.
//!
//! See `plans/todo/03-pr3-subprocess-hook.md` §6 for the test plan.

#![cfg(unix)]

use std::fs;
use std::path::PathBuf;

use serde_json::json;
use tempfile::tempdir;

use zift::deep::config::{DeepMode, DeepRuntime};
use zift::types::{AuthCategory, Confidence, Finding, Language, ScanPass, Surface};

/// Build a minimal subprocess-mode runtime pointing at `cmd`.
fn subprocess_runtime(cmd: &str, timeout_secs: u64) -> DeepRuntime {
    DeepRuntime {
        mode: DeepMode::Subprocess,
        base_url: String::new(),
        model: String::new(),
        api_key: None,
        max_cost_usd: None,
        cost_per_1k_input: None,
        cost_per_1k_output: None,
        request_timeout_secs: 120,
        max_candidates: 5,
        max_concurrent: 1,
        temperature: 0.0,
        max_prompt_chars: 16_000,
        excludes: Vec::new(),
        language_filter: Vec::new(),
        agent_cmd: Some(cmd.into()),
        agent_timeout_secs: timeout_secs,
    }
}

fn structural_finding(file: &str, line: usize) -> Finding {
    Finding {
        id: format!("structural-{file}-{line}"),
        file: PathBuf::from(file),
        line_start: line,
        line_end: line + 2,
        code_snippet: String::new(),
        language: Language::TypeScript,
        category: AuthCategory::Custom,
        confidence: Confidence::Low,
        description: "matched custom rule".into(),
        pattern_rule: Some("ts-custom".into()),
        policy_outputs: vec![],
        pass: ScanPass::Structural,
        surface: Surface::Backend,
    }
}

#[test]
fn happy_path_subprocess_emits_semantic_finding() {
    let dir = tempdir().unwrap();
    fs::write(
        dir.path().join("auth.ts"),
        "// imports\nfunction isAdmin(u) {\n  return u.role === 'admin';\n}\n",
    )
    .unwrap();

    // Canned response matching deep-mode schema. printf swallows stdin
    // (which we still write to it) and emits the canned JSON.
    let canned = json!({
        "findings": [{
            "line_start": 2,
            "line_end": 4,
            "category": "rbac",
            "confidence": "high",
            "description": "isAdmin role check",
            "reasoning": "function name + role comparison",
            "is_false_positive": false
        }]
    })
    .to_string();
    // Use a heredoc-style approach via printf to avoid shell-quoting hell.
    // The inner single quotes are escaped via '"'"' for sh -c safety.
    let cmd = format!(
        "cat >/dev/null && printf '%s' '{}'",
        canned.replace('\'', "'\"'\"'")
    );

    let runtime = subprocess_runtime(&cmd, 30);
    let merged = zift::deep::run(Vec::new(), dir.path(), &runtime).unwrap();

    let semantic: Vec<&Finding> = merged
        .iter()
        .filter(|f| f.pass == ScanPass::Semantic)
        .collect();
    assert_eq!(
        semantic.len(),
        1,
        "expected one semantic finding, got {merged:?}"
    );
    assert_eq!(semantic[0].category, AuthCategory::Rbac);
    assert_eq!(semantic[0].confidence, Confidence::High);
}

#[test]
fn nonzero_exit_skips_candidate_keeps_structural() {
    // A failing agent_cmd must NOT hard-fail the entire deep run. The
    // structural set should ride through unchanged — best-effort
    // enrichment, not all-or-nothing.
    let dir = tempdir().unwrap();
    fs::write(
        dir.path().join("auth.ts"),
        "function isAdmin(u) { return u.role === 'admin'; }\n",
    )
    .unwrap();

    let runtime = subprocess_runtime("cat >/dev/null && exit 7", 5);
    let structural = vec![structural_finding("auth.ts", 1)];
    let merged = zift::deep::run(structural.clone(), dir.path(), &runtime).unwrap();

    // Structural finding survived; no semantic added.
    assert_eq!(merged.len(), 1);
    assert_eq!(merged[0].pass, ScanPass::Structural);
}

#[test]
fn malformed_stdout_skips_candidate() {
    let dir = tempdir().unwrap();
    fs::write(
        dir.path().join("auth.ts"),
        "function isAdmin(u) { return u.role === 'admin'; }\n",
    )
    .unwrap();

    let runtime = subprocess_runtime("cat >/dev/null && printf 'not json'", 5);
    let merged = zift::deep::run(Vec::new(), dir.path(), &runtime).unwrap();

    // No candidates produced findings; merged is empty (no structural
    // input either).
    assert!(merged.is_empty(), "expected empty merge, got {merged:?}");
}

#[test]
fn timeout_skips_candidate_and_returns_promptly() {
    // Subprocess sleeps 30s, timeout is 1s — must skip + return,
    // not hang the run.
    let dir = tempdir().unwrap();
    fs::write(
        dir.path().join("auth.ts"),
        "function isAdmin(u) { return u.role === 'admin'; }\n",
    )
    .unwrap();

    let runtime = subprocess_runtime("sleep 30", 1);
    let start = std::time::Instant::now();
    let merged = zift::deep::run(Vec::new(), dir.path(), &runtime).unwrap();
    let elapsed = start.elapsed();

    assert!(merged.is_empty());
    assert!(
        elapsed < std::time::Duration::from_secs(10),
        "deep::run hung past the per-candidate timeout: {elapsed:?}",
    );
}

#[test]
fn agent_receives_envelope_with_system_user_schema() {
    // Round-trip the envelope through a temp file so we can parse and
    // assert on its actual contents — `cat > file` captures the raw
    // stdin without needing to modify the runtime API. After the run
    // we read the file back, parse as JSON, and assert on the concrete
    // fields rather than just key presence. This rules out the
    // "everything-grepped-empty-merge passed silently" failure mode
    // that the companion test below also guards.
    let dir = tempdir().unwrap();
    fs::write(
        dir.path().join("auth.ts"),
        "function isAdmin(u) { return u.role === 'admin'; }\n",
    )
    .unwrap();

    // Capture stdin to a tempfile, then emit canned findings JSON.
    // Using `dir.path()` for the capture file keeps the test
    // hermetic — the tempdir is cleaned up on drop.
    let envelope_path = dir.path().join("captured-envelope.json");
    let canned = r#"{"findings":[]}"#;
    let cmd = format!(
        "cat > '{}' && printf '%s' '{}'",
        envelope_path.display(),
        canned,
    );

    let runtime = subprocess_runtime(&cmd, 10);
    let merged = zift::deep::run(Vec::new(), dir.path(), &runtime).unwrap();

    // No structural input + empty canned findings → empty merge. This
    // alone could pass via the orchestrator's skip path; the
    // assertions below pin the envelope shape, and
    // `agent_envelope_failure_path_is_observable` pins the failure
    // path.
    assert!(merged.is_empty());

    // Parse the captured envelope and assert on actual contents, not
    // just key presence. This catches schema regressions (e.g.,
    // accidentally renaming a field) that key-presence-via-grep would
    // miss.
    let raw = fs::read_to_string(&envelope_path)
        .expect("agent_cmd should have written the envelope to the temp file");
    let envelope: serde_json::Value =
        serde_json::from_str(&raw).expect("envelope must be valid JSON");

    // `system` and `user` are non-empty strings (rendered prompt
    // template). The renderer never produces empty values for these
    // — if it did, the deep-mode response wouldn't be useful.
    let system = envelope
        .get("system")
        .and_then(|v| v.as_str())
        .expect("envelope.system must be a string");
    let user = envelope
        .get("user")
        .and_then(|v| v.as_str())
        .expect("envelope.user must be a string");
    assert!(!system.is_empty(), "envelope.system must be non-empty");
    assert!(!user.is_empty(), "envelope.user must be non-empty");
    // The user prompt should reference the candidate file path so the
    // agent has enough context to produce findings keyed to a location.
    assert!(
        user.contains("auth.ts"),
        "envelope.user must reference the candidate file (got: {user:?})",
    );

    // `schema` is the JSON Schema for the response — must be an
    // object, not a string or null. Subprocess wrappers may forward
    // this verbatim to a real LLM as `response_format.json_schema`.
    let schema = envelope
        .get("schema")
        .expect("envelope.schema must be present");
    assert!(
        schema.is_object(),
        "envelope.schema must be a JSON object (got: {schema:?})",
    );
}

#[test]
fn agent_envelope_failure_path_is_observable() {
    // Companion to the test above: if the envelope shape changes and
    // the assertion above starts passing only via the orchestrator's
    // skip path, we'd never notice. Pin the failure path: a grep that
    // rejects the envelope makes the agent fail nonzero → empty
    // merge — but if we provide a structural finding, it should
    // survive because subprocess is best-effort.
    let dir = tempdir().unwrap();
    fs::write(
        dir.path().join("auth.ts"),
        "function isAdmin(u) { return u.role === 'admin'; }\n",
    )
    .unwrap();

    // Reject an envelope key that should never be present (acts as a
    // guarded "this must fail" path).
    let cmd =
        "in=$(cat) && echo \"$in\" | grep -q '\"definitely_not_present\"' && printf 'unreached'";
    let runtime = subprocess_runtime(cmd, 5);

    let structural = vec![structural_finding("auth.ts", 1)];
    let merged = zift::deep::run(structural, dir.path(), &runtime).unwrap();

    // Structural finding rides through; no semantic merged in.
    assert_eq!(merged.len(), 1);
    assert_eq!(merged[0].pass, ScanPass::Structural);
}
