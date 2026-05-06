//! Integration tests for the deep-pass HTTP client against a mocked
//! OpenAI-compatible endpoint (mockito).
//!
//! These tests exercise the full client path: request body shape, response
//! parsing, retry-on-bad-JSON, cost cap enforcement, and auth errors.

use mockito::Server;
use serde_json::json;

use zift::deep::candidate::{Candidate, CandidateKind};
use zift::deep::client::{OpenAiCompatibleClient, TokenUsage};
use zift::deep::config::DeepRuntime;
use zift::deep::cost::CostTracker;
use zift::deep::error::DeepError;
use zift::deep::prompt::{PromptInputs, render};
use zift::types::{AuthCategory, Confidence, Language};

fn runtime_for(server_url: &str) -> DeepRuntime {
    DeepRuntime {
        mode: zift::deep::config::DeepMode::Http,
        base_url: server_url.to_string(),
        model: "test-model".into(),
        api_key: Some("test-key".into()),
        max_cost_usd: None,
        cost_per_1k_input: None,
        cost_per_1k_output: None,
        request_timeout_secs: 10,
        max_candidates: 10,
        max_concurrent: 1,
        temperature: 0.0,
        max_prompt_chars: 16_000,
        excludes: Vec::new(),
        language_filter: Vec::new(),
        agent_cmd: None,
        agent_timeout_secs: 600,
    }
}

fn synth_candidate() -> Candidate {
    Candidate {
        kind: CandidateKind::Escalation,
        file: std::path::PathBuf::from("src/auth.ts"),
        language: Language::TypeScript,
        line_start: 10,
        line_end: 15,
        source_snippet: "function isAdmin() { return user.role === 'admin'; }".into(),
        imports: Vec::new(),
        original_finding_id: Some("structural-1".into()),
        seed_category: Some(AuthCategory::Custom),
    }
}

fn ok_response(content: &str, prompt_tokens: u32, completion_tokens: u32) -> String {
    json!({
        "id": "chatcmpl-test",
        "object": "chat.completion",
        "created": 1234567890,
        "model": "test-model",
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": content,
            },
            "finish_reason": "stop"
        }],
        "usage": {
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": prompt_tokens + completion_tokens,
        }
    })
    .to_string()
}

fn findings_content_one() -> String {
    json!({
        "findings": [{
            "line_start": 10,
            "line_end": 12,
            "category": "rbac",
            "confidence": "high",
            "description": "isAdmin role check",
            "reasoning": "function name + return value structure indicates rbac",
            "is_false_positive": false
        }]
    })
    .to_string()
}

#[test]
fn happy_path_returns_findings_and_usage() {
    let mut server = Server::new();
    let m = server
        .mock("POST", "/chat/completions")
        .match_header("authorization", "Bearer test-key")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(ok_response(&findings_content_one(), 100, 50))
        .create();

    let runtime = runtime_for(&server.url());
    let client = OpenAiCompatibleClient::new(&runtime).unwrap();
    let cand = synth_candidate();
    let prompt = render(&PromptInputs {
        candidate: &cand,
        structural_finding: None,
    });

    let response = client.analyze(&prompt).unwrap();
    assert_eq!(response.findings.len(), 1);
    assert_eq!(response.findings[0].line_start, 10);
    assert_eq!(response.findings[0].category, AuthCategory::Rbac);
    assert_eq!(response.findings[0].confidence, Confidence::High);
    assert_eq!(response.usage.input_tokens, 100);
    assert_eq!(response.usage.output_tokens, 50);
    m.assert();
}

#[test]
fn empty_findings_array_is_valid() {
    let mut server = Server::new();
    let m = server
        .mock("POST", "/chat/completions")
        .with_status(200)
        .with_body(ok_response(r#"{"findings": []}"#, 80, 20))
        .create();

    let runtime = runtime_for(&server.url());
    let client = OpenAiCompatibleClient::new(&runtime).unwrap();
    let prompt = render(&PromptInputs {
        candidate: &synth_candidate(),
        structural_finding: None,
    });

    let response = client.analyze(&prompt).unwrap();
    assert!(response.findings.is_empty());
    assert_eq!(response.usage.input_tokens, 80);
    m.assert();
}

#[test]
fn malformed_json_returns_bad_response_after_retry() {
    let mut server = Server::new();
    // Both the structured-output attempt and the fallback retry return
    // garbage. Two hits total.
    let m = server
        .mock("POST", "/chat/completions")
        .with_status(200)
        .with_body(ok_response("this is definitely not json", 50, 10))
        .expect(2)
        .create();

    let runtime = runtime_for(&server.url());
    let client = OpenAiCompatibleClient::new(&runtime).unwrap();
    let prompt = render(&PromptInputs {
        candidate: &synth_candidate(),
        structural_finding: None,
    });

    let err = client.analyze(&prompt).unwrap_err();
    assert!(
        matches!(err, DeepError::BadResponse(_)),
        "expected BadResponse, got: {err:?}"
    );
    m.assert();
}

#[test]
fn fallback_retry_succeeds_when_first_attempt_returns_bad_json() {
    let mut server = Server::new();

    // First attempt (with response_format) returns garbage. PartialJsonString
    // requires the body to have a `response_format` key, so this mock only
    // matches the structured-output attempt — not the retry.
    let bad = server
        .mock("POST", "/chat/completions")
        .match_body(mockito::Matcher::PartialJsonString(
            r#"{"response_format": {}}"#.into(),
        ))
        .with_status(200)
        .with_body(ok_response("not json", 50, 10))
        .create();

    // Second attempt (without response_format) returns valid findings. The
    // first mock won't match this request (no `response_format` field), so
    // mockito falls through to this one.
    let good = server
        .mock("POST", "/chat/completions")
        .with_status(200)
        .with_body(ok_response(&findings_content_one(), 60, 30))
        .create();

    let runtime = runtime_for(&server.url());
    let client = OpenAiCompatibleClient::new(&runtime).unwrap();
    let prompt = render(&PromptInputs {
        candidate: &synth_candidate(),
        structural_finding: None,
    });

    let response = client.analyze(&prompt).unwrap();
    assert_eq!(response.findings.len(), 1);
    // Assert BOTH mocks were consumed exactly once (mockito's default
    // expectation). This proves the structured-output attempt fired AND the
    // retry without schema fired — without these asserts the test could pass
    // by accidentally hitting `good` twice.
    bad.assert();
    good.assert();
}

#[test]
fn json_wrapped_in_markdown_fence_is_accepted() {
    let mut server = Server::new();
    let fenced = format!("```json\n{}\n```", findings_content_one());
    let m = server
        .mock("POST", "/chat/completions")
        .with_status(200)
        .with_body(ok_response(&fenced, 50, 10))
        .create();

    let runtime = runtime_for(&server.url());
    let client = OpenAiCompatibleClient::new(&runtime).unwrap();
    let prompt = render(&PromptInputs {
        candidate: &synth_candidate(),
        structural_finding: None,
    });

    let response = client.analyze(&prompt).unwrap();
    assert_eq!(response.findings.len(), 1);
    m.assert();
}

#[test]
fn http_400_with_response_format_triggers_retry() {
    // First attempt (with response_format) returns 400 — typical of a server
    // that hard-fails unsupported structured output rather than ignoring it.
    // Second attempt (without response_format) returns valid findings.
    let mut server = Server::new();

    let bad = server
        .mock("POST", "/chat/completions")
        .match_body(mockito::Matcher::PartialJsonString(
            r#"{"response_format": {}}"#.into(),
        ))
        .with_status(400)
        .with_body(r#"{"error": "response_format unsupported"}"#)
        .create();

    let good = server
        .mock("POST", "/chat/completions")
        .with_status(200)
        .with_body(ok_response(&findings_content_one(), 60, 30))
        .create();

    let runtime = runtime_for(&server.url());
    let client = OpenAiCompatibleClient::new(&runtime).unwrap();
    let prompt = render(&PromptInputs {
        candidate: &synth_candidate(),
        structural_finding: None,
    });

    let response = client.analyze(&prompt).unwrap();
    assert_eq!(response.findings.len(), 1);
    // Assert BOTH mocks fired exactly once — see the fallback-retry test
    // above for why this matters (without it, the structured-output attempt
    // could be silently skipped and the test would still pass).
    bad.assert();
    good.assert();
}

#[test]
fn http_400_without_response_format_surfaces_as_config_error() {
    // After retry, 400/422 should fall through to Config — no infinite loop.
    let mut server = Server::new();
    let m = server
        .mock("POST", "/chat/completions")
        .with_status(400)
        .with_body("bad request")
        .expect_at_least(2)
        .create();

    let runtime = runtime_for(&server.url());
    let client = OpenAiCompatibleClient::new(&runtime).unwrap();
    let prompt = render(&PromptInputs {
        candidate: &synth_candidate(),
        structural_finding: None,
    });

    let err = client.analyze(&prompt).unwrap_err();
    assert!(
        matches!(err, DeepError::Config(_)),
        "expected Config after retry, got: {err:?}"
    );
    m.assert();
}

#[test]
fn http_401_surfaces_as_config_error() {
    let mut server = Server::new();
    let m = server
        .mock("POST", "/chat/completions")
        .with_status(401)
        .with_body("{\"error\": \"unauthorized\"}")
        .create();

    let runtime = runtime_for(&server.url());
    let client = OpenAiCompatibleClient::new(&runtime).unwrap();
    let prompt = render(&PromptInputs {
        candidate: &synth_candidate(),
        structural_finding: None,
    });

    let err = client.analyze(&prompt).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("auth rejected"), "got: {msg}");
    m.assert();
}

#[test]
fn http_500_surfaces_as_transient_for_per_candidate_skip() {
    // 5xx is a transient server-side failure, NOT misconfiguration. It must
    // surface as `Transient` so the orchestrator's per-candidate skip path
    // takes it. Mapping to `Config` would hard-fail the whole deep run on
    // one upstream blip; mapping to `BadResponse` would (incorrectly) trigger
    // the schema-fallback retry — pointless during an outage and just doubles
    // upstream traffic.
    let mut server = Server::new();
    let m = server
        .mock("POST", "/chat/completions")
        .with_status(500)
        .with_body("internal server error")
        // EXACTLY one request: `analyze()` must NOT retry transient failures.
        .expect(1)
        .create();

    let runtime = runtime_for(&server.url());
    let client = OpenAiCompatibleClient::new(&runtime).unwrap();
    let prompt = render(&PromptInputs {
        candidate: &synth_candidate(),
        structural_finding: None,
    });

    let err = client.analyze(&prompt).unwrap_err();
    assert!(
        matches!(err, DeepError::Transient(_)),
        "expected Transient for 5xx, got: {err:?}",
    );
    let msg = format!("{err}");
    assert!(msg.contains("500"), "msg should reference status: {msg}");
    m.assert();
}

#[test]
fn http_429_surfaces_as_transient_for_per_candidate_skip() {
    // 429 Too Many Requests is transient (rate-limit / quota), same bucket
    // as 5xx — must hit the per-candidate skip path, NOT abort via `Config`,
    // and NOT trigger the schema-fallback retry (it would just re-hit the
    // rate limit and worsen the situation).
    let mut server = Server::new();
    let m = server
        .mock("POST", "/chat/completions")
        .with_status(429)
        .with_body("rate limited")
        // EXACTLY one request: `analyze()` must NOT retry rate-limited responses.
        .expect(1)
        .create();

    let runtime = runtime_for(&server.url());
    let client = OpenAiCompatibleClient::new(&runtime).unwrap();
    let prompt = render(&PromptInputs {
        candidate: &synth_candidate(),
        structural_finding: None,
    });

    let err = client.analyze(&prompt).unwrap_err();
    assert!(
        matches!(err, DeepError::Transient(_)),
        "expected Transient for 429, got: {err:?}",
    );
    let msg = format!("{err}");
    assert!(msg.contains("429"), "msg should reference status: {msg}");
    m.assert();
}

#[test]
fn cost_tracker_caps_and_errors() {
    let mut runtime = runtime_for("http://unused");
    runtime.max_cost_usd = Some(0.01);
    runtime.cost_per_1k_input = Some(0.10); // 1k input = $0.10 → exceeds $0.01 cap

    let tracker = CostTracker::new(&runtime);
    let usage = TokenUsage {
        input_tokens: 1_000,
        output_tokens: 0,
    };
    let err = tracker.record(&usage).unwrap_err();
    assert!(matches!(err, DeepError::CostExceeded { .. }));
}

#[test]
fn request_body_includes_model_and_messages() {
    let mut server = Server::new();
    // Use mockito's body matcher to assert the request shape.
    let m = server
        .mock("POST", "/chat/completions")
        .match_body(mockito::Matcher::AllOf(vec![
            mockito::Matcher::PartialJsonString(r#"{"model": "test-model"}"#.into()),
            mockito::Matcher::PartialJsonString(
                r#"{"messages": [{"role": "system"}, {"role": "user"}]}"#.into(),
            ),
            mockito::Matcher::PartialJsonString(r#"{"temperature": 0.0}"#.into()),
        ]))
        .with_status(200)
        .with_body(ok_response(r#"{"findings": []}"#, 10, 5))
        .create();

    let runtime = runtime_for(&server.url());
    let client = OpenAiCompatibleClient::new(&runtime).unwrap();
    let prompt = render(&PromptInputs {
        candidate: &synth_candidate(),
        structural_finding: None,
    });

    client.analyze(&prompt).unwrap();
    m.assert();
}

#[test]
fn missing_usage_field_defaults_to_zero() {
    // Some local servers don't return usage at all.
    let mut server = Server::new();
    let response_without_usage = json!({
        "id": "chatcmpl-test",
        "model": "test-model",
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": r#"{"findings": []}"#},
            "finish_reason": "stop"
        }]
    })
    .to_string();
    let m = server
        .mock("POST", "/chat/completions")
        .with_status(200)
        .with_body(response_without_usage)
        .create();

    let runtime = runtime_for(&server.url());
    let client = OpenAiCompatibleClient::new(&runtime).unwrap();
    let prompt = render(&PromptInputs {
        candidate: &synth_candidate(),
        structural_finding: None,
    });

    let response = client.analyze(&prompt).unwrap();
    assert_eq!(response.usage.input_tokens, 0);
    assert_eq!(response.usage.output_tokens, 0);
    m.assert();
}

// -- End-to-end deep::run tests --------------------------------------------

use std::fs;
use std::path::PathBuf;
use tempfile::tempdir;
use zift::types::{Finding, ScanPass, Surface};

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
        rego_stub: None,
        cedar_stub: None,
        pass: ScanPass::Structural,
        surface: Surface::Backend,
    }
}

#[test]
fn deep_run_end_to_end_produces_semantic_finding() {
    let dir = tempdir().unwrap();
    // Write a source file containing an auth-y function so cold-region picks it up.
    fs::write(
        dir.path().join("auth.ts"),
        "// imports here\nfunction isAdmin(user) {\n  return user.role === 'admin';\n}\n",
    )
    .unwrap();

    let mut server = Server::new();
    let _m = server
        .mock("POST", "/chat/completions")
        .with_status(200)
        .with_body(ok_response(
            &json!({
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
            .to_string(),
            120,
            40,
        ))
        .expect_at_least(1)
        .create();

    let runtime = runtime_for(&server.url());

    // No structural findings — cold-region scan should pick up isAdmin.
    let merged = zift::deep::run(Vec::new(), dir.path(), &runtime).unwrap();

    assert!(!merged.is_empty(), "expected at least one semantic finding");
    let semantic: Vec<&Finding> = merged
        .iter()
        .filter(|f| f.pass == ScanPass::Semantic)
        .collect();
    assert_eq!(semantic.len(), 1);
    assert_eq!(semantic[0].category, AuthCategory::Rbac);
    assert_eq!(semantic[0].confidence, Confidence::High);
}

#[test]
fn deep_run_drops_structural_when_model_flags_false_positive() {
    let dir = tempdir().unwrap();
    // Write a source file with auth-y content so the structural finding can resolve.
    fs::write(
        dir.path().join("auth.ts"),
        "function maybeAuth() {\n  // not actually authz\n  return true;\n}\n",
    )
    .unwrap();

    let mut server = Server::new();
    let _m = server
        .mock("POST", "/chat/completions")
        .with_status(200)
        .with_body(ok_response(
            &json!({
                "findings": [{
                    "line_start": 1,
                    "line_end": 3,
                    "category": "custom",
                    "confidence": "low",
                    "description": "not really auth",
                    "reasoning": "function name is misleading; no actual authz logic",
                    "is_false_positive": true
                }]
            })
            .to_string(),
            80,
            20,
        ))
        .expect_at_least(1)
        .create();

    let runtime = runtime_for(&server.url());
    let structural = vec![structural_finding("auth.ts", 1)];

    let merged = zift::deep::run(structural, dir.path(), &runtime).unwrap();

    // The structural finding was the only input; the model rejected it.
    // Result should be empty (no semantic finding emitted, no structural retained).
    assert!(merged.is_empty(), "expected empty result, got: {merged:?}");
}

#[test]
fn deep_run_emits_findings_in_deterministic_order() {
    // Three structural findings across two files; deep::run must return
    // them sorted by (file, line_start, line_end), regardless of the
    // randomized HashMap iteration internally.
    let dir = tempdir().unwrap();
    fs::write(dir.path().join("a.ts"), "x\n".repeat(100)).unwrap();
    fs::write(dir.path().join("b.ts"), "x\n".repeat(100)).unwrap();

    let mut server = Server::new();
    // Model returns no findings — keeps focus on the structural ordering.
    let _m = server
        .mock("POST", "/chat/completions")
        .with_status(200)
        .with_body(ok_response(r#"{"findings": []}"#, 10, 5))
        .expect_at_least(1)
        .create();
    let runtime = runtime_for(&server.url());

    let structural = vec![
        structural_finding("b.ts", 50),
        structural_finding("a.ts", 80),
        structural_finding("a.ts", 10),
    ];
    let merged = zift::deep::run(structural, dir.path(), &runtime).unwrap();

    let order: Vec<(String, usize)> = merged
        .iter()
        .map(|f| (f.file.display().to_string(), f.line_start))
        .collect();
    assert_eq!(
        order,
        vec![
            ("a.ts".to_string(), 10),
            ("a.ts".to_string(), 80),
            ("b.ts".to_string(), 50),
        ]
    );
}

#[test]
fn deep_run_preserves_findings_when_cost_cap_trips_mid_run() {
    // Two cold-region candidates. Tight cap + high rates → first response
    // tips us over the cap. The orchestrator should keep that first
    // semantic finding and the surviving structural set (none here),
    // not propagate CostExceeded as an error.
    let dir = tempdir().unwrap();
    fs::write(
        dir.path().join("a.ts"),
        "function isAdmin(u) { return u.role === 'admin'; }\n",
    )
    .unwrap();
    fs::write(
        dir.path().join("b.ts"),
        "function hasPermission(u) { return u.perms.includes('x'); }\n",
    )
    .unwrap();

    let mut server = Server::new();
    let _m = server
        .mock("POST", "/chat/completions")
        .with_status(200)
        .with_body(ok_response(
            &json!({
                "findings": [{
                    "line_start": 1,
                    "line_end": 1,
                    "category": "rbac",
                    "confidence": "high",
                    "description": "role check",
                    "reasoning": "isAdmin role comparison",
                    "is_false_positive": false
                }]
            })
            .to_string(),
            10_000, // huge usage so the very first record() trips the cap
            5_000,
        ))
        .expect_at_least(1)
        .create();

    let mut runtime = runtime_for(&server.url());
    runtime.max_cost_usd = Some(0.01);
    runtime.cost_per_1k_input = Some(1.00); // 10k input @ $1/k = $10 → way over $0.01 cap
    runtime.cost_per_1k_output = Some(1.00);

    // Should NOT return Err(CostExceeded) — should return what was collected.
    let merged = zift::deep::run(Vec::new(), dir.path(), &runtime)
        .expect("cap breach must not propagate as error");
    let semantic: Vec<&Finding> = merged
        .iter()
        .filter(|f| f.pass == ScanPass::Semantic)
        .collect();
    assert_eq!(
        semantic.len(),
        1,
        "expected to keep the in-flight semantic finding, got: {merged:?}",
    );
}

#[test]
fn deep_run_returns_structural_unchanged_when_no_candidates() {
    let dir = tempdir().unwrap();
    // No source files; no auth-y content; no structural findings.
    // deep::run should return the empty input as-is without making HTTP calls.

    let mut server = Server::new();
    let m = server
        .mock("POST", "/chat/completions")
        .with_status(500) // would fail if called; we shouldn't call it
        .expect(0)
        .create();

    let runtime = runtime_for(&server.url());
    let merged = zift::deep::run(Vec::new(), dir.path(), &runtime).unwrap();
    assert!(merged.is_empty());
    m.assert();
}
