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

    // First attempt (with response_format) returns garbage.
    let _bad = server
        .mock("POST", "/chat/completions")
        .match_body(mockito::Matcher::PartialJsonString(
            r#"{"response_format": {}}"#.into(),
        ))
        .with_status(200)
        .with_body(ok_response("not json", 50, 10))
        .create();

    // Second attempt (without response_format) returns valid findings.
    let _good = server
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
fn http_500_surfaces_as_config_error() {
    let mut server = Server::new();
    let m = server
        .mock("POST", "/chat/completions")
        .with_status(500)
        .with_body("internal server error")
        .create();

    let runtime = runtime_for(&server.url());
    let client = OpenAiCompatibleClient::new(&runtime).unwrap();
    let prompt = render(&PromptInputs {
        candidate: &synth_candidate(),
        structural_finding: None,
    });

    let err = client.analyze(&prompt).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("500"), "got: {msg}");
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
