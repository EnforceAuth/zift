//! End-to-end integration test for the MCP server.
//!
//! Spawns `zift mcp` as a subprocess, drives the JSON-RPC handshake over
//! stdin/stdout, and asserts the protocol-level shape of responses. This
//! catches regressions the in-process unit tests can't (e.g. accidental
//! `println!` to stdout from anywhere on the call path, or a tracing
//! subscriber that writes to stdout instead of stderr).

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

use serde_json::{Value, json};

/// Path to the `zift` binary built by Cargo for this test run.
fn zift_bin() -> std::path::PathBuf {
    // CARGO_BIN_EXE_<bin name> is set by Cargo for integration tests.
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_zift"))
}

/// Spawn `zift mcp --scan-root <tmp>` and return the child + line-buffered
/// reader of its stdout.
fn spawn_server(
    scan_root: &std::path::Path,
) -> (std::process::Child, BufReader<std::process::ChildStdout>) {
    let mut child = Command::new(zift_bin())
        .arg("mcp")
        .arg("--scan-root")
        .arg(scan_root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        // Keep stderr inherited so test runners surface log output on failure.
        .stderr(Stdio::inherit())
        .spawn()
        .expect("zift mcp should spawn");
    let stdout = child.stdout.take().expect("stdout piped");
    let reader = BufReader::new(stdout);
    (child, reader)
}

fn send(child: &mut std::process::Child, msg: &Value) {
    let stdin = child.stdin.as_mut().expect("stdin piped");
    let line = serde_json::to_string(msg).unwrap();
    stdin.write_all(line.as_bytes()).unwrap();
    stdin.write_all(b"\n").unwrap();
    stdin.flush().unwrap();
}

fn read_one(reader: &mut BufReader<std::process::ChildStdout>) -> Value {
    let mut line = String::new();
    let n = reader.read_line(&mut line).expect("server stdout readable");
    assert!(n > 0, "server returned EOF instead of a JSON-RPC frame");
    serde_json::from_str(line.trim())
        .unwrap_or_else(|e| panic!("server emitted non-JSON line: {line:?} ({e})"))
}

fn shutdown(mut child: std::process::Child) {
    // Closing stdin signals clean shutdown — same path agent hosts use.
    drop(child.stdin.take());
    let status = child.wait().expect("server should exit on stdin close");
    assert!(status.success(), "server exited with: {status:?}");
}

#[test]
fn handshake_then_tools_list_then_resources_list() {
    let dir = tempfile::tempdir().unwrap();
    let (mut child, mut reader) = spawn_server(dir.path());

    // 1. initialize handshake
    send(
        &mut child,
        &json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2024-11-05"}
        }),
    );
    let resp = read_one(&mut reader);
    assert_eq!(resp["id"], 1);
    assert_eq!(resp["result"]["protocolVersion"], "2024-11-05");
    assert_eq!(resp["result"]["serverInfo"]["name"], "zift");
    assert!(resp["result"]["capabilities"]["tools"].is_object());
    assert!(resp["result"]["capabilities"]["resources"].is_object());

    // 2. notifications/initialized — no response expected.
    send(
        &mut child,
        &json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
        }),
    );

    // 3. tools/list
    send(
        &mut child,
        &json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
    );
    let resp = read_one(&mut reader);
    assert_eq!(resp["id"], 2);
    let tools = resp["result"]["tools"].as_array().unwrap();
    let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
    for expected in [
        "scan_authz",
        "get_finding_context",
        "list_rules",
        "get_rule",
        "suggest_rego",
        "validate_rego",
        "analyze_snippet",
    ] {
        assert!(names.contains(&expected), "tool {expected} missing");
    }
    // Every descriptor must have a JSON Schema input.
    for t in tools {
        assert_eq!(t["inputSchema"]["type"], "object", "{:?}", t["name"]);
    }

    // 4. resources/list
    send(
        &mut child,
        &json!({"jsonrpc": "2.0", "id": 3, "method": "resources/list"}),
    );
    let resp = read_one(&mut reader);
    assert_eq!(resp["id"], 3);
    let resources = resp["result"]["resources"].as_array().unwrap();
    let uris: Vec<&str> = resources
        .iter()
        .map(|r| r["uri"].as_str().unwrap())
        .collect();
    assert!(uris.contains(&"prompt://system"));
    assert!(uris.contains(&"prompt://schema"));

    shutdown(child);
}

#[test]
fn tools_call_validate_rego_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let (mut child, mut reader) = spawn_server(dir.path());

    // initialize
    send(
        &mut child,
        &json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2024-11-05"}
        }),
    );
    let _ = read_one(&mut reader);

    // tools/call → validate_rego on a known-good policy
    send(
        &mut child,
        &json!({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {
                "name": "validate_rego",
                "arguments": {
                    "policy": "package x\nimport rego.v1\ndefault allow := false\n"
                }
            }
        }),
    );
    let resp = read_one(&mut reader);
    assert_eq!(resp["id"], 2);
    // Per MCP spec + our serde behavior, `isError` is omitted on success
    // (via `skip_serializing_if`). Treat missing-or-false as the success case.
    let is_error = resp["result"]["isError"].as_bool().unwrap_or(false);
    assert!(!is_error, "validate_rego unexpectedly errored: {resp:?}");
    let text = resp["result"]["content"][0]["text"].as_str().unwrap();
    let payload: Value = serde_json::from_str(text).unwrap();
    assert_eq!(payload["valid"], true);

    shutdown(child);
}

#[test]
fn tools_call_analyze_snippet_returns_system_and_schema() {
    let dir = tempfile::tempdir().unwrap();
    let (mut child, mut reader) = spawn_server(dir.path());

    send(
        &mut child,
        &json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2024-11-05"}
        }),
    );
    let _ = read_one(&mut reader);

    send(
        &mut child,
        &json!({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {
                "name": "analyze_snippet",
                "arguments": {
                    "file": "src/auth.ts",
                    "language": "typescript",
                    "line_start": 1,
                    "line_end": 2,
                    "snippet": "if (user.role === 'admin') { return true; }",
                    "imports": []
                }
            }
        }),
    );
    let resp = read_one(&mut reader);
    let text = resp["result"]["content"][0]["text"].as_str().unwrap();
    let payload: Value = serde_json::from_str(text).unwrap();
    assert!(payload["system"].as_str().unwrap().contains("CATEGORIES"));
    assert!(payload["user"].as_str().unwrap().contains("Lines: 1-2"));
    assert_eq!(payload["schema"]["required"][0], "findings");

    shutdown(child);
}

#[test]
fn resources_read_prompt_system_matches_canonical_constant() {
    let dir = tempfile::tempdir().unwrap();
    let (mut child, mut reader) = spawn_server(dir.path());

    send(
        &mut child,
        &json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2024-11-05"}
        }),
    );
    let _ = read_one(&mut reader);

    send(
        &mut child,
        &json!({
            "jsonrpc": "2.0", "id": 2, "method": "resources/read",
            "params": {"uri": "prompt://system"}
        }),
    );
    let resp = read_one(&mut reader);
    let contents = resp["result"]["contents"].as_array().unwrap();
    let body = contents[0]["text"].as_str().unwrap();
    // The plan §8 calls out this assertion specifically: prompt://system MUST
    // round-trip the canonical SYSTEM_PROMPT verbatim.
    assert_eq!(body, zift::deep::prompt::SYSTEM_PROMPT);

    shutdown(child);
}

#[test]
fn resources_read_prompt_schema_matches_canonical_schema() {
    let dir = tempfile::tempdir().unwrap();
    let (mut child, mut reader) = spawn_server(dir.path());

    send(
        &mut child,
        &json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2024-11-05"}
        }),
    );
    let _ = read_one(&mut reader);

    send(
        &mut child,
        &json!({
            "jsonrpc": "2.0", "id": 2, "method": "resources/read",
            "params": {"uri": "prompt://schema"}
        }),
    );
    let resp = read_one(&mut reader);
    let contents = resp["result"]["contents"].as_array().unwrap();
    let body = contents[0]["text"].as_str().unwrap();
    let parsed: Value = serde_json::from_str(body).unwrap();
    assert_eq!(parsed, zift::deep::prompt::output_schema());

    shutdown(child);
}

#[test]
fn unknown_method_returns_method_not_found_error_response() {
    let dir = tempfile::tempdir().unwrap();
    let (mut child, mut reader) = spawn_server(dir.path());

    send(
        &mut child,
        &json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2024-11-05"}
        }),
    );
    let _ = read_one(&mut reader);

    send(
        &mut child,
        &json!({"jsonrpc": "2.0", "id": 2, "method": "no/such/method"}),
    );
    let resp = read_one(&mut reader);
    assert_eq!(resp["id"], 2);
    assert_eq!(resp["error"]["code"], -32601);

    shutdown(child);
}
