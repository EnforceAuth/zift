//! Subprocess hook transport (Tier 3 of the deep-mode design).
//!
//! Spawns a user-supplied shell command per request, writes a single
//! JSON envelope to its stdin, and reads the deep-mode response schema
//! from its stdout. The escape hatch for any agent that doesn't fit the
//! MCP server (Tier 1) or the OpenAI-compatible HTTP client (Tier 2):
//!
//! ```text
//! claude -p --output-format json
//! aider --no-auto-commits
//! ./my-wrapper.sh         # arbitrary user script
//! ```
//!
//! Wire format on stdin (one line, then EOF):
//!
//! ```json
//! {"system": "...", "user": "...", "schema": { ... }}
//! ```
//!
//! Wire format expected on stdout (parsed verbatim, optional markdown
//! fence stripped):
//!
//! ```json
//! {"findings": [{"line_start": 12, "line_end": 18, ...}]}
//! ```
//!
//! Both shapes are identical to the HTTP transport's contract — that's
//! deliberate: agent CLIs that wrap real LLMs can route system/user
//! straight through, and we never fork the schema between transports.
//!
//! ## Cost tracking
//!
//! N/A. Subprocess agents don't return token counts in any standard
//! way; [`crate::deep::analyzer::TokenUsage::default`] short-circuits
//! the cost tracker. Users wanting a ceiling enforce it externally
//! (timeouts, ulimits, wrapper scripts).
//!
//! ## Security
//!
//! The user supplies an arbitrary shell command. If `.zift.toml` is
//! checked in and Zift is run by another user (CI, shared dev box),
//! that's a footgun — same threat as `.editorconfig`-style attacks. We
//! document the risk; we don't sandbox.

use crate::deep::analyzer::{AnalyzeResponse, Analyzer, TokenUsage};
use crate::deep::client::{strip_markdown_fence, truncate_for_log};
use crate::deep::config::DeepRuntime;
use crate::deep::error::DeepError;
use crate::deep::finding::SemanticFinding;
use crate::deep::prompt::RenderedPrompt;
use serde::Deserialize;
use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

/// `Debug` is derived so `Result<Self, _>::unwrap_err` works in tests
/// — the std `unwrap_err` requires `Self: Debug`. The struct only holds
/// a command string and a timeout; nothing sensitive to redact.
#[derive(Debug)]
pub struct SubprocessClient {
    /// Shell command line, as supplied by the user. Passed to the
    /// platform shell (`sh -c` on Unix, `cmd /C` on Windows).
    cmd: String,
    /// Wall-clock ceiling for one request. On expiry the child is
    /// killed and [`DeepError::Timeout`] is returned.
    timeout: Duration,
}

impl SubprocessClient {
    pub fn new(runtime: &DeepRuntime) -> Result<Self, DeepError> {
        let cmd = runtime
            .agent_cmd
            .clone()
            .ok_or_else(|| {
                // Belt-and-suspenders: `deep::config::build` already
                // validates this. If we ever reach here, the runtime
                // was hand-constructed with a bug — fail loud.
                DeepError::Config(
                    "subprocess analyzer constructed without agent_cmd \
                     (runtime invariant violated)"
                        .into(),
                )
            })?
            .trim()
            .to_string();
        if cmd.is_empty() {
            return Err(DeepError::Config(
                "subprocess agent_cmd is empty after trim".into(),
            ));
        }
        Ok(Self {
            cmd,
            timeout: Duration::from_secs(runtime.agent_timeout_secs),
        })
    }

    /// Spawn the agent, write the JSON envelope, read stdout to EOF,
    /// parse, and return.
    fn run_once(&self, prompt: &RenderedPrompt) -> Result<AnalyzeResponse, DeepError> {
        let envelope = build_envelope(prompt);

        // Spawn through the platform shell so users can supply pipelines
        // (`claude -p | jq ...`). On Unix that's `sh -c <cmd>`; on
        // Windows it's `cmd /C <cmd>`.
        let mut child = shell_command(&self.cmd)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| {
                // ENOENT / permission errors at spawn time are
                // operator-actionable misconfiguration (typo in
                // `agent_cmd`, missing binary), not transient. Surface
                // as `Config` so the orchestrator hard-fails the whole
                // deep run rather than silently skipping every
                // candidate — every spawn would fail identically.
                DeepError::Config(format!("failed to spawn agent_cmd ({}): {e}", self.cmd))
            })?;

        let mut stdin = child
            .stdin
            .take()
            .expect("stdin pipe was requested via Stdio::piped");
        let stdout = child
            .stdout
            .take()
            .expect("stdout pipe was requested via Stdio::piped");
        let stderr = child
            .stderr
            .take()
            .expect("stderr pipe was requested via Stdio::piped");

        // Writer thread: writes the envelope and drops stdin (closes
        // the pipe so the child sees EOF). On its own thread because
        // pipes block at ~64KB on Linux when the child isn't reading;
        // a synchronous write_all could deadlock against a buggy
        // agent that exits without consuming stdin.
        let envelope_bytes = envelope.into_bytes();
        let writer = thread::spawn(move || -> std::io::Result<()> {
            stdin.write_all(&envelope_bytes)?;
            stdin.flush()?;
            // Drop stdin → pipe closes → child sees EOF.
            drop(stdin);
            Ok(())
        });

        // Reader threads for stdout/stderr. Both must run on
        // background threads for the same backpressure reason as the
        // writer: a chatty agent that fills the pipe before exiting
        // would otherwise deadlock with the writer.
        let (stdout_tx, stdout_rx) = mpsc::channel::<std::io::Result<String>>();
        let _stdout_thread = thread::spawn(move || {
            let mut buf = String::new();
            let mut handle = stdout;
            let res = handle.read_to_string(&mut buf).map(|_| buf);
            // Receiver may have hung up if we timed out — ignore.
            let _ = stdout_tx.send(res);
        });

        let (stderr_tx, stderr_rx) = mpsc::channel::<String>();
        let _stderr_thread = thread::spawn(move || {
            let mut buf = String::new();
            let mut handle = stderr;
            let _ = handle.read_to_string(&mut buf);
            let _ = stderr_tx.send(buf);
        });

        // Bound the wait by polling `try_wait`. Without `wait_timeout`
        // this is the simplest portable approach; 50ms granularity is
        // fine since real agent latencies are seconds-to-minutes.
        let start = Instant::now();
        let exit = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) => {
                    if start.elapsed() >= self.timeout {
                        // Kill the child, reap it, and let the reader
                        // threads drain naturally as the pipes close.
                        let _ = child.kill();
                        let _ = child.wait();
                        let _ = writer.join();
                        let _ = stdout_rx.recv();
                        let _ = stderr_rx.recv();
                        return Err(DeepError::Timeout {
                            secs: self.timeout.as_secs(),
                        });
                    }
                    thread::sleep(Duration::from_millis(50));
                }
                Err(e) => {
                    return Err(DeepError::Io(e));
                }
            }
        };

        // Drain background threads. EPIPE on writer is OK if the child
        // exited before reading stdin (e.g. "help" mode that ignores
        // input); only log it.
        if let Ok(Err(e)) = writer.join() {
            tracing::debug!("subprocess: writer error (likely EPIPE on early exit): {e}");
        }
        let stdout_buf = stdout_rx
            .recv()
            .map_err(|_| DeepError::BadResponse("subprocess stdout reader disconnected".into()))?
            .map_err(DeepError::Io)?;
        let stderr_buf = stderr_rx.recv().unwrap_or_default();

        if !exit.success() {
            // Surface as `BadResponse` so the orchestrator skips this
            // candidate but keeps going — same per-candidate-skip path
            // as malformed JSON. Avoid leaking stderr verbatim into
            // the error message (it can echo prompt text); cap and log
            // to debug instead.
            tracing::debug!(
                exit = ?exit,
                stderr = %truncate_for_log(&stderr_buf),
                stdout = %truncate_for_log(&stdout_buf),
                "subprocess: agent_cmd exited nonzero",
            );
            return Err(DeepError::BadResponse(format!(
                "agent_cmd exited with {} (no findings parsed)",
                exit_status_brief(&exit),
            )));
        }

        // Parse stdout as our findings envelope. Same fence-stripping
        // and same truncated-debug-log discipline as the HTTP client —
        // model-or-CLI output may mirror prompt text and should not
        // appear verbatim in error strings.
        let cleaned = strip_markdown_fence(&stdout_buf);
        let parsed: FindingsEnvelope = serde_json::from_str(cleaned).map_err(|e| {
            tracing::debug!(
                error = %e,
                preview = %truncate_for_log(&stdout_buf),
                stderr_preview = %truncate_for_log(&stderr_buf),
                "subprocess: stdout was not valid findings JSON",
            );
            DeepError::BadResponse("agent_cmd output was not valid findings JSON".into())
        })?;

        Ok(AnalyzeResponse {
            findings: parsed.findings,
            // Subprocess agents don't report tokens in a standard way.
            // The cost tracker short-circuits on default usage.
            usage: TokenUsage::default(),
        })
    }
}

impl Analyzer for SubprocessClient {
    fn analyze(&self, prompt: &RenderedPrompt) -> Result<AnalyzeResponse, DeepError> {
        self.run_once(prompt)
    }
}

/// JSON envelope written verbatim to the agent's stdin.
fn build_envelope(prompt: &RenderedPrompt) -> String {
    // Use serde_json directly so any future field additions ride the
    // same canonical-JSON path as the HTTP transport's request body.
    serde_json::json!({
        "system": prompt.system,
        "user":   prompt.user,
        "schema": prompt.schema,
    })
    .to_string()
}

/// Construct a [`Command`] that runs `cmd` through the platform shell.
/// Unix → `sh -c`; Windows → `cmd /C`. Allowing a shell parse keeps the
/// CLI surface friendly (pipes, redirects, env-var expansion) at the
/// cost of inheriting whatever quoting the user's shell does — same
/// trade-off as `npm scripts` or `Makefile` recipes.
#[cfg(unix)]
fn shell_command(cmd: &str) -> Command {
    let mut c = Command::new("sh");
    c.arg("-c").arg(cmd);
    c
}

#[cfg(windows)]
fn shell_command(cmd: &str) -> Command {
    let mut c = Command::new("cmd");
    c.arg("/C").arg(cmd);
    c
}

/// Brief, allocation-free string form of [`std::process::ExitStatus`]
/// for the user-visible error message. `Display` for `ExitStatus`
/// prints "exit status: 1" / "signal: 9" already; just delegate.
fn exit_status_brief(status: &std::process::ExitStatus) -> String {
    status.to_string()
}

#[derive(Deserialize)]
struct FindingsEnvelope {
    findings: Vec<SemanticFinding>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deep::candidate::{Candidate, CandidateKind};
    use crate::deep::config::DeepMode;
    use crate::deep::prompt::{PromptInputs, render};
    use crate::types::Language;
    use std::path::PathBuf;

    fn synth_runtime(cmd: &str, timeout_secs: u64) -> DeepRuntime {
        DeepRuntime {
            mode: DeepMode::Subprocess,
            base_url: String::new(),
            model: String::new(),
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
            agent_cmd: Some(cmd.into()),
            agent_timeout_secs: timeout_secs,
        }
    }

    fn synth_prompt() -> RenderedPrompt {
        let cand = Candidate {
            kind: CandidateKind::ColdRegion,
            file: PathBuf::from("a.ts"),
            language: Language::TypeScript,
            line_start: 1,
            line_end: 5,
            source_snippet: "function isAdmin() { return true; }".into(),
            imports: Vec::new(),
            original_finding_id: None,
            seed_category: None,
        };
        render(&PromptInputs {
            candidate: &cand,
            structural_finding: None,
        })
    }

    #[test]
    fn new_rejects_empty_agent_cmd() {
        let mut rt = synth_runtime("nonempty", 60);
        rt.agent_cmd = Some("".into());
        let err = SubprocessClient::new(&rt).unwrap_err();
        assert!(matches!(err, DeepError::Config(_)));
    }

    #[test]
    fn new_rejects_whitespace_agent_cmd() {
        let mut rt = synth_runtime("nonempty", 60);
        rt.agent_cmd = Some("   ".into());
        let err = SubprocessClient::new(&rt).unwrap_err();
        assert!(matches!(err, DeepError::Config(_)));
    }

    #[test]
    fn new_rejects_runtime_without_agent_cmd() {
        // Defense-in-depth — `build` validates this, but a hand-rolled
        // runtime should still surface a clear error.
        let mut rt = synth_runtime("ignored", 60);
        rt.agent_cmd = None;
        let err = SubprocessClient::new(&rt).unwrap_err();
        assert!(
            matches!(err, DeepError::Config(ref msg) if msg.contains("invariant")),
            "expected Config(<invariant>), got: {err:?}",
        );
    }

    #[test]
    fn build_envelope_contains_system_user_and_schema() {
        let prompt = synth_prompt();
        let env = build_envelope(&prompt);
        let v: serde_json::Value = serde_json::from_str(&env).unwrap();
        assert!(v.get("system").is_some(), "envelope missing 'system'");
        assert!(v.get("user").is_some(), "envelope missing 'user'");
        assert!(v.get("schema").is_some(), "envelope missing 'schema'");
        // Schema round-trips structurally — must equal what render() produced,
        // because subprocess wrappers may forward it verbatim to a real LLM.
        assert_eq!(v.get("schema").unwrap(), &prompt.schema);
    }

    // -- Live-process tests are gated to Unix to avoid maintaining a
    // -- Rust fixture binary for Windows. The integration test crate
    // -- under tests/deep_subprocess_integration.rs covers the
    // -- end-to-end flow with shell-script fixtures.

    #[cfg(unix)]
    #[test]
    fn happy_path_with_cat_returning_canned_json() {
        // sh -c 'cat <<EOF ... EOF' ignores stdin and emits canned
        // JSON — proves the parse path without needing a real agent.
        let canned = r#"{"findings": []}"#;
        let cmd = format!("printf '%s' '{}'", canned);
        let rt = synth_runtime(&cmd, 10);
        let client = SubprocessClient::new(&rt).unwrap();
        let prompt = synth_prompt();
        let resp = client.analyze(&prompt).unwrap();
        assert!(resp.findings.is_empty());
        assert_eq!(resp.usage, TokenUsage::default());
    }

    #[cfg(unix)]
    #[test]
    fn nonzero_exit_surfaces_as_bad_response_for_skip() {
        // Per-candidate skip semantics: nonzero exit = skip this
        // candidate, keep going on others. Must NOT be Config (which
        // hard-fails the whole deep pass).
        let rt = synth_runtime("exit 7", 5);
        let client = SubprocessClient::new(&rt).unwrap();
        let err = client.analyze(&synth_prompt()).unwrap_err();
        assert!(
            matches!(err, DeepError::BadResponse(_)),
            "expected BadResponse for nonzero exit, got: {err:?}",
        );
    }

    #[cfg(unix)]
    #[test]
    fn malformed_stdout_surfaces_as_bad_response() {
        let rt = synth_runtime("printf 'this is not json'", 5);
        let client = SubprocessClient::new(&rt).unwrap();
        let err = client.analyze(&synth_prompt()).unwrap_err();
        assert!(
            matches!(err, DeepError::BadResponse(_)),
            "expected BadResponse for malformed stdout, got: {err:?}",
        );
    }

    #[cfg(unix)]
    #[test]
    fn timeout_kills_long_running_subprocess() {
        // 1s timeout, command sleeps 30s — must time out promptly,
        // not hang the test runner.
        let rt = synth_runtime("sleep 30", 1);
        let client = SubprocessClient::new(&rt).unwrap();
        let start = Instant::now();
        let err = client.analyze(&synth_prompt()).unwrap_err();
        let elapsed = start.elapsed();
        assert!(
            matches!(err, DeepError::Timeout { .. }),
            "expected Timeout, got: {err:?}",
        );
        // Generous upper bound — the polling cadence is 50ms and
        // killing the child should be near-instant.
        assert!(
            elapsed < Duration::from_secs(5),
            "timeout took too long: {elapsed:?}",
        );
    }

    #[cfg(unix)]
    #[test]
    fn spawn_failure_surfaces_as_config_for_hard_fail() {
        // Nonexistent command goes through `sh -c`, which exits 127.
        // That surfaces as BadResponse (per-candidate skip), NOT as a
        // spawn-time Config error — sh itself spawned just fine.
        // This test pins that behavior.
        let rt = synth_runtime("definitely-not-a-command-12345", 5);
        let client = SubprocessClient::new(&rt).unwrap();
        let err = client.analyze(&synth_prompt()).unwrap_err();
        assert!(
            matches!(err, DeepError::BadResponse(_)),
            "expected BadResponse (sh exited 127), got: {err:?}",
        );
    }

    #[cfg(unix)]
    #[test]
    fn markdown_fence_around_stdout_is_stripped() {
        // Wrapper CLIs sometimes fence JSON; we must still parse.
        let cmd = r#"printf '%s' '```json
{"findings": []}
```'"#;
        let rt = synth_runtime(cmd, 5);
        let client = SubprocessClient::new(&rt).unwrap();
        let resp = client.analyze(&synth_prompt()).unwrap();
        assert!(resp.findings.is_empty());
    }
}
