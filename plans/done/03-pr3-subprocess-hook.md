# PR 3 — Tier 3 deep scan: subprocess hook

Companion to [00-deep-mode-overview.md](./00-deep-mode-overview.md). Builds on the primitives shipped in [PR 1](../done/01-pr1-deep-http-transport.md). The smallest of the three transports — an escape hatch for any agent that doesn't fit Tier 1 (MCP) or Tier 2 (HTTP).

**Status**: not started. Depends on PR 1 landing.

## 1. Goal & scope

Add `--agent-cmd "<command>"` flag. Zift writes the rendered prompt + candidate JSON to the subprocess's stdin and reads JSON matching the deep-mode schema from its stdout. Use cases:

- `claude -p` (the Claude Code CLI in print mode)
- `aider` running in a constrained mode
- A user shell script that does whatever wrapping they need
- Any agent that exposes a stdin-in / stdout-out contract

Out of scope: process pooling, IPC beyond stdin/stdout, environment-variable injection beyond what the user's shell provides.

## 2. CLI surface

```bash
zift scan ./repo --deep --agent-cmd "claude -p --output-format json"
```

In `.zift.toml`:

```toml
[deep]
mode = "subprocess"
agent_cmd = "claude -p --output-format json"
agent_timeout_secs = 600     # generous; LLM CLIs can be slow
```

Mode resolution: CLI `--agent-cmd` implies `mode = "subprocess"`. Explicit `mode = "subprocess"` without `agent_cmd` is a hard error.

## 3. Implementation sketch

New module: `src/deep/subprocess.rs`. Roughly 100-150 lines.

```rust
pub struct SubprocessClient {
    cmd: String,
    timeout: Duration,
}

impl SubprocessClient {
    pub fn new(runtime: &DeepRuntime) -> Result<Self, DeepError>;
    pub fn analyze(&self, prompt: &RenderedPrompt) -> Result<AnalyzeResponse, DeepError>;
}
```

`analyze` flow:

1. Spawn the command via `std::process::Command::new("sh").arg("-c").arg(&self.cmd)` with stdin/stdout piped.
2. Write to stdin a single JSON envelope: `{ "system": ..., "user": ..., "schema": ... }`. Close stdin.
3. Read stdout to EOF (with timeout).
4. Parse stdout as the same JSON schema as PR 1's HTTP path (`output_schema`).
5. Return `AnalyzeResponse { findings, usage: TokenUsage::zero() }` — token tracking N/A here.

## 4. Architectural reuse

The orchestrator (`deep::run`) becomes generic over the analyzer:

```rust
trait Analyzer {
    fn analyze(&self, prompt: &RenderedPrompt) -> Result<AnalyzeResponse, DeepError>;
}

impl Analyzer for OpenAiCompatibleClient { ... }   // PR 1
impl Analyzer for SubprocessClient { ... }         // PR 3
```

Trait introduced in this PR (or backported into PR 1 if PR 2 already needed it). The candidate selector, prompt renderer, schema, merge, and cost tracker are all reused unchanged.

`mode` field on `DeepRuntime` selects which analyzer to instantiate.

## 5. Cost tracking

N/A. Subprocess agents don't return token counts in any standard way. `CostTracker` is bypassed for this transport (treat every call as $0). If users want a ceiling, they enforce it externally — `timeout`, `ulimit`, or a wrapper script that counts invocations.

## 6. Test plan

- Unit-test envelope construction (JSON shape).
- Integration test with a tiny shell-script "agent": writes a canned response to stdout. Mock contract is portable (POSIX `cat <<EOF` style). Skip on Windows or use a Rust binary in `tests/fixtures/`.
- Test for malformed-stdout error path.
- Test for timeout (subprocess that sleeps forever).
- Test for nonzero exit (subprocess that exits 1 — should surface as `DeepError`).

## 7. Open questions

1. **Shell vs direct exec.** Using `sh -c` lets users supply pipelines (`claude -p | jq ...`) but creates a Windows-portability issue. Lean: `sh -c` on Unix, `cmd /c` on Windows. Or document Unix-only for v1.
2. **Stdin envelope format.** JSON object with `{system, user, schema}` (proposed) vs a single big string concatenated for the user prompt. Lean toward JSON — agents that wrap real LLMs can route system/user separately; trivial-to-skip otherwise.
3. **Concurrency.** Default to `max_concurrent: 1` for subprocess (some agent CLIs serialize internally; spawning 4 of them is not always faster). Document this.
4. **Streaming output.** Some agent CLIs stream tokens. We require the final full JSON; if the CLI streams partial JSON, we read to EOF and parse the whole buffer. Document.

## 8. Commit sequence (rough)

1. `refactor(deep): introduce Analyzer trait, port OpenAI client to it`
2. `feat(deep): add subprocess analyzer + --agent-cmd flag`
3. `test(deep): subprocess integration test with shell-script fixture`
4. `docs: example agent-cmd usages (claude -p, aider, custom script)`

Each commit small and reviewable.

## 9. Risks

- **Hard to debug.** When a user's `agent_cmd` returns garbage, the failure mode is opaque. Surface a generic, non-sensitive error to the user (e.g. "agent_cmd failed to parse output"). Gate verbose stdout/stderr capture behind explicit debug logging (e.g. `RUST_LOG=zift::deep=debug`), and even there cap the snippet length and apply the same redaction discipline as `src/deep/client.rs` — `agent_cmd` output can mirror prompt text and scanned source verbatim, which would re-create the secret/source-leak class we already avoid in the HTTP client.
- **Security.** Running arbitrary shell commands the user configured is a footgun if `.zift.toml` is checked in to a repo and Zift is run by another user. Document; consider warning when `agent_cmd` is read from a `.zift.toml` not owned by the running user.

---

## 10. Shipped

**Branch**: `feat/deep-subprocess`
**Status**: open as PR.

### Module additions

- `src/deep/analyzer.rs` — `Analyzer` trait + relocated `AnalyzeResponse`/`TokenUsage` from `client.rs`. The seam between `deep::run` and concrete transports.
- `src/deep/subprocess.rs` — `SubprocessClient`, ~280 lines including unit tests. Spawns the user's command through the platform shell (`sh -c` on Unix, `cmd /C` on Windows), writes a JSON envelope to stdin, reads stdout to EOF with a wall-clock timeout enforced by polling `try_wait` at 50ms granularity. Stderr is captured for debug logs only.
- `tests/deep_subprocess_integration.rs` — 6 end-to-end tests against shell-script fixtures (`#![cfg(unix)]`).

### Plan deviations (all flagged in commit messages)

1. **`base_url`/`model` remain `String`, not `Option<String>`.** Plan §3 implied separate fields per mode. Switching to `Option` would have churned every call site (HTTP client constructor, `cost::CostTracker::new`, every test rt() helper). Empty strings in subprocess mode work because `OpenAiCompatibleClient::new` is never instantiated when `mode == Subprocess` — guarded by the `match` in `deep::run`. Documented on `DeepRuntime`.
2. **Spawn failures (sh exits 127) surface as `BadResponse`, not `Config`.** Plan §9 implied any spawn error was misconfiguration. In practice, `sh -c` itself spawns fine and returns 127 for "command not found" — that surfaces as nonzero exit, mapped to `BadResponse`, which the orchestrator skips. The user still gets a clear error from the per-candidate-skip warn-log; hard-failing the whole deep run on a typo felt heavy-handed when the structural pass would have already produced findings.
3. **Stdout/stderr drained via background threads with `mpsc::channel`.** Plan §3 sketched a single-thread-with-`read_to_string` flow. That deadlocks if the agent fills the stderr pipe (~64KB) before exiting — the writer thread blocks on stdin, the main thread blocks on stdout, and stderr never gets read. Three-thread design (writer, stdout reader, stderr reader) is necessary for backpressure correctness, not a stylistic choice.
4. **`SubprocessClient` derives `Debug`.** Required so `Result<SubprocessClient, _>::unwrap_err` works in `#[test]` blocks. Struct only contains a command string and `Duration` — nothing sensitive.
5. **No `wait_timeout` crate dep.** Plan §3 left the timeout strategy open. We poll `try_wait` at 50ms cadence inside the orchestrator's own loop; works on every platform without a new dependency. Latency overhead is rounding error against agent CLIs that take seconds-to-minutes per request.
6. **Plan moved to `done/` in this same PR.** Folder convention from `00-deep-mode-overview.md`. Overview file's PR 3 cross-reference updated to point at `../done/03-...`.

### Test counts

After this PR:

- 275 lib unit tests (was 253; +22 new in `deep::config::tests` and `deep::subprocess::tests`).
- 18 + 6 + 6 = 30 integration tests across 3 files (`deep_http_integration`, `mcp_stdio_integration`, `deep_subprocess_integration`).

### Open follow-ups

- **Concurrency** — subprocess transport is hard-pinned to `max_concurrent = 1`. Rationale: `claude -p` and friends serialize internally, parallelism rarely helps. If a real workload contradicts this, lift the cap behind explicit `[deep] max_concurrent = N`.
- **Windows fixture** — integration tests are `#![cfg(unix)]`. A Rust-binary fixture would unblock Windows CI. Defer until a Windows user files an issue.
- **Owner-mismatch warning on `.zift.toml`.** Plan §9 floated warning when `agent_cmd` comes from a config file not owned by the running user. Useful future hardening; not in scope here.
