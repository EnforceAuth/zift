# PR 3 — Tier 3 deep scan: subprocess hook

Companion to [00-deep-mode-overview.md](./00-deep-mode-overview.md). Builds on the primitives shipped in [PR 1](./01-pr1-deep-http-transport.md). The smallest of the three transports — an escape hatch for any agent that doesn't fit Tier 1 (MCP) or Tier 2 (HTTP).

**Status**: not started. Depends on PR 1 landing.

## 1. Goal & scope

Add `--agent-cmd "<command>"` flag. Zift writes the rendered prompt + candidate JSON to the subprocess's stdin and reads JSON matching the deep-mode schema from its stdout. Use cases:

- `claude -p` (the Claude Code CLI in print mode)
- `aider` running in a constrained mode
- A user shell script that does whatever wrapping they need
- Any agent that exposes a stdin-in / stdout-out contract

Out of scope: process pooling, IPC beyond stdin/stdout, environment-variable injection beyond what the user's shell provides.

## 2. CLI surface

```
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

- **Hard to debug.** When a user's `agent_cmd` returns garbage, the failure mode is opaque. Always print the first ~500 bytes of stdout to stderr on parse failure. Always print stderr from the subprocess on nonzero exit.
- **Security.** Running arbitrary shell commands the user configured is a footgun if `.zift.toml` is checked in to a repo and Zift is run by another user. Document; consider warning when `agent_cmd` is read from a `.zift.toml` not owned by the running user.
