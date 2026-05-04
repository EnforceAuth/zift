# zift

[![CI](https://github.com/EnforceAuth/zift/actions/workflows/ci.yml/badge.svg)](https://github.com/EnforceAuth/zift/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.91%2B-orange.svg)](https://www.rust-lang.org/)

Sift through your codebase for embedded authorization logic. Extract it into Policy as Code (PaC) — [Rego](https://www.openpolicyagent.org/docs/latest/policy-language/) for [OPA](https://www.openpolicyagent.org/) today, with other engines (e.g. Cedar) on the roadmap.

> **Status:** v0.1 — structural scanning ready for TypeScript, JavaScript, Java, Python, and Go. `--deep` (LLM-assisted) mode functional via any OpenAI-compatible endpoint or MCP-capable agent host.

## What is zift?

Most applications embed authorization decisions directly in application code: role checks in `if` statements, permission guards in middleware, business rules that act as access control. This scattered auth logic is hard to audit, hard to test, and impossible to enforce consistently.

**zift** scans your codebase, finds these embedded authorization patterns, and helps you externalize them into Policy as Code (PaC) — Rego policies for OPA today — that a policy engine can enforce centrally.

## How it works

```bash
zift .                          # structural scan of current directory (fast, free)
zift scan ./src --deep ...      # also run LLM-assisted semantic analysis
zift extract ./findings.json    # generate Policy-as-Code from scan findings (Rego today)
zift report .                   # detailed findings report
```

### Two-pass architecture

1. **Structural scan** (tree-sitter) — fast, deterministic, zero-cost. Finds known authorization patterns: role checks, permission guards, auth middleware, security annotations.

2. **Semantic scan** (`--deep`, opt-in) — sends candidate code regions to an LLM that classifies authorization logic the structural pass missed or misjudged. Useful for business rules that implicitly encode access control, and for languages where structural support hasn't shipped yet (C#, Kotlin, etc.).

## Supported languages

| Language | Structural | Deep (cold-region) | Framework hints (deep) |
|----------|-----------|---------------------|------------------------|
| TypeScript / JavaScript | yes (v0.1) | yes (v0.1) | Express, NestJS, Next.js |
| Java | yes (v0.1) | yes (v0.1) | Spring Security, Jakarta Security |
| Python | yes (v0.1) | yes (v0.1) | Django, Flask, FastAPI |
| Go | yes (v0.1) | yes (v0.1) | Gin, Echo |
| C# | planned (v0.2) | yes (v0.1) | ASP.NET Core |
| Kotlin | planned (v0.2) | yes (v0.1) | Spring (Kotlin) |
| Ruby | planned (v0.2) | yes (v0.1) | Rails |
| PHP | planned (v0.2) | yes (v0.1) | Laravel |

Deep mode walks the full source tree by extension and detects auth-y function names with regex — so it produces useful results in any language well before structural support lands.

## Installation

### Homebrew (macOS / Linux x86_64)

```bash
brew install enforceauth/tap/zift
```

### Cargo

```bash
cargo install zift
```

Prefer prebuilt binaries? [`cargo binstall zift`](https://github.com/cargo-bins/cargo-binstall) pulls the right archive from GitHub Releases automatically.

### Binary download

Prebuilt binaries for Linux (x86_64), macOS (x86_64 and arm64), and Windows (x86_64) are available from [Releases](https://github.com/EnforceAuth/zift/releases).

## Deep mode (`--deep`)

`--deep` ships three transports — pick whichever fits your existing tooling. Pick exactly one:

| Tier | Transport | When |
|------|-----------|------|
| 1 | **MCP server** (`zift mcp`) | You already use an agent host (Claude Code, Cursor, Continue, Cline, Zed). The host owns the model; Zift is a tool provider. |
| 2 | **OpenAI-compatible HTTP** (`--base-url`) | Headless / CI runs against any OpenAI-shaped chat-completions endpoint — Ollama, LM Studio, llama.cpp, vLLM, OpenRouter, OpenAI, Anthropic-via-proxy. |
| 3 | **Subprocess hook** (`--agent-cmd`) | Anything else — `claude -p`, `aider`, custom shell scripts. Stdin: prompt + JSON envelope. Stdout: JSON matching the deep-mode schema. |

> **New to `--deep`?** [`docs/DEEP_MODE_WALKTHROUGH.md`](docs/DEEP_MODE_WALKTHROUGH.md) is a hands-on tour of all three transports against the same fixture, with real commands, real outputs, and the differences between static and deep made explicit.

### HTTP transport (`--base-url`)

One client speaks to **any OpenAI-compatible chat-completions endpoint** — Ollama, LM Studio, llama.cpp, vLLM, OpenRouter, OpenAI, and Anthropic-via-proxy. Pick where you want your bytes to go.

### Local model (Ollama, LM Studio, llama.cpp)

```bash
ollama pull qwen2.5-coder:14b
zift scan ./src --deep \
  --base-url http://localhost:11434/v1 \
  --model qwen2.5-coder:14b
```

No API key needed. Concurrency auto-caps to 1 for localhost endpoints — single-GPU servers serialize internally, so parallelism > 1 just adds queueing.

### Hosted model (OpenAI, OpenRouter, etc.)

```bash
export ZIFT_AGENT_API_KEY=sk-...
zift scan ./src --deep \
  --base-url https://api.openai.com/v1 \
  --model gpt-4o-mini \
  --max-cost 5.00
```

`--max-cost` enforces a USD spend ceiling using token rates supplied via `.zift.toml` (see below). With no rates configured, tracking is a no-op.

### Configuration file

Most settings can live in `.zift.toml`:

```toml
[deep]
base_url          = "http://localhost:11434/v1"
model             = "qwen2.5-coder:14b"
max_cost          = 5.00
cost_per_1k_input  = 0.0   # hosted models: e.g. 0.00015 for gpt-4o-mini input
cost_per_1k_output = 0.0   #                e.g. 0.0006  for gpt-4o-mini output
```

`api_key` is intentionally **not** readable from `.zift.toml` — keys belong in `$ZIFT_AGENT_API_KEY` or `--api-key`, not in source-controlled files.

### Subprocess transport (`--agent-cmd`)

For agents that don't speak the OpenAI HTTP dialect — `claude -p`, `aider`, or any user wrapper script — drive them through stdin/stdout:

```bash
zift scan ./src --deep --agent-cmd "claude -p --output-format json"
```

Zift writes one JSON envelope to the command's stdin and reads the deep-mode JSON response from stdout:

```jsonc
// stdin (one line, then EOF)
{"system": "...", "user": "...", "schema": { /* JSON Schema */ }}

// stdout (the deep-mode response schema)
{"findings": [{"line_start": 12, "line_end": 18, "category": "rbac", ...}]}
```

The schema is identical to the HTTP transport's response — wrappers around real LLMs forward `system`/`user` straight through.

#### `.zift.toml` for subprocess

```toml
[deep]
mode               = "subprocess"
agent_cmd          = "claude -p --output-format json"
agent_timeout_secs = 600     # generous; LLM CLIs can be slow (default)
```

#### Example wrappers

```bash
# Claude Code CLI in print mode — already emits structured JSON.
zift scan . --deep --agent-cmd "claude -p --output-format json"

# Custom shell script — read envelope from stdin, call your favorite agent,
# emit `{"findings": [...]}` on stdout.
zift scan . --deep --agent-cmd "./scripts/zift-agent.sh"

# Pipeline with jq for response massaging.
zift scan . --deep --agent-cmd "my-agent | jq -c '{findings: .results}'"
```

#### Caveats

- **No token tracking.** Subprocess agents don't return token counts in any standard way; `--max-cost` has no effect. Enforce ceilings externally (timeouts, ulimits, wrapper scripts).
- **No retry.** Each candidate gets one subprocess invocation. Nonzero exit, bad JSON, or timeout → skip the candidate, keep going.
- **Unix-only for v0.1.4.** Windows users: use the HTTP transport or wrap the agent in a WSL command.
- **Security note.** `agent_cmd` is run through your platform shell. Don't run Zift against an untrusted `.zift.toml` — same threat model as `.editorconfig`-style attacks.

## MCP server (`zift mcp`)

If you already use an agent host — Claude Code, Cursor, Continue, Cline, Zed, or anything else that speaks the [Model Context Protocol](https://modelcontextprotocol.io) — Zift can plug in as a tool provider over stdio:

```bash
zift mcp --scan-root .
```

Your agent host calls Zift's tools; *its* model produces the analysis. Zift never hosts an LLM client this way — you keep your existing model relationship and Zift contributes the authz expertise (rule library, prompt, Rego validation today).

### Tools exposed

| Tool | Purpose |
|---|---|
| `scan_authz` | Run a structural scan; return findings + enforcement-point count |
| `get_finding_context` | Expand a finding's surrounding code window |
| `list_rules` | Enumerate the rule library (filter by language / category) |
| `get_rule` | Fetch a rule's full definition (tree-sitter query, predicates, Rego template) |
| `suggest_rego` | Render a Rego stub for a finding (template-driven or category default) |
| `validate_rego` | Parse a Rego policy with the embedded `regorus` engine |
| `analyze_snippet` | Render the deep-scan prompt + JSON Schema *without* calling any model — the agent host's model produces the response |

### Resources exposed

| URI | Content |
|---|---|
| `prompt://system` | The system prompt sent on every deep-scan request |
| `prompt://schema` | The JSON Schema deep-scan responses must validate against |
| `category://<auth_category>` | Definition + canonical examples per category |
| `rule://<rule_id>` | One rule's full definition |

### Example agent host configs

#### Claude Code

```jsonc
// ~/.config/claude-code/mcp.json (or wherever your host stores MCP configs)
{
  "mcpServers": {
    "zift": {
      "command": "zift",
      "args": ["mcp", "--scan-root", "/path/to/your/repo"]
    }
  }
}
```

#### Cursor / Continue / Cline / Zed

These hosts ship their own MCP config UI. Point them at the `zift` binary with `mcp` and `--scan-root <repo>` as arguments; the protocol is identical.

#### Manual smoke-test from the shell

```bash
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}' | zift mcp
```

You should see a single line back with `serverInfo.name == "zift"` and capability flags for tools/resources.
Then call `tools/list` to see the seven tool descriptors.

## Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for
build instructions, the Conventional Commits / DCO sign-off conventions, and
our PR expectations. By participating you agree to our
[Code of Conduct](CODE_OF_CONDUCT.md).

For questions and ideas, start a
[Discussion](https://github.com/EnforceAuth/zift/discussions). For
vulnerabilities, see [SECURITY.md](SECURITY.md).

## License

Licensed under the [Apache License, Version 2.0](LICENSE). See [NOTICE](NOTICE)
for attribution requirements.
