# zift

Sift through your codebase for embedded authorization logic. Extract it into Rego for [OPA](https://www.openpolicyagent.org/).

> **Status:** v0.1 — structural scanning ready for TypeScript, JavaScript, and Java. `--deep` (LLM-assisted) mode functional via any OpenAI-compatible endpoint.

## What is zift?

Most applications embed authorization decisions directly in application code: role checks in `if` statements, permission guards in middleware, business rules that act as access control. This scattered auth logic is hard to audit, hard to test, and impossible to enforce consistently.

**zift** scans your codebase, finds these embedded authorization patterns, and helps you externalize them into Rego policies that OPA can enforce centrally.

## How it works

```bash
zift .                          # structural scan of current directory (fast, free)
zift scan ./src --deep ...      # also run LLM-assisted semantic analysis
zift extract ./findings.json    # generate Rego from scan findings
zift report .                   # detailed findings report
```

### Two-pass architecture

1. **Structural scan** (tree-sitter) — fast, deterministic, zero-cost. Finds known authorization patterns: role checks, permission guards, auth middleware, security annotations.

2. **Semantic scan** (`--deep`, opt-in) — sends candidate code regions to an LLM that classifies authorization logic the structural pass missed or misjudged. Useful for business rules that implicitly encode access control, and for languages where structural support hasn't shipped yet (Python, Go, etc.).

## Deep mode (`--deep`)

`--deep` talks to **any OpenAI-compatible chat-completions endpoint** — one client speaks to Ollama, LM Studio, llama.cpp, vLLM, OpenRouter, OpenAI, and Anthropic-via-proxy. Pick where you want your bytes to go.

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

## Supported languages

| Language | Structural | Deep (cold-region) | Framework hints (deep) |
|----------|-----------|---------------------|------------------------|
| TypeScript / JavaScript | yes (v0.1) | yes (v0.1) | Express, NestJS, Next.js |
| Java | yes (v0.1) | yes (v0.1) | Spring Security, Jakarta Security |
| Python | planned (v0.2) | yes (v0.1) | Django, Flask, FastAPI |
| Go | planned (v0.2) | yes (v0.1) | Gin, Echo |
| C# | planned (v0.3) | yes (v0.1) | ASP.NET Core |
| Kotlin | planned (v0.3) | yes (v0.1) | Spring (Kotlin) |
| Ruby | planned (v0.3) | yes (v0.1) | Rails |
| PHP | planned (v0.3) | yes (v0.1) | Laravel |

Deep mode walks the full source tree by extension and detects auth-y function names with regex — so it produces useful results in any language well before structural support lands.

## Installation

### Cargo

```bash
cargo install --git https://github.com/EnforceAuth/zift
```

### Binary download

Prebuilt binaries for Linux (x86_64), macOS (x86_64 and arm64), and Windows (x86_64) are available from [Releases](https://github.com/EnforceAuth/zift/releases).

## License

Apache-2.0
