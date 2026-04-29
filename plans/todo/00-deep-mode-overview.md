# Deep mode — design overview

Tracks the multi-PR effort to make `--deep` functional and keep Zift agent-agnostic as the LLM landscape churns.

## Goal

Make `zift scan --deep` produce semantic findings (`pass: ScanPass::Semantic`) without coupling Zift to any specific LLM provider, vendor, or local-model runner. Users must be able to plug in the agent they already use.

## Design constraints

1. **No provider treadmill.** We do not write `AnthropicClient` + `OpenAIClient` + `OllamaClient` + `GeminiClient` + …. Every quarter another provider ships; we'd spend our time chasing them.
2. **Local-first must be a real path**, not an afterthought. Running fully offline against `ollama serve` or `llama-server` should be no harder than running against a hosted API.
3. **Zift's value is rules + prompts + Rego validation**, not model plumbing. The transports are interchangeable; the authz domain knowledge is the moat.
4. **Each transport reuses the same primitives** — candidate selection, context expansion, prompt library, structured output schema, semantic-finding merge. No parallel implementations.

## The three transports

| Tier | Transport | When it's used | PR |
|------|-----------|----------------|-----|
| 1 | **MCP server** (`zift mcp`) | User has an agent host (Claude Code, Cursor, Continue, Cline, Zed). Their agent calls Zift tools; their agent calls the model. We never see the model. | [PR 2](../done/02-pr2-mcp-server.md) |
| 2 | **OpenAI-compatible HTTP** (`--base-url`) | Headless / CI runs. One client speaks to Ollama, LM Studio, llama.cpp `server`, vLLM, OpenRouter, Together, Groq, Anthropic-via-proxy, OpenAI itself. | [PR 1](../done/01-pr1-deep-http-transport.md) |
| 3 | **Subprocess hook** (`--agent-cmd`) | Anything else — `claude -p`, `aider`, custom shell scripts, agents that don't expose HTTP. Stdin: prompt + JSON. Stdout: JSON matching our schema. | [PR 3](./03-pr3-subprocess-hook.md) |

User picks explicitly via `[deep] mode = "mcp" | "http" | "subprocess"`. No provider auto-detection magic.

## Build order: inside-out

We build PR 1 first even though MCP (PR 2) is the strategically headline answer. Reason: MCP needs the prompt library, candidate selection, context expansion, and structured-output schema *anyway*. Building HTTP first forces those primitives into a clean shape; the MCP server in PR 2 is then a thin transport layer over them. The reverse order means writing the primitives for MCP, then refactoring when HTTP shows up.

```text
                               ┌─────────────────────────┐
                               │     src/deep/           │
                               │  candidate · context    │
                               │  prompt · merge · cost  │
                               │  finding · output schema│
                               └─────────────────────────┘
                                ▲          ▲          ▲
                                │          │          │
              ┌─────────────────┘          │          └─────────────────┐
              │                            │                            │
   ┌──────────────────────┐    ┌──────────────────────┐    ┌──────────────────────┐
   │  PR 1: HTTP client   │    │  PR 2: MCP server    │    │  PR 3: Subprocess    │
   │  (built first)       │    │  (thin wrapper)      │    │  (thinnest wrapper)  │
   └──────────────────────┘    └──────────────────────┘    └──────────────────────┘
```

## Shared primitives (defined in PR 1, reused by PR 2 and PR 3)

- `deep::prompt::SYSTEM_PROMPT` — the authz definition + category taxonomy + output contract.
- `deep::prompt::output_schema()` — the JSON Schema every transport's response must validate against.
- `deep::prompt::render(...)` — produces `(system, user, schema)` tuples per candidate.
- `deep::candidate::select_candidates(...)` — chooses what to escalate / cold-scan.
- `deep::context::expand_finding(...)` and `expand_region(...)` — pulls surrounding code.
- `deep::finding::SemanticFinding` and `into_finding(...)` — the deserialization target + canonical-Finding translation.
- `deep::merge::merge(...)` — dedup + integration of semantic findings into the structural set.
- `deep::cost::CostTracker` — token-based USD ceiling.

## Folder convention

- `plans/todo/` — work not yet shipped. Plans live here while in flight.
- `plans/done/` — work that has shipped. Move the file here in the same commit that ships the work, optionally appending a "Shipped" section with the merged PR link and any decisions changed during implementation.

## Cross-references

- [PR 1 — HTTP transport](../done/01-pr1-deep-http-transport.md)
- [PR 2 — MCP server](../done/02-pr2-mcp-server.md)
- [PR 3 — Subprocess hook](./03-pr3-subprocess-hook.md)
