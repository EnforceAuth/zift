# PR 2 — Tier 1 deep scan: MCP server

Companion to [00-deep-mode-overview.md](../todo/00-deep-mode-overview.md). Builds on the primitives shipped in [PR 1](./01-pr1-deep-http-transport.md). This is the strategically headline transport — it inverts the model relationship so Zift never hosts an LLM client; the user's existing agent host (Claude Code, Cursor, Continue, Cline, Zed, etc.) calls Zift as an MCP tool provider.

**Status**: shipped (see "Shipped" at the bottom of this file).

## 1. Goal & scope

Add `zift mcp` subcommand that runs Zift as an MCP server over stdio. The agent host connects, calls our tools, and gets back structured authz findings + ground-truth Rego validation. The agent host owns the model; we own the authz expertise.

Out of scope: HTTP-transport MCP (stdio is the universal default), authentication, multi-client.

## 2. Subcommand

```bash
zift mcp [--rules-dir DIR] [--scan-root DIR]
```

Speaks JSON-RPC 2.0 over stdio per the MCP spec. `--scan-root` defaults to cwd; `--rules-dir` follows existing precedence.

## 3. Tools exposed

| Tool | Purpose | Reuses |
|---|---|---|
| `scan_authz` | Run structural scan on a path; return findings JSON | `scanner::scan` |
| `get_finding_context` | Expand a finding's snippet (lines before/after, or smart enclosing function) | `deep::context::expand_finding` |
| `list_rules` | Enumerate the rule library (id, language, category, confidence, description) | `rules::loader` |
| `get_rule` | Fetch one rule's full definition incl. tree-sitter query and Rego template | `rules::loader` |
| `suggest_rego` | Render a rule's Rego template against a finding's captures | existing rendering |
| `validate_rego` | Run OPA against a Rego policy; return parse errors / test results | `rego::validate` (may need shelling out to `opa` or embedding `regorus`) |
| `analyze_snippet` | Given a snippet + language + optional seed, return the rendered prompt + schema. Does NOT call any model. | `deep::prompt::render`, `deep::prompt::output_schema` |

`analyze_snippet` is the key trick: the MCP server returns the prompt and schema; the agent host's model produces the response; the host can call `submit_analysis` (next tool, optional) to register the result. Or it just keeps the result locally — Zift doesn't have to track it.

## 4. Resources exposed

| Resource | URI | Content |
|---|---|---|
| `rule://<rule_id>` | per-rule | Full TOML rule + human-readable docs |
| `category://<auth_category>` | per category | One-paragraph definition + canonical examples |
| `prompt://system` | singleton | The `SYSTEM_PROMPT` constant from `deep::prompt` |
| `prompt://schema` | singleton | The `output_schema()` JSON Schema |

This is how the MCP-attached agent learns *how* to think about authz — by reading the resources we already wrote for PR 1.

## 5. Crate dependencies

Use the official Rust MCP SDK if it exists; otherwise hand-roll JSON-RPC 2.0 over stdio (small, well-spec'd protocol). As of this writing the canonical SDK is `rmcp` (modelcontextprotocol/rust-sdk). Verify currency at PR start.

```toml
[dependencies]
rmcp = "..."  # or whatever the official Rust SDK is at PR-start time
```

If no maintained SDK exists, the alternative is roughly 300 lines of stdio + serde + JSON-RPC framing.

## 6. Architectural reuse

PR 2 should not implement *any* prompt logic, *any* candidate selection, *any* output schema. Those are imported verbatim from `crate::deep::prompt` and `crate::deep::candidate`.

```rust
use crate::deep::prompt::{SYSTEM_PROMPT, output_schema, render};
use crate::deep::context::expand_finding;
use crate::deep::candidate::select_candidates;
```

The MCP server is a transport, period.

## 7. Open questions (resolve before kickoff)

1. **Rust MCP SDK maturity.** If `rmcp` is still 0.x with breaking changes per release, we may want to pin or vendor.
2. **Streaming.** MCP supports streaming responses. Worth using for long scans? Probably yes for `scan_authz` on large repos. Confirm SDK supports it.
3. **`validate_rego` implementation.** Shell out to `opa` binary (requires user to have it installed) vs embed `regorus` (Rust-native OPA-compatible evaluator). Lean toward `regorus` for zero-install UX. Verify rule coverage parity.
4. **Multi-tenancy.** MCP servers are typically single-client; do we need to handle concurrent calls? Stdio means one client at a time, so no — keep it single-threaded internally.
5. **Logging.** stdio is the wire; logs must go to stderr only. Audit existing `eprintln!` / log calls in `scanner::*` to ensure none accidentally write to stdout.

## 8. Test plan (sketch)

- Unit-test each tool handler against a fake JSON-RPC framer.
- Integration test: spawn `zift mcp` as subprocess, send canned `tools/list`, `tools/call` messages, assert responses.
- One smoke test that loads `prompt://system` and `prompt://schema` and asserts they match the constants in `crate::deep::prompt`.

## 9. Commit sequence (rough)

1. `feat(mcp): add zift mcp subcommand stub` — CLI wiring, prints "MCP server starting" and exits.
2. `feat(mcp): JSON-RPC 2.0 stdio framing` — protocol layer, no tools yet.
3. `feat(mcp): expose rule library as tools and resources` — `scan_authz`, `list_rules`, `get_rule`, `rule://*`, `category://*`.
4. `feat(mcp): expose deep-mode primitives as tools` — `get_finding_context`, `analyze_snippet`, `prompt://system`, `prompt://schema`.
5. `feat(mcp): expose Rego suggestion and validation` — `suggest_rego`, `validate_rego`.
6. `docs(mcp): example agent host configs` — Claude Code, Cursor, Continue snippets in README or docs/.

## 10. Decision deferred from PR 1

If during PR 1 we find the prompt library / candidate selection abstractions need a different shape to also serve the MCP path, fix them in PR 1 before merging — don't ship a shape we'll break in PR 2.

## Shipped

Implemented as a single PR. Decisions taken during implementation:

- **Hand-rolled JSON-RPC 2.0 over stdio** instead of `rmcp`. The codebase is fully blocking (`reqwest::blocking`, `regorus::Engine`); pulling in `rmcp` would have forced tokio/async fragmentation. Hand-roll is ~250 lines of `serde` + line-delimited framing in `src/mcp/jsonrpc.rs`.
- **Protocol version pinned to `2024-11-05`** (not the floating "current" date). Agent hosts negotiate via `initialize`; we want predictable behavior across releases.
- **`validate_rego` uses embedded `regorus`** — the dependency was already present for the structural pass's template validation, so zero-install UX was free.
- **Streaming responses deferred.** Single-client stdio + the largest tool result (full `scan_authz`) fits comfortably in a single response in practice. Revisit if multi-thousand-finding scans become a real workload.
- **`prompt://system` and `prompt://schema` round-trip the canonical `crate::deep::prompt` constants verbatim.** Asserted in the integration test — drift between the deep-scan path and the MCP path becomes a test failure, not a silent inconsistency.
- **Path containment**: every tool that resolves a relative path canonicalizes against `--scan-root` and rejects paths whose canonical form lands outside it. Same defense the deep-scan `expand_finding` already uses.

Tooling shipped (7 tools): `scan_authz`, `get_finding_context`, `list_rules`, `get_rule`, `suggest_rego`, `validate_rego`, `analyze_snippet`.

Resources shipped (4 kinds): `prompt://system`, `prompt://schema`, `category://<slug>` × 7 categories, `rule://<id>` × every loaded rule.

Tests:

- 35 unit tests under `src/mcp/*` (jsonrpc framing, server dispatch, every tool, every resource).
- 6 stdio integration tests in `tests/mcp_stdio_integration.rs` that spawn `zift mcp` as a subprocess and drive the protocol over real pipes — catches the class of regressions in-process tests can't (e.g. an accidental `println!` to stdout from anywhere on the call path).
