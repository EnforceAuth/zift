# PR 1 — Tier 2 deep scan: OpenAI-compatible HTTP transport

Companion to [00-deep-mode-overview.md](./00-deep-mode-overview.md). This PR makes `--deep` functional end-to-end and lays down the shared primitives that PR 2 and PR 3 reuse.

## 1. Goal & scope

End-to-end working `--deep` flag using a single HTTP client that speaks the OpenAI `/v1/chat/completions` shape. After this PR:

```bash
zift scan ./repo --deep \
  --base-url http://localhost:11434/v1 \
  --model qwen2.5-coder:14b \
  --api-key sk-...
```

…produces additional `Finding`s with `pass: ScanPass::Semantic` merged into the report alongside structural findings.

**Out of scope**: MCP server, subprocess hook, per-provider auth quirks. We accept a `base_url` and let the user point us at whatever proxies that translate to OpenAI shape.

## 2. Module layout

All new code lives under `src/deep/`.

### `src/deep/mod.rs` — orchestrator

```rust
pub use config::DeepRuntime;          // resolved CLI+config bundle
pub use error::DeepError;
pub use finding::SemanticFinding;     // pre-merge LLM output
pub mod candidate;
pub mod client;
pub mod config;
pub mod context;
pub mod cost;
pub mod error;
pub mod finding;
pub mod merge;
pub mod prompt;

pub fn run(
    structural: &[Finding],
    scan_root: &Path,
    runtime: &DeepRuntime,
) -> Result<Vec<Finding>, DeepError>;
```

`run` is the single entry point called from `commands/scan.rs`. Synchronous (see §4). Returns `Vec<Finding>` with `pass: Semantic` already set. Merging into the master vec happens in the caller.

### `src/deep/config.rs` — runtime config

```rust
pub struct DeepRuntime {
    pub base_url: String,                  // e.g. "http://localhost:11434/v1"
    pub model: String,
    pub api_key: Option<String>,           // some local servers accept any string or none
    pub max_cost_usd: Option<f64>,
    pub cost_per_1k_input: Option<f64>,    // user-supplied; None = no cost tracking
    pub cost_per_1k_output: Option<f64>,
    pub request_timeout_secs: u64,         // default 120
    pub max_candidates: usize,             // default 50
    pub max_concurrent: usize,             // default 4
    pub temperature: f32,                  // default 0.0
    pub max_prompt_chars: usize,           // default 16000, hard truncates expanded snippet
}

pub fn build(args: &ScanArgs, config: &ZiftConfig) -> Result<DeepRuntime, DeepError>;
```

Resolution precedence:

- `base_url`, `model`, `max_cost`: CLI flag > `[deep]` config > built-in default.
- `api_key`: CLI flag (`--api-key`) > env var (`ZIFT_AGENT_API_KEY`) > unset. **Intentionally NOT readable from `.zift.toml`** — keys belong in env vars or CLI to avoid accidental secret commits.

Validation: empty `base_url` is hard error; missing `model` is hard error; missing `api_key` is a warning (not an error — Ollama/llama.cpp accept any value).

### `src/deep/error.rs`

```rust
#[derive(thiserror::Error, Debug)]
pub enum DeepError {
    #[error("missing config: {0}")]                Config(String),
    #[error("HTTP error: {0}")]                    Http(#[from] reqwest::Error),
    #[error("model returned malformed JSON: {0}")] BadResponse(String),
    #[error("cost ceiling reached after ${spent:.4} USD")] CostExceeded { spent: f64 },
    #[error("request timed out after {secs}s")]    Timeout { secs: u64 },
    #[error("io error: {0}")]                      Io(#[from] std::io::Error),
}
```

`DeepError` converts into `ZiftError::General` at the call site so the rest of the binary stays unchanged.

### `src/deep/candidate.rs` — what to send

```rust
pub struct Candidate {
    pub kind: CandidateKind,                   // Escalation | ColdRegion
    pub file: PathBuf,
    pub language: Language,
    pub line_start: usize,                     // 1-based, inclusive
    pub line_end: usize,
    pub source_snippet: String,                // already-expanded context
    pub original_finding_id: Option<String>,   // present iff Escalation
    pub seed_category: Option<AuthCategory>,   // hint for prompt selection
}

pub enum CandidateKind { Escalation, ColdRegion }

pub fn select_candidates(
    structural: &[Finding],
    scan_root: &Path,
    runtime: &DeepRuntime,
) -> Result<Vec<Candidate>, DeepError>;
```

See §6 for heuristics.

### `src/deep/context.rs` — code expansion

```rust
pub fn expand_finding(
    finding: &Finding,
    scan_root: &Path,
) -> Result<ExpandedContext, DeepError>;

pub fn expand_region(
    file: &Path,
    language: Language,
    line_start: usize,
    line_end: usize,
) -> Result<ExpandedContext, DeepError>;

pub struct ExpandedContext {
    pub file_relative: PathBuf,
    pub language: Language,
    pub line_start: usize,    // adjusted to enclosing function start
    pub line_end: usize,
    pub snippet: String,      // function body + imports
    pub imports: Vec<String>, // top of file, top 20 lines verbatim
}
```

Strategy in §7.

### `src/deep/prompt.rs` — prompt + JSON schema

```rust
pub struct PromptInputs<'a> {
    pub candidate: &'a Candidate,
    pub structural_finding: Option<&'a Finding>,
}

pub struct RenderedPrompt {
    pub system: String,
    pub user: String,
    pub schema: serde_json::Value,    // for OpenAI structured-outputs
}

pub fn render(inputs: &PromptInputs) -> RenderedPrompt;

pub fn output_schema() -> serde_json::Value;       // exported; PR 2/PR 3 reuse
pub const SYSTEM_PROMPT: &str = "...";              // exported; PR 2/PR 3 reuse
```

Schema in §5; sketch in §6.

### `src/deep/client.rs` — HTTP transport

```rust
pub struct OpenAiCompatibleClient {
    http: reqwest::blocking::Client,
    base_url: String,
    api_key: Option<String>,
    model: String,
    temperature: f32,
}

impl OpenAiCompatibleClient {
    pub fn new(runtime: &DeepRuntime) -> Result<Self, DeepError>;
    pub fn analyze(&self, prompt: &RenderedPrompt) -> Result<AnalyzeResponse, DeepError>;
}

pub struct AnalyzeResponse {
    pub findings: Vec<SemanticFinding>,
    pub usage: TokenUsage,
}

pub struct TokenUsage {
    pub input_tokens: u32,
    pub output_tokens: u32,
}
```

Implementation: POST `{base_url}/chat/completions` with body containing `model`, `messages: [system, user]`, `response_format: { type: "json_schema", json_schema: { name: "zift_findings", strict: true, schema: ... } }`, `temperature`. Some local servers ignore `response_format` — we still parse `choices[0].message.content` as JSON. If that fails, retry once with a degraded prompt that says "respond with ONLY a JSON object matching this schema" and no `response_format` field.

### `src/deep/finding.rs` — semantic-side type

```rust
#[derive(Deserialize, Debug, Clone)]
pub struct SemanticFinding {
    pub line_start: usize,
    pub line_end: usize,
    pub category: AuthCategory,
    pub confidence: Confidence,
    pub description: String,
    pub reasoning: String,
    pub is_false_positive: bool,           // for escalations: model judges seed
}

pub fn into_finding(
    sem: SemanticFinding,
    candidate: &Candidate,
    seed: Option<&Finding>,
) -> Finding;
```

`into_finding` translates to the canonical `Finding`, computing the deterministic id via the existing hash. Need to expose `compute_finding_id` from `scanner/matcher.rs` as `pub(crate)` — clean refactor in commit 2.

### `src/deep/merge.rs` — dedup + integrate

```rust
pub fn merge(structural: Vec<Finding>, semantic: Vec<Finding>) -> Vec<Finding>;
```

Rules: a semantic finding overlapping a structural finding's range (same file, range overlap >= 50%) replaces the structural one only if the semantic finding has equal or higher confidence; otherwise both kept. False-positive flags from `SemanticFinding::is_false_positive` cause the structural counterpart to be dropped entirely.

### `src/deep/cost.rs` — token-based ceiling

```rust
pub struct CostTracker {
    spent_micro_usd: AtomicU64,    // millionths of a dollar; avoid float atomics
    cap_usd: Option<f64>,
    in_rate: Option<f64>,
    out_rate: Option<f64>,
}

impl CostTracker {
    pub fn new(runtime: &DeepRuntime) -> Self;
    pub fn record(&self, usage: &TokenUsage) -> Result<(), DeepError>;
    pub fn spent_usd(&self) -> f64;
}
```

After every response, orchestrator calls `record`. If new total exceeds cap, return `CostExceeded` and stop dispatching further candidates (in-flight ones complete naturally).

## 3. Cargo.toml additions

```toml
[dependencies]
reqwest = { version = "0.12", default-features = false, features = ["blocking", "json", "rustls-tls"] }

[dev-dependencies]
mockito = "1"
```

`rustls-tls` over `native-tls` to keep the build hermetic (no OpenSSL on contributor machines). `serde_json` and `thiserror` already present. `mockito` is sync — no tokio leak into the test harness.

## 4. Async strategy: blocking

**Recommendation: blocking.** Reasons:

- Today's `scan` pipeline is sync end-to-end. `commands::scan::execute → scanner::scan` is sync.
- Going async means making `main` async (forces a tokio runtime) or `block_on`-ing inside `scan::execute`. Either way, async colors `run`, `client::analyze`, every helper.
- Concurrency for HTTP fan-out is achievable with `std::thread::scope` over `reqwest::blocking::Client` (clone-cheap). Cap parallelism at `runtime.max_concurrent` (default 4).
- If we later need streaming for MCP (PR 2) we can add an async path then; the prompt/schema/candidate primitives don't change.

Single shared `reqwest::blocking::Client` on `OpenAiCompatibleClient` — avoids per-request runtime spinup.

## 5. Structured output JSON schema

This is the contract PR 2 and PR 3 must also bind to.

```json
{
  "type": "object",
  "properties": {
    "findings": {
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "line_start":        { "type": "integer", "minimum": 1 },
          "line_end":          { "type": "integer", "minimum": 1 },
          "category":          { "type": "string",
                                 "enum": ["rbac", "abac", "middleware",
                                          "business_rule", "ownership",
                                          "feature_gate", "custom"] },
          "confidence":        { "type": "string", "enum": ["low", "medium", "high"] },
          "description":       { "type": "string", "maxLength": 280 },
          "reasoning":         { "type": "string", "maxLength": 800 },
          "is_false_positive": { "type": "boolean" }
        },
        "required": ["line_start", "line_end", "category", "confidence",
                     "description", "reasoning", "is_false_positive"],
        "additionalProperties": false
      }
    }
  },
  "required": ["findings"],
  "additionalProperties": false
}
```

Snake_case enums match `#[serde(rename_all = "snake_case")]` on `AuthCategory`.

## 6. System prompt sketch

`SYSTEM_PROMPT` (single concatenated string):

1. Role: "You are an expert in application authorization patterns. You analyze source code snippets to identify embedded authorization logic."
2. Definition of authorization: role checks, attribute checks, ownership, feature gates, middleware, business logic that gates access.
3. Anti-examples: input validation, generic null/empty checks, rate limits not user-conditioned, retry/idempotency logic.
4. The seven `AuthCategory` values with one-sentence definitions each.
5. Confidence calibration: "high = unambiguous auth check; medium = likely auth with reasonable alternate interpretation; low = could be auth, depends on unseen context."
6. Output contract: "You MUST return a JSON object matching this schema. No prose. No markdown fences. If the snippet contains no authorization logic, return `{\"findings\": []}`."

Per-call user prompt (rendered by `prompt::render`):

- Header: file relative path, language, line range.
- Optional seed: "A structural rule flagged this region as <category, confidence>. Confirm or reject."
- The expanded snippet, fenced.
- "Identify all authorization decisions in the snippet above. Use line numbers from the snippet."

Keep it short — small local models struggle with long prompts.

### Candidate selection rules

`select_candidates` returns up to `runtime.max_candidates` (default 50), in priority order:

**Escalations** (push):
- Every structural finding with `confidence: Low`. Goal: classify or reject.
- Every structural finding with `confidence: Medium` and `category: BusinessRule | Custom | Ownership`. These are the noisy categories.
- Skip `confidence: High` — already trusted; sending them just costs money.

**Cold regions** (pull):
- Walk all source files in the scan root via an extension-based discovery that maps to the full `Language` enum, **not** just structurally-supported languages. (`discovery::discover_files` today is restricted to TS/JS/Java; we either extend it or add a `discover_files_for_deep` variant that covers Python, Go, C#, Kotlin, Ruby, PHP file extensions too.)
- Regex-match function/method names: `(?i)(authori[sz]e|authenticate|require|ensure|guard|protect|allow|deny|check|can|may|isAdmin|hasRole|hasPermission)` plus a per-language function-keyword anchor where known (`function`, `def`, `func`, `fun`, `public`, `private`, `fn`, `=> {`). Languages we don't have a function-keyword for fall back to auth-name-only matching — slightly noisier but still useful.
- Each match becomes one `ColdRegion` candidate. Cap cold regions at 30% of `max_candidates` so escalations get priority.
- De-duplicate cold regions against escalation file/line ranges.

**Why ungated across all languages**: structural support is at v0.1 (TS/JS/Java); Python/Go are v0.2 roadmap, C#/Kotlin/Ruby/PHP are v0.3. Cold-region scanning is regex-based and grammar-free, so the semantic pass becomes a way to ship *useful* coverage of v0.2/v0.3 languages **before** their structural grammars land. Early adopters running `--deep` against a Python or Go codebase get value today.

Determinism: candidates sorted by `(file, line_start)` so reruns produce identical input ordering, keeping test expectations stable.

## 7. Context expansion strategy

Two-tier:

**Fast path (default)**: line-window expansion. Read the file, take lines `[max(1, start-5), min(eof, end+15)]`. Cheap, no parsing. Plus the first 20 lines of the file as `imports` (verbatim — model parses).

**Smart path** (used when fast-path snippet is < 8 lines after window): re-parse with tree-sitter (`parser::parse_source` already exists); walk up from the original node to the nearest `function_declaration | method_definition | arrow_function | function_expression | class_declaration`; expand to that node's range. Cap at 200 lines to bound prompt size.

**Smart-path only available for languages with an integrated tree-sitter grammar** — today TS/JS/Java. Python/Go/etc. fall through to the line-window fast path until their grammars land in v0.2/v0.3. This is fine: the model can usually figure out function boundaries from a generous line window, especially with the file header (imports) included.

Truncate the final snippet at `runtime.max_prompt_chars` (default 16000) to prevent foot-guns on huge functions.

## 8. Test plan

### Unit tests

| Module | Tests |
|---|---|
| `config.rs` | precedence (CLI > env > toml); empty base_url errors; partial config accepted |
| `candidate.rs` | high-conf skipped; low-conf escalated; cold regex matches `requireAuth`/`isAdmin` but not `authorRefactor`; max_candidates honored; deterministic ordering |
| `context.rs` | line-window math at file boundaries; tree-sitter expansion finds enclosing function in TS; imports extracted |
| `prompt.rs` | rendered prompt valid UTF-8 and < 8KB for typical input; schema is valid JSON Schema (round-trip via serde_json) |
| `client.rs` | success path; malformed JSON path (missing `findings`); HTTP 500; HTTP 401; request body shape (assert via serde_json::Value comparison) |
| `cost.rs` | cap not exceeded; cap exceeded triggers error; `None` rates → no tracking |
| `merge.rs` | overlapping ranges replace by confidence; false-positive drops seed; non-overlapping kept |

### Integration test: `tests/deep_http_integration.rs`

Uses `mockito` (sync). Three tests:

1. **Happy path**: spin up `mockito::Server`; mock `POST /chat/completions` to return canned OpenAI-shaped response with one semantic finding; build a `DeepRuntime` pointing at `server.url()`; synthesize a structural `Finding` with `confidence: Low`; call `deep::run`; assert returned vec has 1 entry with `pass: ScanPass::Semantic` and right `line_start`.

2. **Malformed JSON**: mock returns `{"choices":[{"message":{"content":"not json"}}]}` — assert `DeepError::BadResponse`.

3. **Cost cap**: mock returns `usage: {prompt_tokens: 10000, completion_tokens: 5000}`; set `max_cost_usd: 0.01` and rates that exceed; expect `CostExceeded`.

### Existing test impact

CLI test for `--provider` no longer applies; replace with `--base-url`. Existing scan tests don't set `--deep` so they should be no-ops; verify.

## 9. Error handling

| Failure | Behavior |
|---|---|
| Malformed JSON from model | One retry with degraded prompt; if still bad, log warning + drop candidate, continue |
| HTTP timeout | Configurable per-request timeout (default 120s); on timeout, log + drop candidate |
| API key missing | Warn at startup if base_url is non-localhost; allow it (local servers don't need keys) |
| Cost ceiling hit mid-run | Stop dispatching new candidates; finalize in-flight; warn with spent total; return findings collected so far |
| HTTP 401/403 | Hard fail with clear "auth rejected by {base_url}" message |
| HTTP 5xx | Exponential backoff (3 attempts at 1s, 4s, 16s) then drop |
| `--deep` without `--model` | Hard fail at config-build time |
| `--deep` without `--base-url` | Hard fail at config-build time (no default — user intent matters) |

Drop-and-continue is the right policy: structural findings still ship; semantic is best-effort enrichment.

## 10. Cost tracking

User-supplied per-1k-token rates. Two new `[deep]` fields:

```toml
[deep]
base_url = "http://localhost:11434/v1"
model = "qwen2.5-coder:14b"
max_cost = 5.00
cost_per_1k_input = 0.0      # local model = free
cost_per_1k_output = 0.0
```

Logic in `cost::record`:

```
delta = (in_tokens / 1000.0) * in_rate + (out_tokens / 1000.0) * out_rate
spent += delta
if cap.is_some_and(|c| spent > c): Err(CostExceeded { spent })
```

If both rates are `None`, skip tracking (spent = 0, never errors). Token counts come from response `usage`; if a server omits usage, log debug and treat `delta = 0`.

CLI `--max-cost` wins over toml; CLI flags for the rates intentionally not added — they belong in the config file.

## 11. Commit sequence

Six commits, each compiling and passing tests:

1. **`refactor(cli): drop closed LlmProvider enum, add --base-url, rename env var`** — `cli.rs`, `config.rs`, `commands/init.rs`, `docs/DESIGN.md`, CLI tests. Renames `ZIFT_API_KEY` → `ZIFT_AGENT_API_KEY`; `api_key` removed from config-file schema. Stub-only deep scan still prints the warning.
2. **`feat(deep): add deep module skeleton with config + error types`** — empty modules with type definitions; `deep::run` returns `Ok(vec![])`; wired into `commands/scan.rs`; tests for `config::build`. Expose `compute_finding_id` from scanner.
3. **`feat(deep): candidate selection and context expansion`** — `candidate.rs`, `context.rs` with tests. `deep::run` produces candidates but returns empty findings.
4. **`feat(deep): prompt rendering and JSON schema`** — `prompt.rs`, `finding.rs`. `output_schema()` and `SYSTEM_PROMPT` exported. Tests for prompt validity.
5. **`feat(deep): OpenAI-compatible HTTP client`** — `client.rs` + reqwest dep + cost tracker. Unit tests with no network. Integration test in `tests/` with mockito (mocked happy path + bad-JSON + cost-cap).
6. **`feat(deep): merge semantic findings into scan output`** — `merge.rs`; wire end-to-end in `commands/scan.rs`; update existing scan tests to assert `pass`; end-to-end test with mockito producing a real `ScanPass::Semantic` finding.

Each commit ~150-400 lines of diff, reviewable independently. PR title for the merge: `feat: implement --deep with OpenAI-compatible HTTP transport`.

## 12. Decisions & open issues

### Locked decisions

1. **Cold-region scanning is ungated across languages.** Runs on every language in the `Language` enum, including ones without a tree-sitter grammar. Rationale in §6. Implementation note: `discovery::discover_files` today only emits TS/JS/Java extensions; deep mode either extends it or adds a `discover_files_for_deep` that covers all `Language` extensions.
2. **No `OPENAI_API_KEY` fallback.** Only `ZIFT_AGENT_API_KEY` is honored from the environment. Explicit > implicit; Zift is not OpenAI.
3. **Localhost concurrency auto-cap.** When `base_url` host is `localhost` or `127.0.0.1` (or `::1`), `max_concurrent` defaults to 1. Local single-GPU servers serialize internally; parallelism > 1 just adds queueing. User can override via explicit `[deep] max_concurrent = N`.

### Open issues

1. **`response_format` not universally supported.** Ollama 0.5+, llama.cpp partial. Plan: send it; on parse failure, retry without it. Follow-up issue: capability detection at startup vs per-call.
2. **Determinism in CI.** With `temperature: 0.0` and a mock server, integration tests are deterministic. Real-LLM tests are not — don't add any.
3. **`compute_finding_id` location.** Currently private in `scanner/matcher.rs`. Need to expose at `crate::types::compute_finding_id` or similar. Small refactor in commit 2.

## 13. Critical files

- `/Users/brad/dev/zift/src/cli.rs`
- `/Users/brad/dev/zift/src/config.rs`
- `/Users/brad/dev/zift/src/commands/scan.rs`
- `/Users/brad/dev/zift/src/commands/init.rs`
- `/Users/brad/dev/zift/src/types.rs`
- `/Users/brad/dev/zift/src/scanner/matcher.rs` (expose finding_id)
- `/Users/brad/dev/zift/Cargo.toml`

---

## 14. Shipped

**Branch**: `feat/deep-http`
**Test count**: 199 passing (186 lib unit + 13 integration); clippy clean with `-D warnings`.

### Commits (in order)

| Commit | Title |
|---|---|
| `10f2643` | docs: add plans/ tree with PR 1-3 plan for --deep |
| `5743690` | docs(plans): lock three decisions for PR 1 deep-mode design |
| `e29eb42` | refactor(cli): replace closed LlmProvider enum with --base-url |
| `08ad940` | feat(deep): add deep module skeleton with config + error types |
| `4a1a110` | feat(deep): candidate selection and context expansion |
| `0b0ecef` | feat(deep): prompt rendering and JSON schema |
| `fd2683a` | feat(deep): OpenAI-compatible HTTP client + cost tracker |
| `c9a5004` | feat(deep): wire orchestrator end-to-end and merge semantic findings |

The plan called for 6 implementation commits; we shipped 6, plus 2 doc commits up front and 1 commit to move this plan to `done/`.

### Plan deviations (all flagged in commit messages)

1. **`api_key` excluded from `.zift.toml`.** Originally §2 said precedence was CLI > env > config; security review during commit 1 dropped the config-file step — keys belong in env or CLI, not source-controlled files. Plan §2 was updated in commit 1.
2. **CLI flag rename**: `ZIFT_API_KEY` → `ZIFT_AGENT_API_KEY` (commit 1). Decided mid-implementation; namespaced + semantic.
3. **`Candidate.imports` field added.** §2 didn't specify it; needed by `prompt::render` for per-call framework detection. Populated from `ExpandedContext.imports` in `select_candidates`.
4. **Smart-path tree-sitter expansion deferred.** Plan §7 specced both fast-path and smart-path for commit 3; only fast-path shipped. The line-window with imports is sufficient for the model to figure out function boundaries on the languages we support, and adding tree-sitter walking can land later if measurement says it matters. Smart-path comments preserved as TODOs in `src/deep/context.rs`.
5. **Concurrency is sequential, not fan-out.** Plan §4 mentioned `std::thread::scope` over `reqwest::blocking::Client` to honor `runtime.max_concurrent`. Commit 6 ships sequential dispatch with a TODO in `src/deep/mod.rs::run`. Local servers (localhost auto-capped to 1) wouldn't benefit anyway, and remote endpoints can have this added later without API changes.
6. **`src/lib.rs` split added in commit 5.** Required to let `tests/deep_http_integration.rs` reach internal modules. `src/main.rs` is now a thin shim. Future-proofs PR 2 (the MCP server can depend on `zift` as a library).
7. **Markdown-fence stripping added to client.** Not in original plan; shipped after observing that some local models wrap JSON in ` ```json ` fences despite system-prompt instructions. `strip_markdown_fence` in `src/deep/client.rs`.
8. **`AUTH_NAME_REGEX` tweak**: pattern is `authori[sz]\w*` not `authori[sz]e\w*`. The plan-suggested regex would have missed "authorization" (no `e` between `z` and `ation`). Caught by tests in commit 3.

### Open follow-ups (from §12 "Open issues" + new ones)

- **Concurrency fan-out** — implement `std::thread::scope` parallelism for non-localhost backends (commit 6 TODO).
- **Smart-path tree-sitter expansion** — walk to enclosing function for TS/JS/Java findings. Useful when fast-path snippet is < 8 lines after window (commit 3 TODO in `context.rs`).
- **`response_format` capability detection at startup** — current model is "send it, retry without on parse failure"; could be one-off probe instead.
- **HTTP 5xx exponential backoff** — currently any 5xx is a hard skip; plan §9 specced 3 attempts at 1s/4s/16s. Worth adding for flaky remote endpoints.
- **`compute_finding_id` move** — currently `pub(crate)` in `scanner/matcher.rs`; cleaner home would be `types::compute_finding_id`.

### Ready for PR 2

The shared primitives are stable and exported:

- `crate::deep::prompt::SYSTEM_PROMPT`
- `crate::deep::prompt::output_schema()`
- `crate::deep::prompt::render(...)`
- `crate::deep::candidate::select_candidates(...)`
- `crate::deep::context::expand_finding(...)`, `expand_region(...)`
- `crate::deep::finding::SemanticFinding`, `into_finding(...)`
- `crate::deep::merge::merge(...)`
- `crate::deep::cost::CostTracker`

PR 2 (MCP server) can wrap these without reimplementing.
