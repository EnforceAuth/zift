# Deep mode walkthrough

A hands-on tour of `zift scan --deep` across all three transports, run
against the same TypeScript fixture so you can see what changes between
**static** and **deep**, and between Tier 1 (MCP host), Tier 2 (HTTP), and
Tier 3 (subprocess). Adapted from a fresh end-to-end shakedown — every
command, output, and design decision below comes from a real session, not a
synthesized example.

## TL;DR — pick your path

| Mode | What you get | When |
|------|--------------|------|
| `zift scan` (static) | Tree-sitter pattern matches in supported languages | Always. Fast, free, deterministic. |
| `zift scan --deep --base-url …` (Tier 2) | LLM verdicts via OpenAI-compatible HTTP. Local with Ollama/LM Studio, remote with OpenAI/OpenRouter/Anthropic-via-proxy | Headless / CI runs, anywhere you want explicit endpoint control |
| `zift mcp` (Tier 1) | An agent host you already use (Claude Code, Cursor, Continue, Cline, Zed) drives the scan as one tool among many | Interactive review, auditor workflows, anywhere you want the agent in the loop |
| `zift scan --deep --agent-cmd …` (Tier 3) | Spawn an arbitrary command per request; `{system, user, schema}` envelope over stdin, JSON over stdout | Agent CLIs that don't speak HTTP — `claude -p`, `aider`, `codex exec`, custom scripts |

Static and deep are not exclusive — deep operates *on top of* the structural
pass, and the merged finding set is what you get back.

## Setup

```bash
cargo build --release
```

### Fixture A — escalation + cold region in one file

```ts
// /tmp/zift-manual/app.ts
import { Request, Response } from 'express';

// Medium-confidence ownership (structural). Will be ESCALATED in deep mode
// because should_escalate() flags medium+ownership for re-evaluation.
export async function deletePost(req: Request, res: Response) {
  const post = await db.posts.findById(req.params.id);
  if (post.ownerId === req.user.id) {
    await db.posts.delete(post.id);
    return res.send({ deleted: true });
  }
  return res.status(403).send('forbidden');
}

// Cold-region candidate — function name "checkPermission" triggers the
// AUTH_NAME_REGEX in cold-scan. Structural pass misses the buried tier
// gate; the model should pick it up as feature_gate or business_rule.
export function checkPermission(req: Request, res: Response) {
  const tier = req.user.subscriptionTier;
  if (tier === 'free' || (tier === 'basic' && req.path.includes('/advanced'))) {
    return res.status(402).send('Upgrade required');
  }
  return res.json({ feature: 'unlocked' });
}
```

This file is constructed to exercise **both** of the candidate sources deep
mode considers:

1. The `deletePost` ownership check matches the structural rule
   `ts-ownership-check` — but at medium confidence, so it gets *escalated*
   to the model for a second look.
2. The `checkPermission` function name triggers `AUTH_NAME_REGEX` in
   `discover_cold_regions`, but the body has no structural pattern match —
   the structural pass misses it entirely. Deep mode picks it up as a
   *cold region* candidate.

## Static baseline

```bash
./target/release/zift scan /tmp/zift-manual -f json | jq '.findings'
```

```json
[
  {
    "file": "app.ts",
    "line_start": 7,
    "line_end": 7,
    "category": "ownership",
    "confidence": "medium",
    "pass": "structural",
    "pattern_rule": "ts-ownership-check",
    "code_snippet": "post.ownerId === req.user.id"
  }
]
```

**One finding.** `checkPermission` is invisible to the structural pass
because there's no rule that matches a string-equality comparison against
a literal subscription tier. The structural pass is fast and right, but
narrow — it only knows the patterns it knows.

This is the gap deep mode exists to fill.

---

## Test 1 — HTTP transport via Ollama (Tier 2)

Easiest path. Fully local, no API key, no per-token cost. Ollama exposes
an OpenAI-compatible endpoint at `http://localhost:11434/v1`.

```bash
ollama pull qwen2.5-coder:14b
./target/release/zift scan /tmp/zift-manual \
  --deep \
  --base-url http://localhost:11434/v1 \
  --model qwen2.5-coder:14b \
  -f json -v
```

What zift logs:

```
INFO running deep scan via HTTP: base_url=http://localhost:11434/v1 model=qwen2.5-coder:14b
INFO deep: analyzing 1 candidate(s) (cap: 50)
DEBUG semantic finding file=app.ts lines="7-8" category=Ownership confidence=Medium is_false_positive=false
INFO deep: 1 semantic finding(s); 0 structural false-positive(s); spent $0.0000
DEBUG merge: semantic finding replaces structural at app.ts:7-8
```

Result:

```json
{
  "file": "app.ts",
  "line_start": 7,
  "line_end": 8,
  "category": "ownership",
  "confidence": "medium",
  "pass": "semantic",
  "pattern_rule": "ts-ownership-check-semantic",
  "description": "Ownership check where post.ownerId is compared to req.user.id."
}
```

Three things to notice:

- **One candidate, not two.** The escalation's expanded context window
  (5 lines before, 15 after) absorbed the entire file — `checkPermission`
  was *inside* the candidate window, so it wasn't added as a separate
  cold-region candidate. The `coalesce_windows` + `overlaps_any` logic
  in `src/deep/candidate.rs` suppresses overlapping cold regions, since
  the model is already going to see that code.

- **`pattern_rule: "ts-ownership-check-semantic"`.** Semantic findings
  derived from an escalation seed get the seed's rule id with a
  `-semantic` suffix. They share lineage with the structural rule that
  triggered the analysis, but are distinguishable from it. (More on this
  in [Static vs deep — what changes about findings](#static-vs-deep--what-changes-about-findings).)

- **`merge: semantic finding replaces structural at app.ts:7-8`.** When a
  semantic finding overlaps a structural one, the structural is dropped
  (the deep pass is the more authoritative verdict). You don't get
  duplicate findings stacked at the same window.

The model didn't surface the `checkPermission` tier gate this run — it saw
the code in context but chose not to flag it. That's a model-side recall
issue, not a Zift bug. Either tighten the prompt, try a larger model, or
isolate the cold region into its own file.

### 1b — cold region in isolation

To force the cold-region path to fire on its own, separate it from any
structural finding:

```ts
// /tmp/zift-manual2/feature.ts
import { Request, Response } from 'express';

export function checkPermission(req: Request, res: Response) {
  const tier = req.user.subscriptionTier;
  if (tier === 'free' || (tier === 'basic' && req.path.includes('/advanced'))) {
    return res.status(402).send('Upgrade required');
  }
  return res.json({ feature: 'unlocked' });
}
```

```bash
./target/release/zift scan /tmp/zift-manual2 -f json | jq '.findings | length'
# → 0   (structural pass finds nothing)

./target/release/zift scan /tmp/zift-manual2 \
  --deep --base-url http://localhost:11434/v1 --model qwen2.5-coder:14b \
  -f json -v
```

```json
{
  "file": "feature.ts",
  "line_start": 6,
  "line_end": 9,
  "category": "feature_gate",
  "confidence": "high",
  "pass": "semantic",
  "pattern_rule": "semantic-feature_gate",
  "description": "Checks user subscription tier to gate access to certain features."
}
```

**`pattern_rule: "semantic-feature_gate"`** — note the prefix flip. Cold-
region candidates have no structural seed, so the rule id is synthesized
from the model's category. This makes the lineage explicit:

- `{rule}-semantic` → "the model re-evaluated structural rule `{rule}`"
- `semantic-{category}` → "the model found this on its own; no structural seed"

A consumer grouping findings by `pattern_rule` can tell at a glance which
findings the structural rules already covered and which only deep mode
caught.

**Cost:** $0.0000 (local). **Time:** 6.3s after model warm-up.

---

## Test 2 — MCP via Claude Code (Tier 1)

The headline path. Claude Code is the agent. It calls Zift's tools via
stdio MCP and runs the model itself — zift never sees the model.

Register zift as a project-scoped MCP server. **Note the `--`** between
`claude mcp add`'s flags and the server command, otherwise `claude` eats
zift's `--scan-root`:

```bash
claude mcp add zift -- /Users/brad/dev/zift/target/release/zift mcp \
  --scan-root /tmp/zift-manual

claude mcp list
# zift: /Users/brad/dev/zift/target/release/zift mcp --scan-root /tmp/zift-manual - ✓ Connected
```

Then run a non-interactive Claude Code session that's allowed to use
zift's tools:

```bash
claude -p "Use zift's MCP tools to do a full deep authorization scan of /tmp/zift-manual:
1. scan_authz to get structural findings.
2. For each finding, get_finding_context to widen the window.
3. Also look for cold regions: find files with auth-y function names
   (checkPermission, isAdmin, hasRole, etc), call get_finding_context on them.
4. For each widened context, call analyze_snippet to fetch zift's deep-pass
   prompt envelope.
5. Evaluate each prompt envelope yourself: read the system + user prompts,
   examine the snippet, produce findings matching the JSON schema.
6. Report all findings (structural + semantic) as a JSON array with file,
   lines, category, confidence, source, reasoning." \
  --output-format stream-json --verbose \
  --allowedTools "mcp__zift__scan_authz,mcp__zift__get_finding_context,mcp__zift__analyze_snippet,Read,Glob"
```

What Claude Code did, in order (extracted from the stream-json trace):

1. `mcp__zift__scan_authz({path: "/tmp/zift-manual"})`
2. `mcp__zift__get_finding_context({file: "app.ts", line_start: 7, line_end: 7})`
3. `mcp__zift__get_finding_context` again with a wider range — saw `checkPermission`
4. `mcp__zift__analyze_snippet` for the `deletePost` window (lines 5-12)
5. `mcp__zift__analyze_snippet` for the `checkPermission` window (lines 17-23)
6. **Evaluated both envelopes against its own model (Opus 4.7)** and produced findings.

Final output:

```json
[
  {"file": "app.ts", "lines": "7", "category": "ownership", "confidence": "medium", "source": "structural"},
  {"file": "app.ts", "lines": "5-12", "category": "ownership", "confidence": "high", "source": "semantic"},
  {"file": "app.ts", "lines": "17-23", "category": "feature_gate", "confidence": "high", "source": "semantic"}
]
```

| metric | value |
|---|---|
| turns | 7 |
| duration | 81s |
| cost | $0.43 (Opus 4.7) |
| zift tool calls | 5 |
| findings produced | 3 |

**This is the same fixture as Test 1.** Three findings instead of one — the
larger model + agentic flow caught both the ownership escalation *and* the
feature gate that Ollama missed.

Cleanup:

```bash
claude mcp remove zift
```

### Tier 1 quirk

The MCP server has no `discover_cold_regions` tool today. An agent host
can only reach files surfaced via `get_finding_context` from an existing
structural finding. In Tier 2/3, zift drives candidate discovery directly
via `discover_files_for_deep` and walks the whole scan root — the agent
host can't trigger that pathway through MCP. Worth knowing if you're
auditing a codebase whose authz logic lives outside any structural rule's
reach.

---

## Test 3 — Subprocess via `claude -p` (Tier 3)

Same agent as Test 2, different transport. This is the headless / CI path —
no interactive session, no MCP scaffolding, just stdin → stdout.

```bash
cat > /tmp/zift-claude-agent.sh <<'EOF'
#!/bin/bash
# Adapter: read zift's {system, user, schema} envelope on stdin,
# shell out to `claude -p`, emit deep-mode JSON on stdout.
set -euo pipefail
envelope=$(cat)
system=$(echo "$envelope" | jq -r .system)
user=$(echo "$envelope"   | jq -r .user)
schema=$(echo "$envelope" | jq -c .schema)

prompt=$(cat <<INNER
$system

---

$user

---

Respond with ONLY a JSON object matching this schema. No prose. No markdown fences.

Schema:
$schema
INNER
)

# claude -p --output-format json wraps the result as {"type":"result","result":"..."}.
# Pull .result, strip any ``` fences the model added anyway, emit the JSON.
claude -p "$prompt" --output-format json 2>/dev/null \
  | jq -r '.result' \
  | python3 -c 'import sys, re; s=sys.stdin.read().strip(); print(re.sub(r"^```(?:json)?\s*|\s*```$", "", s, flags=re.M))'
EOF
chmod +x /tmp/zift-claude-agent.sh

./target/release/zift scan /tmp/zift-manual \
  --deep --agent-cmd "/tmp/zift-claude-agent.sh" \
  -f json -v
```

Result: 3 findings (1 structural + 2 semantic), 6s. Same shape as Test 2.

### Why fence-stripping?

The model often wraps its JSON in ` ```json … ``` ` despite the prompt
asking it not to. The Python regex strips those fences before the JSON
hits zift's deserializer. If you don't, you get a per-candidate
`BadResponse: model returned malformed JSON` warning and lose that
candidate's findings.

If `claude -p` ever emits a banner or warning to stdout (deprecation
notices, login prompts), the wrapper needs to be tightened — zift expects
the *only* thing on stdout to be the JSON envelope.

---

## Test 4 — Subprocess via `codex exec` (Tier 3)

Same shape, different agent. The OpenAI Codex CLI has `--output-schema`
natively, so the wrapper is shorter and the JSON is schema-constrained
by the OpenAI API itself — no fence-stripping needed.

```bash
cat > /tmp/zift-codex-agent.sh <<'EOF'
#!/bin/bash
set -euo pipefail
envelope=$(cat)

tmpdir=$(mktemp -d)
trap "rm -rf $tmpdir" EXIT
schema_file="$tmpdir/schema.json"
out_file="$tmpdir/result.json"

echo "$envelope" | jq .schema > "$schema_file"
prompt="$(echo "$envelope" | jq -r .system)

---

$(echo "$envelope" | jq -r .user)"

codex exec \
  --skip-git-repo-check \
  --sandbox read-only \
  --output-schema "$schema_file" \
  --output-last-message "$out_file" \
  "$prompt" >/dev/null 2>&1

cat "$out_file"
EOF
chmod +x /tmp/zift-codex-agent.sh

./target/release/zift scan /tmp/zift-manual \
  --deep --agent-cmd "/tmp/zift-codex-agent.sh" \
  -f json -v
```

Result, condensed:

```
finding 1: structural ownership (line 7)            → ts-ownership-check
finding 2: semantic ownership (lines 7-11, high)    → ts-ownership-check-semantic
finding 3: semantic feature_gate (lines 18-20, high) → semantic-feature_gate
```

7.5s end-to-end. Same 3-finding shape as Tests 2 and 3.

Notice finding #3's `pattern_rule`: **`semantic-feature_gate`**, not
`ts-ownership-check-semantic`. The escalation's expanded window covered
the `checkPermission` function, the model returned a feature_gate finding
for it — but its line range (18-20) is *disjoint* from the seed's range
(line 7), so the lineage falls back to the category-based slug. A
consumer grouping by `pattern_rule` can tell this finding has nothing to
do with the ownership rule that triggered the analysis.

---

## Comparison

Same fixture (`/tmp/zift-manual/app.ts`), different transports:

| | Transport | Agent | Findings | Time | Cost | Driver |
|---|---|---|---|---|---|---|
| 1a | HTTP | Ollama qwen2.5-coder:14b | 1 (escalation only) | ~26s | $0.00 | zift |
| 1b | HTTP | Ollama qwen2.5-coder:14b on cold-only fixture | 1 | ~6s | $0.00 | zift |
| 2 | MCP | Claude Code (Opus 4.7) | 3 | ~81s | $0.43 | host |
| 3 | Subprocess | `claude -p` | 3 | ~6s | usage hidden | zift |
| 4 | Subprocess | `codex exec` | 3 | ~7s | usage hidden | zift |

Three transports, four agents, identical contract: same `(system, user,
schema)` envelope, same `findings[]` JSON output, same merge semantics.

## Static vs deep — what changes about findings

Every finding has a `pass` field that says where it came from:

- `pass: "structural"` — tree-sitter pattern match. Has a `pattern_rule`
  matching a real rule in `rules/{language}/`. Has a `rego_stub` populated
  from the rule's template.
- `pass: "semantic"` — model verdict. Has a synthetic `pattern_rule`
  (see lineage table below). `rego_stub` is null — semantic findings
  don't carry a Rego template (the model isn't drafting policy).

### `pattern_rule` lineage on semantic findings

| Candidate kind | Model's range overlaps seed? | `pattern_rule` |
|---|---|---|
| Escalation (structural finding triggered the analysis) | yes | `{seed-rule-id}-semantic` |
| Escalation | no (incidental finding from surrounding context) | `semantic-{category}` |
| Cold region (no seed) | n/a | `semantic-{category}` |

Why this matters: pre-fix (PR #23), every semantic finding from an
escalation candidate inherited the seed's `pattern_rule` *verbatim*, even
when the model re-categorized the finding entirely. An ownership seed
re-evaluated as `feature_gate` was still being reported as
`Rule: ts-ownership-check`. Lineage was lost; provenance was confusing.
The current rules separate "this is the seed's verdict" from "this is an
incidental finding the model spotted nearby".

### `summary.by_category` round-trips

The summary block uses the same canonical snake_case slugs as
`findings[].category`:

```json
{
  "findings": [
    {"category": "feature_gate", ...},
    {"category": "ownership", ...}
  ],
  "summary": {
    "by_category": {"feature_gate": 1, "ownership": 1}
  }
}
```

A JSON consumer can group findings by category and look the count up in
the summary without any string mangling. (This was a real bug pre-fix —
the summary used `Display`-form keys with spaces, the findings used
serde snake_case, and they disagreed on `business_rule` / `feature_gate`.
Both sides now go through `AuthCategory::slug()`.)

## When to reach for which mode

- **Static (`zift scan`)**: always. It's the floor of what zift knows. CI
  should always run it; PRs touching auth-related files should always
  trip it. Free, fast, deterministic.
- **Tier 2 HTTP local (Ollama, LM Studio, llama.cpp)**: for full local
  iteration. Free, your code never leaves the machine, latency dominated
  by your GPU. Limited by the model's recall — small models (≤7B) miss
  things, ≥14B is the sweet spot for following the schema reliably.
- **Tier 2 HTTP remote (OpenAI, OpenRouter, …)**: when you want a frontier
  model's recall and don't mind the per-token cost. Set `--max-cost` and
  configure `cost_per_1k_input` / `cost_per_1k_output` in `.zift.toml` so
  the cap actually binds.
- **Tier 1 MCP**: when an auditor or developer is reviewing a codebase
  *interactively* and wants the agent in the loop — picking which findings
  to triage, drafting Rego, asking follow-up questions. Most expensive
  per run, most useful per run.
- **Tier 3 subprocess**: when your agent doesn't speak HTTP. `claude -p`,
  `aider`, custom scripts that do retrieval before calling a model, in-
  house wrappers that stamp results with provenance. The wrapper is
  yours; the contract is just `{system, user, schema}` in, deep-mode
  JSON out.

You don't have to pick one. A common shape:
- Static in CI on every PR
- Tier 2 HTTP-local against Ollama nightly for repo-wide drift
- Tier 1 MCP when a human is reviewing

## Things that surprised us during the shakedown

- **Ollama doesn't strictly support `response_format: json_schema`**. The
  HTTP client retries without strict schema on 400; you'll see one warning
  per candidate the first time. Doesn't break anything, just adds noise.
- **High-confidence structural findings don't escalate.** They're already
  trusted. If you want to force one through deep mode, rewrite the rule
  to medium confidence or drop it altogether and let the cold-region path
  pick it up.
- **Cold regions are suppressed when their window overlaps an escalation
  candidate's window** (`overlaps_any` in `src/deep/candidate.rs`). The
  model already sees that code in the escalation prompt, so a duplicate
  candidate just doubles your token spend.
- **Localhost auto-caps `max_concurrent` to 1**. Single-GPU servers
  serialize internally; parallelism > 1 just adds queue latency.
- **A typo'd `--agent-cmd` (binary not found, exit 127) gets per-
  candidate-skipped**, not failed-fast. You'll see a `WARN bad response`
  for every candidate. Worth grepping logs for repeated `bad response`
  before trusting a "no findings" result.
- **`claude -p` cold-starts can take 30+ seconds.** The subprocess
  transport's default `agent_timeout_secs` is 600 (10 minutes) for this
  reason — don't tighten it for agent CLIs.

## See also

- [`docs/DESIGN.md`](DESIGN.md) — overall architecture, rule schema, scan
  pipeline.
- [`README.md`](../README.md) §Deep mode — flag reference and config-file
  schema.
- [`plans/done/00-deep-mode-overview.md`](../plans/done/00-deep-mode-overview.md)
  — original three-PR plan, the build-order rationale, what each transport
  was meant to be good at.
