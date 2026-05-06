# Cedar Support — Design Memo

**Status:** Draft — exploring for v0.3
**Author:** seeded from a scoping investigation; refine before committing to a milestone
**Companion issue:** [#27 — Cedar support / pluggable policy backends](https://github.com/EnforceAuth/zift/issues/27)

## TL;DR

zift currently emits [Rego](https://www.openpolicyagent.org/docs/latest/policy-language/) for [OPA](https://www.openpolicyagent.org/) as its only Policy-as-Code (PaC) target. Adding [Cedar](https://www.cedarpolicy.com/) as a second first-class target is a ~300–400-line change spread across the rule format, finding schema, generator module, CLI, and MCP API. The deep-mode prompt and the structural scanner are already engine-agnostic, so the work is concentrated in the *generation* and *output* layers.

This memo is a scoping document, not a build plan. It records what's coupled to Rego today, the smallest set of changes that would let Cedar coexist with Rego as peer backends, and the migration risks worth budgeting for before we start cutting code.

## Why Cedar (and why now is "later, not now")

Cedar is the natural second target:
- **Different audience.** AWS Verified Permissions, Authzed, and Cedar-as-a-library shops aren't an OPA crowd. Generating Rego for them is a non-starter; generating Cedar makes zift relevant.
- **Different shape.** Cedar's policy model (principal/action/resource with explicit hierarchies) is closer to an authorization service than OPA's general-purpose decision engine. Some findings will translate to Cedar more naturally than to Rego (and vice versa).
- **Validates the abstraction.** Today "PaC backend" is a one-element set. Two elements is the smallest test of whether the abstraction actually holds up.

It's not the right work for v0.2 because:
- v0.2 is committing to Python and Go *structural* scanning. Splitting attention across backend pluralism and language pluralism would dilute both.
- The Rego templates aren't yet stable enough that locking them behind a trait makes sense — we're still learning what good Rego output looks like for the categories we detect.
- We have no concrete user pulling for Cedar today. Adding it speculatively risks shipping a half-baked Cedar generator that nobody validates.

So: log the design now while context is fresh; revisit when v0.2 is shipping.

## Current coupling — what's where

### Engine-agnostic (no work needed)

- **`src/scanner/`** — finds authz patterns; doesn't know what gets generated downstream.
- **`src/deep/prompt.rs`** — the LLM prompt describes authz categories, not policy languages. The deep-mode response schema (`SemanticFinding`) is engine-neutral.
- **`AuthCategory`, `Confidence`, `Finding` core fields** — the taxonomy is about *what the code does*, not *how to express the policy*.

### Lightly coupled (additive change)

- **`Finding::rego_stub: Option<String>`** in `src/types.rs` — single field, serialized to JSON. Adding `cedar_stub: Option<String>` alongside is backward-compatible. Cleaner long-term: a `policy_outputs: Vec<PolicyOutput { engine, content }>` collection, but that's a JSON-schema migration consumers feel.
- **TOML rule format** (`rules/**/*.toml`, `[rule.rego_template]`) — each rule has exactly one template. Add an optional `[rule.cedar_template]` block; rules without one simply produce no Cedar output for that finding (acceptable — Cedar coverage can grow rule-by-rule).
- **`extract` CLI subcommand** — add `--engine rego|cedar` (default `rego`). `--package-prefix` is Rego-flavored; rename to `--policy-prefix` and document it as a no-op for Cedar, or keep both with deprecation.

### Tightly coupled (real refactor)

- **`src/rego/`** — `validator.rs` embeds `regorus`; `templates.rs` does Rego-specific package naming and `#`-comment confidence wrapping; `grouping.rs` produces Rego module hierarchies. ~500 lines, all Rego-shaped.
- **`src/mcp/tools.rs`** — `suggest_rego` and `validate_rego` are tool names in the MCP descriptor. Changing names is a breaking API contract for any agent host (Claude Code, Cursor, Cline, Zed) that has them wired in.

## Proposed approach

### Phase A — additive, no breaking changes (~250 lines)

1. **Rule format: parallel template keys**
   ```toml
   [rule.role-check-conditional.rego_template]
   template = "..."

   [rule.role-check-conditional.cedar_template]   # new, optional
   template = "..."
   ```
   In `src/rules/mod.rs`, parse both. Most rules will only have `rego_template` for a long while.

2. **`Finding` schema: parallel stub field**
   ```rust
   pub struct Finding {
       // ...
       pub rego_stub: Option<String>,
       pub cedar_stub: Option<String>,   // new
   }
   ```
   Backward-compatible serialization. JSON consumers that don't know about Cedar see a field they ignore.

3. **New `src/cedar/` module**
   Mirrors `src/rego/` but smaller. Cedar has no packages and a flatter file model, so `grouping.rs` is simpler. Validation can use the [`cedar-policy`](https://crates.io/crates/cedar-policy) crate directly.
   ```text
   src/cedar/
     mod.rs
     templates.rs    # render + confidence wrapping (Cedar uses // for comments)
     validator.rs    # cedar-policy parse check
     grouping.rs     # one .cedar file per package, no module nesting
   ```
   Estimate: ~200 lines.

4. **CLI: `--engine` on `extract`**
   ```bash
   zift extract findings.json --engine cedar --output-dir ./policies/cedar
   ```
   Default remains `rego` for backward compatibility.

5. **MCP: new tools, old aliases retained**
   - Add `suggest_policy(finding_id, engine)` and `validate_policy(content, engine)`.
   - Keep `suggest_rego` and `validate_rego` as Rego-pinned aliases that internally call the new tools with `engine="rego"`. Document them as deprecated but supported.

### Phase B — clean up the abstraction (~150 lines + refactor)

Tracked separately as its own work item so Phase A can ship and Phase B can
land on its own merits, not on a wait-for-feedback gate.

6. **Extract a `PolicyGenerator` trait**
   ```rust
   pub trait PolicyGenerator {
       fn engine(&self) -> PolicyEngine;
       fn validate(&self, policy: &str) -> ValidationResult;
       fn wrap_by_confidence(&self, body: &str, confidence: Confidence) -> String;
       fn group_and_generate(&self, findings: &[Finding], opts: &ExtractOpts) -> Vec<PolicyFile>;
   }
   ```
   `RegoGenerator` and `CedarGenerator` implement it. The `extract` pipeline becomes generic over `dyn PolicyGenerator`, dispatched off the `--engine` flag.

7. **Replace parallel `*_stub` fields with a `PolicyOutput` collection on `Finding`**
   Swap `rego_stub` / `cedar_stub` for `policy_outputs: Vec<PolicyOutput>`. Provide a deserialization shim that folds legacy `*_stub` fields into the new collection so existing findings files keep loading; the shim is part of Phase B, not a separate migration.

## Risks and migrations

| Risk | Detail | Mitigation |
|---|---|---|
| Persisted JSON findings drift | Users who store findings files will have a mix of `rego_stub`-only and `rego_stub` + `cedar_stub` records | Phase A keeps both fields. Phase B replaces them with `policy_outputs` and ships a deserialization shim that reads the legacy fields, so old findings files keep loading without a coordinated bump |
| MCP tool-name contract | Agent hosts have `suggest_rego` / `validate_rego` wired up | Keep them as aliases indefinitely; new tools are opt-in |
| Half-baked Cedar templates | Shipping Cedar coverage for some rules but not others reads as broken | Document Cedar coverage per-rule; CLI warns when extracting Cedar from rules that have no Cedar template |
| `regorus` and `cedar-policy` binary size | Two policy engines linked into one binary | Both are Rust-native; combined overhead should be ~3–5MB. Acceptable. Revisit with `--features rego,cedar` if it bloats |
| `--package-prefix` semantics | Cedar has no packages | Rename to `--policy-prefix`; for Cedar, treat as a filename prefix instead. Document explicitly |

## Out of scope

- **Auto-translating Rego → Cedar.** zift generates from findings, not from existing Rego. Translation between engines is a separate (and much harder) problem.
- **Cedar runtime / enforcement.** Same as Rego: zift is static analysis. Enforcement is the platform's job.
- **Engine selection heuristics.** No "zift picks the right engine for your finding" magic. The user picks the engine; zift fills in the template.
- **Other PaC languages in this milestone.** This memo is about going from one engine to two. Going from two to N is a separate exercise that benefits from what Phase B teaches us.

## Open questions

1. **Template parity expectations.** Do we require every rule to ship a Cedar template before we mark Cedar "supported," or do we ship Cedar with partial coverage and expand over time? (Recommendation: partial coverage with clear per-rule reporting.)
2. **MCP versioning.** If we add `suggest_policy`/`validate_policy`, do we bump the MCP server's advertised version? Agent hosts may key behavior off it.
3. **`cedar-policy` crate stability.** Cedar is younger than OPA. Worth a dependency review before committing.
4. **Default engine.** Stays `rego` for v0.3 (backward compatibility). Revisit for v1.0 — by then "PaC, you pick" might be the better default than any single engine.

## Decision log

- **2026-05-03** — memo drafted alongside the user-facing rename from "Rego for OPA" to "Policy as Code (PaC)." No code changes proposed yet; doc captures the investigation while context is fresh.
- **2026-05-06** — Phase A landed (`feat: add Cedar as a second policy engine`). Phase B's "wait for users" gate and "JSON-schema break needs a major-version bump" gate dropped: the `*_stub` → `policy_outputs` migration is in Phase B's scope and ships with a deserialization shim, so it doesn't need a coordinated version cut.
