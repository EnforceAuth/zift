# Pre-OSS corpus shakedown

Tracks the effort to put Zift through its paces against real, recognizable open-source codebases — one per supported language — before flipping the repo public tomorrow.

## Goal

Surface bugs, false positives, false negatives, and ergonomic rough edges by running `zift scan` against codebases that:

1. Are well-known enough to make a credible "we ran Zift against X" demo / blog story.
2. Have **little or no externalized Policy as Code** (no production Rego/OPA/Cedar setup).
3. Have **enough embedded authz** — role checks, ownership tests, framework decorators / middleware — that we expect lots of findings.
4. Bonus points if they have *some* externalized PaC alongside embedded checks ("you already started; here's everything you missed" is a great narrative).

We are not trying to ship policies for these projects — we're stress-testing the scanner, the rule set, and the Rego generator on inputs we don't control.

We run **both passes** on every target:

- **Structural** (`zift scan`) — fast, deterministic, what every user gets out of the box.
- **Deep** (`zift scan --deep`) — semantic / LLM-assisted pass on the same tree.

Then we diff. Anywhere deep finds authz that structural missed is either (a) a candidate for a new structural rule, (b) a tightening of an existing predicate, or (c) genuine semantic-only territory we should call out in the docs. Anywhere structural fires that deep dismisses is a false-positive lead.

## Why these specific codebases

For each language we picked one **primary** target (the one we will actually run against and report on) and one **backup** in case the primary fails to clone or has license/scope issues.

| Lang | Primary | Backup | Why |
|------|---------|--------|-----|
| JavaScript | [TryGhost/Ghost](https://github.com/TryGhost/Ghost) | [NodeBB/NodeBB](https://github.com/NodeBB/NodeBB) | Ghost has a homegrown `canThis(user).edit.post(...)` permission DSL plus scattered `user.role` checks across `core/server/`. No Rego anywhere. Should hit `permission-check-call`, `has-role-call`, `role-check-conditional`, `express-*-middleware`. |
| TypeScript | [calcom/cal.com](https://github.com/calcom/cal.com) | [outline/outline](https://github.com/outline/outline) | Cal.com is Next.js + Prisma with extensive team/org/seat embedded checks (`isTeamAdmin`, `userBelongsToTeam`, `canEditEventType`, etc.) and zero externalized PaC. Should hit most TS rules including `nestjs-*`, `permission-check-call`, `ownership-check`, `jwt-token-check`. Outline is the "has *some* PaC" backup — its `policies/` directory is hand-rolled abac-ish code that maps cleanly to a "you've reinvented Rego" pitch. |
| Java | [openmrs/openmrs-core](https://github.com/openmrs/openmrs-core) | [jhipster/jhipster-sample-app](https://github.com/jhipster/jhipster-sample-app) | OpenMRS has a custom `Privilege` / `Role` model with `Context.hasPrivilege("...")` calls peppered throughout the service layer — no Spring Security expressions, no Rego, just embedded checks across a clinical domain. Should hit `custom-authz-call`, `has-role-call`, `authenticated-check`, and likely some `spring-*` rules in the web layer. JHipster sample is the canonical Spring Security + `@PreAuthorize` reference if OpenMRS misbehaves. |
| Python | [zulip/zulip](https://github.com/zulip/zulip) | [netbox-community/netbox](https://github.com/netbox-community/netbox) | Zulip is a mature Django app with a sprawling set of `user_profile.is_realm_admin`, `can_access_stream`, `check_*_permission` helpers and decorators — exactly the embedded-authz pattern Zift exists to surface. Should hit `django-permission-required`, `django-user-passes-test`, `has-perm-call`, `role-check-conditional`, `ownership-check`. NetBox is a clean Django object-permissions backup. |
| Go | [go-gitea/gitea](https://github.com/go-gitea/gitea) | [harness/drone](https://github.com/harness/drone) | Gitea is the gold standard for embedded Go authz: `IsOwner`, `IsAdmin`, `CanRead(unit)`, `CanWrite(unit)` calls everywhere across `models/`, `routers/`, `services/`. No Casbin, no Rego. Should hit `has-role-call`, `permission-check-call`, `ownership-check`, `role-check-conditional`, `gin-auth-middleware`. Drone is the backup with simpler middleware-based authz. |

## Workspace layout

Clone targets live outside the repo so we don't bloat the tree or accidentally commit them:

```
~/dev/zift-corpus/
  js/Ghost/
  ts/cal.com/
  java/openmrs-core/
  python/zulip/
  go/gitea/
```

`.gitignore` already ignores `target/`; nothing in this plan touches the Zift repo's own checkout.

## Per-target checklist

For each codebase, run the same battery and publish results in `docs/corpus/<lang>.md` so users browsing the repo on day one can see real-world examples of what Zift finds:

- [ ] Shallow clone (`git clone --depth 1`) into `~/dev/zift-corpus/<lang>/<repo>`.
- [ ] **Structural pass:** `zift scan <path> --format json > structural.json` and time it.
- [ ] `zift scan <path> --format text` — skim for obvious garbage / panics.
- [ ] **Deep pass:** `zift scan <path> --deep --format json > deep.json` (transport per `[deep]` config; default to MCP/HTTP whichever is wired locally). Time it; record token cost if the transport reports it.
- [ ] **Diff structural vs deep** by file+line+rule. Bucket the deltas:
  - *Deep-only finding* → potential new structural rule or predicate tightening. File a follow-up.
  - *Structural-only finding that deep marked low-confidence / dismissed* → false-positive lead.
  - *Both agree* → calibration win; record as confidence signal.
- [ ] Run `zift extract <path>` (if applicable) and confirm Rego stubs compile (`opa fmt`, `opa eval`).
- [ ] Record in `docs/corpus/<lang>.md`:
  - Repo, commit SHA scanned, file count, LOC, wall time (structural & deep), peak RSS, deep token usage if available.
  - Findings per rule, structural vs deep (`jq 'group_by(.rule_id) | map({rule: .[0].rule_id, n: length})'`).
  - Top-10 findings with file:line — eyeball for false positives.
  - Diff summary (deep-only / structural-only / both).
  - Any rule that fires **zero** times despite the language being present (FN lead — investigate).
  - Any panic, parse error, or tree-sitter failure.
- [ ] File issues for anything actionable; tag `pre-oss` so we can triage before flipping public.

A top-level `docs/corpus/README.md` summarizes the five runs so a visitor can scan one page and see "Zift found N embedded authz sites across these well-known projects."

## Cross-cutting things to watch for

- **Vendored / generated code.** All five primaries vendor *something* (Gitea vendors deps under `vendor/`, Zulip has migrations, Cal.com has generated Prisma client). Confirm Zift's ignore defaults are sane; if not, that's a bug to file before OSS.
- **Monorepo handling.** Cal.com is a turborepo with `apps/` and `packages/`. Make sure scanning the root produces sensible per-package output, not one giant blob.
- **Mixed-language repos.** Gitea has TS in `web_src/`. Ghost has some TS creeping in. Confirm the language router picks the right rule set per file.
- **Rego template quality.** The generated stubs should at least be syntactically valid Rego. Run `opa fmt --diff` over the output dir as a sanity check.
- **Confidence calibration.** If a `medium`-confidence rule produces 90% of findings on every codebase, that's a signal to tighten or downgrade.

## Schedule

We're flipping the repo public **tomorrow**, so this is a one-day shakedown:

1. Clone all five primaries in parallel (cheap, network-bound).
2. Run scans serially, capture results, file issues as we go.
3. Reserve the last block of the day for any P0 fixes that are small (rule predicate tweaks, ignore-glob defaults). Anything bigger gets filed and ships post-OSS.

## Out of scope

- Authoring policies that would actually govern these projects.
- Upstreaming findings as PRs to the target projects (cool follow-up; not today).
- Performance benchmarking beyond rough wall-time. We need correctness signal first.
- Running `--deep` against every file in every repo if cost / latency makes that infeasible. If a tree is too large, sample to a representative subdirectory (e.g. Cal.com `apps/web/app/api/`, Gitea `routers/` + `models/`, Zulip `zerver/`) and note the sampling strategy in the results doc.
