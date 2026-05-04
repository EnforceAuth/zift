# Corpus shakedown — follow-ups

Concrete rule / scanner fixes surfaced by the day-of-OSS corpus shakedown ([04-pre-oss-corpus-shakedown.md](04-pre-oss-corpus-shakedown.md)). Each item is sized to land as a tight, single-PR fix; ordered by impact.

## P0 — high-leverage rule predicate fixes

### 1. `go-has-role-call`: widen predicate, drop string-literal requirement

**Why.** Gitea's permission model is `IsAdmin()`, `IsOwner()`, `HasAnyUnitAccess()`, `CanRead(unit)`. None match the current rule because (a) the name regex is `^(HasRole|HasAnyRole|...)$` and (b) the rule requires a string-literal argument. Deep mode found 13 `semantic-rbac` matches in 600 LOC of `models/perm/access/`; **all** are this shape.

**Fix.**
- Extend `match` regex to: `^(HasRole|HasAnyRole|CheckRole|IsRole|IsInRole|RequireRole|RequireRoles|IsAdmin|IsOwner|Is[A-Z][A-Za-z]*Admin|Can[A-Z][A-Za-z]+|Has[A-Z][A-Za-z]+)$`.
- Drop the string-literal-argument constraint, or split into two rules: `go-has-role-call` (string-literal arg, current behavior, `high` confidence) and `go-permission-predicate-call` (no arg constraint, name-driven, `medium` confidence).
- Add Gitea-style positive tests: `repo.IsAdmin(user)`, `perm.IsOwner()`, `unit.HasAnyUnitAccess()`.

**Expected impact.** Gitea findings jump from 18 → ~200+. Same shape exists in any Go service that hand-rolls authz.

### 2. `ts-permission-check-call`: include `canThis|can|may|allow` chained DSLs

**Why.** Ghost uses `canThis(user).edit.post(post)`. Cal.com uses `userBelongsToTeam(...)`, `isTeamAdmin(...)`. Neither matches.

**Fix.**
- Add a new rule `ts-chained-permission-call` matching `<callee>(...).<verb>.<resource>(...)` where the outer callee name matches `^(can|may|allow|check|ability)$` (case-insensitive). This covers Ghost, CASL, Pundit ports, and similar DSLs.
- Widen `ts-permission-check-call` predicate to include `belongsTo|isTeamAdmin|isOrgOwner|hasMembership|userIs[A-Z]`.

**Expected impact.** Ghost permission DSL surfaces (~10 sites in `core/server/`); Cal.com membership checks across `packages/lib/server/queries/` (estimated 50+ sites).

### 3. `ts-role-check-conditional`: support member-access role paths

**Why.** Cal.com Next.js handlers do `if (session.user.role !== "ADMIN")`. Current rule expects a bare `role` identifier.

**Fix.** Extend the tree-sitter query to accept `member_expression` on the LHS, with the rightmost name matching `^(role|roleName|user.role)$`.

**Expected impact.** Cal.com `apps/web/app/api/` route handler coverage jumps from ~0 to dozens.

### 4. `py-permission-check-call`: include `check_*` helper family

**Why.** Zulip's actual policy decision points are `check_can_invite_users(user_profile, ...)`, `check_basic_stream_access(...)`, `check_message_edit_access(...)`. None match.

**Fix.** Add a positive heuristic for prefixes `check_can_|check_basic_|check_message_|check_stream_|check_*_access`. Could also be a separate `py-check-helper-call` rule.

**Expected impact.** Zulip findings expand from 23 → ~150+ across `zerver/views/` and `zerver/lib/`.

## P1 — new rules for missed ecosystems

### 5. Java `@Authorized` annotation rule

**Why.** OpenMRS's primary policy surface is the custom `@Authorized({"Manage Users"})` annotation. 24 files use it; we found 0.

**Fix.** Generalize the Spring annotation rules into a templated `java-annotation-authz.toml` that takes a configurable annotation name (`@PreAuthorize`, `@Secured`, `@RolesAllowed`, `@Authorized`, `@RequiresPermissions`). Configurable list lives in `[rule.predicates.annotation_name]`.

### 6. Python `@require_*` decorator rule

**Why.** Zulip's `@require_realm_admin`, `@require_organization_member`, `@require_member_or_admin` decorators are first-class authz gates applied to view functions. Zero structural coverage today.

**Fix.** Add `py-require-decorator.toml` matching `decorator: (call function: (identifier) @name)` with predicate `^require_[a-z_]+$`. Same cost as Java's `@Secured` rule.

### 7. tRPC procedure rule

**Why.** Cal.com's web app uses tRPC heavily; `protectedProcedure`, `adminProcedure`, custom `isAdminMiddleware` middleware are unmatched.

**Fix.** Add `ts-trpc-procedure.toml` for `t.procedure.<middleware>.use(...)` and the well-known `protectedProcedure` / `adminProcedure` chained builders.

### 8. NestJS guard composition rule (already exists; calibrate confidence)

`ts-nestjs-use-guards` carried Cal.com's report — 123/166 findings, all genuine. Confidence is already `high`; no change needed beyond verification on more NestJS repos post-OSS.

## P2 — false-positive tightening

### 9. `ts-jwt-token-check`: split sign vs verify/decode

**Why.** Ghost's report is dominated by `jwt.sign(...)` calls — *token issuance for outbound integrations*, not authz decisions. Deep would dismiss most.

**Fix.** Split into:
- `ts-jwt-verify-decode` (authz decision; keep current `medium` confidence)
- `ts-jwt-sign-issue` (`low` confidence, category `custom`, separate from middleware)

### 10. Frontend ownership noise

**Why.** Zulip's `web/src/...` `user.user_id === current_user.user_id` ownership matches are mostly UI state ("is this me?"), not security gates. 15 of 39 Zulip findings.

**Fix.** Either (a) add an exclude-glob default that demotes `web/src/**` and `frontend/**` paths to `low` confidence, or (b) add a per-finding `surface: frontend|backend` field driven by simple path heuristics so users can filter post-hoc.

## P3 — scanner / output

### 11. Empty `code_snippet` on semantic findings

All 28 deep findings across the Zulip subsets carried `code_snippet: ""`. The structural pass populates `code_snippet` from the AST match range; the semantic pass should populate it from the reported line range (or pass through what the agent returned, if non-empty). Without it, downstream tools that show users *what was flagged* have nothing to show.

**Fix.** In the semantic-finding builder, default `code_snippet` to the source slice `lines[line_start..=line_end]` when the agent didn't return one.

### 12. `enforcement_points` reports 0 on every codebase

The `summary.enforcement_points` field is 0 for all five corpus runs. Either the metric is broken or the scanner isn't recognizing externalized policy at all (possible — none of these repos have any). Verify the metric works on a fixture that does have OPA/Cedar files; document the behavior.

### 13. Per-finding `pass` field is the correct anchor for diffs

Every finding carries `pass: structural | semantic`. Use this in `docs/corpus/README.md`'s diff recipe rather than file+line tuples (lines drift across deep's structural-merge step).

## Sequencing

P0 1–4 are predicate widening — small TOML diffs. Land before OSS if there's any time, else first thing post-OSS.
P1 5–7 are new rules — slightly bigger but each one unlocks a popular ecosystem.
P2 9–10 are calibration — depend on having more deep-pass data than today's sample.
P3 11 is the empty-`code_snippet` fix; 12 is a scanner audit; 13 is a docs cleanup.