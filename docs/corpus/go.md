# Go — Gitea

Real-world results from running Zift against [go-gitea/gitea](https://github.com/go-gitea/gitea), the self-hosted Git platform.

## Why this target

Gitea has the most embedded-authz-per-square-inch of anything we tried. Permission model is hand-rolled: `IsOwner`, `IsAdmin`, `CanRead(unit)`, `CanWrite(unit)`, `HasAccess(...)` and dozens of variants spread across `models/perm/`, `services/`, and `routers/`. Zero Casbin, zero OPA, zero externalized PaC. If Zift's Go ruleset has gaps, Gitea will surface them.

## Target metadata

| | |
|---|---|
| Repo | [go-gitea/gitea](https://github.com/go-gitea/gitea) |
| Commit | `762154cb` |
| Go files (excl. `vendor/`) | 2,900 |
| LOC (Go) | 461,786 |
| Externalized PaC | None observed |
| Zift version | 0.1.6 |

## Structural pass

```bash
zift scan ~/zift-corpus/go/gitea --format json -o structural.json
```

| | |
|---|---|
| Wall time | 6.33s |
| Peak RSS | ~30 MB |
| Total findings | **18** |
| Files with findings | 13 |

**Findings per rule**

| Rule | Count |
|------|------:|
| `go-ownership-check` | 16 |
| `ts-role-check-conditional` | 2 |

The two TS hits come from Gitea's `web_src/` frontend — that's expected and confirms the language router is doing the right thing across a mixed-language repo.

**Top findings (sample)**

| File | Line | Snippet |
|------|-----:|---------|
| `models/migrations/v1_11/v111.go` | 187 | `user.ID == repo.OwnerID` |
| `models/perm/access/repo_permission.go` | 440 | `user.ID == repo.OwnerID` |
| `models/perm/access/repo_permission.go` | 499 | `repo.OwnerID == user.ID` |
| `modules/repository/delete.go` | 16 | `user.ID == repo.OwnerID` |
| `routers/api/packages/npm/npm.go` | 169 | `repo.OwnerID == ctx.Doer.ID` |
| `routers/api/v1/user/key.go` | 34 | `defaultUser.ID == key.OwnerID` |

## Gaps & follow-ups

**FN: massive — Gitea's permission model is invisible to the structural pass.**

A quick grep for the obvious permission-check surface:

```text
$ grep -rE '\b(IsOwner|IsAdmin|CanRead|CanWrite|HasAccess|hasAccess)\(' \
    --include='*.go' --exclude-dir=vendor /path/to/gitea -l | wc -l
61
```

61 files contain calls Zift should have flagged; we found 13. The headline issues:

- **`go-permission-check-call` is too narrow.** It looks for verb names like `Allow*`, `Authorize*`, but Gitea's vocabulary is `IsX`, `CanX`. The predicate regex needs to be extended (or split into a separate `go-can-do-call` rule) to cover the convention.
- **`go-has-role-call` requires a string-literal argument.** `HasRole("admin")` matches; `IsAdmin()`, `IsOwner()` don't, even though they're semantically the same check. Either widen the predicate or add a dedicated `go-is-x-method` rule with a heuristic name regex.
- **Method receivers are domain types.** `repo.IsAdmin(user)`, `unit.CanRead(user)` — the predicate match needs to fire on the *method name* alone since the receiver is project-specific. The current `selector_expression` capture is good; it's the regex that misses.

**FN: ownership in expressions besides `==`.**

`go-ownership-check` only fires on `==` comparisons over `OwnerID`-suffixed identifiers. Many Gitea ownership checks use `MatchID(repo.OwnerID, user.ID)` helpers or `slices.Contains(admins, user.ID)`. Out of scope for v0.1, but worth a follow-up rule.

**FP risk: low.** All 16 ownership matches are genuine. The `medium` confidence is appropriate; deep should confirm.

**Mixed-language signal: positive.** TS findings in `web_src/` correctly identified as TypeScript and run through TS rules. Good calibration test.

## Deep pass

Run scoped to Gitea's permission model — `models/perm/access/` (3 files, ~600 LOC of pure access decisions):

```bash
zift scan ~/zift-corpus/go/gitea/models/perm/access/ \
  --deep --agent-cmd "claude -p --output-format json" \
  --format json -o deep.json
```

| | |
|---|---|
| Transport | subprocess (`claude -p`) |
| Total findings | 23 (2 structural retained + 21 semantic) |
| Files with findings | 1 (`repo_permission.go`) |
| Cost reported | $0.00 |

**Deep finds the `IsAdmin` / `IsOwner` / `HasAny*` family wholesale.** This is exactly the FN list the structural pass left on the floor:

| File | Line | Category | Description |
|------|-----:|----------|-------------|
| `repo_permission.go` | 39 | ownership | `IsOwner()` — owner-level access check |
| `repo_permission.go` | 44 | rbac | `IsAdmin()` — admin-or-higher access |
| `repo_permission.go` | 51 | abac | `HasAnyUnitAccess()` — read+ on any repo unit |
| `repo_permission.go` | 60 | feature_gate | `HasAnyUnitPublicAccess()` — anonymous access check |
| `repo_permission.go` | 440 | ownership | Admin override + owner-id check granting Owner access |
| `repo_permission.go` | 446 | rbac | Access-level (collaborator role) computation |
| `repo_permission.go` | 451 | abac | Org-vs-personal-repo permission short-circuit |
| `repo_permission.go` | 498 | ownership | `IsUserRealRepoAdmin` — combined owner / admin check |

13 deep-only `semantic-rbac` findings; all are named methods on `Permission` or top-level helpers. **Every single one would be caught by widening `go-has-role-call`'s predicate to include `^(IsAdmin|IsOwner|Is[A-Z][A-Za-z]*Admin|Can[A-Z][A-Za-z]+|Has[A-Z][A-Za-z]+)$` and dropping the requirement that the argument be a string literal.** That's a one-line rule change worth dozens of finding-equivalents per Gitea-shaped codebase.

## Diff structural ↔ deep

| Bucket | Count | Notes |
|--------|------:|-------|
| Both agree | 2 | Both `OwnerID ==` structural matches in this subset confirmed by deep (lines 440, 499) |
| Structural-only | 0 | Structural-pass-on-this-subset produced exactly 2 findings; both retained |
| Deep-only | 21 | The `IsAdmin` / `IsOwner` / `HasAny*` family + permission-short-circuit logic |

The bigger picture: the full-repo structural pass surfaced 18 findings; this single 3-file deep pass already identified 19 distinct authz decision points the structural pass had no rule for. Extrapolating to the rest of `models/perm/`, `services/`, and `routers/`, **the structural-coverage gap on Gitea is not 5×; it's closer to 50×**. Closing it doesn't require deep mode at scan time — it requires the rule predicate fix above.
