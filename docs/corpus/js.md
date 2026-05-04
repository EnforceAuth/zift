# JavaScript — Ghost

Real-world results from running Zift against [TryGhost/Ghost](https://github.com/TryGhost/Ghost), the headless publishing platform.

## Why this target

Ghost is a Node.js / Express monolith with a hand-rolled permission DSL: `canThis(user).edit.post(post)`. There's a `services/permissions/` module that builds those expressions out of role + privilege rows, but no externalized policy file — every authorization decision is embedded in JS. Tests how Zift handles a "framework of one" pattern.

## Target metadata

| | |
|---|---|
| Repo | [TryGhost/Ghost](https://github.com/TryGhost/Ghost) |
| Commit | `caca37de` |
| JS/TS files (excl. `node_modules`) | 3,942 |
| LOC | 517,452 |
| Externalized PaC | None — custom `canThis()` permission DSL |
| Zift version | 0.1.6 |

## Structural pass

```bash
zift scan ~/zift-corpus/js/Ghost --format json -o structural.json
```

| | |
|---|---|
| Wall time | 31.04s |
| Peak RSS | ~28 MB |
| Total findings | **32** |
| Files with findings | 18 |

**Findings per rule**

| Rule | Count |
|------|------:|
| `ts-jwt-token-check` | 31 |
| `ts-ownership-check` | 1 |

**Top findings (sample)**

| File | Line | Snippet |
|------|-----:|---------|
| `ghost/core/bin/generate-golden-email.js` | 48 | `jwt.sign({}, Buffer.from(apiKey.secret, 'hex'), {...})` |
| `ghost/core/.../scheduling/utils.js` | 73 | `jwt.sign({exp: tokenExpiry.unix(), nbf: ...})` |
| `ghost/core/.../endpoints/featurebase.js` | 20 | `jwt.sign(userData, config.get('featurebase:jwtSecret'), ...)` |
| `ghost/core/.../auth/api-key/admin.js` | 105 | `jwt.decode(token, {complete: true})` |
| `ghost/core/.../auth/api-key/admin.js` | 172 | `jwt.verify(token, secret, options)` |
| `ghost/core/.../members-api/services/token-service.js` | 20 | `jwt.sign({sub, kid: jwk.kid}, this._privateKey, ...)` |
| `ghost/core/.../importers/data/users-importer.js` | 71 | `attachedRole.user_id === obj.id` |

## Gaps & follow-ups

**FN: Ghost's permission DSL is invisible to the structural pass.**

```text
$ grep -rE 'canThis\(' --include='*.js' /path/to/Ghost/ghost/core/core/server | wc -l
10
```

`canThis(user).edit.post(post)` is the canonical authorization call shape across Ghost's server code. The structural ruleset doesn't surface any of these. Two fixes possible:

1. **Add a JS/TS rule for chained permission DSLs.** Match `canThis(...).<verb>.<resource>(...)` as a single tree-sitter pattern. This pattern shows up in other ecosystems too (CASL `ability.can(...)`, Pundit-style ports), so a generalized `chained-permission-call` rule pays off across many codebases.
2. **Generalize `permission-check-call` predicate.** The current TS `permission-check-call` regex misses `canThis` because it doesn't use a verb-prefix convention. Extending the regex to include `canThis|can|may|allow` as a bare name is a smaller change.

**FN: Express middleware not detected.**

Ghost mounts auth middleware via `app.use(auth.authenticate.authenticateApiKey)` and similar, but `ts-express-auth-middleware` and `ts-express-route-middleware` produced zero hits. Worth investigating — likely a predicate calibration issue (Ghost wraps middleware factories and the AST doesn't look like the canonical `app.use(authMiddleware)` shape).

**FP: `jwt-token-check` may be over-eager.**

31 of 32 findings are `jwt.sign / verify / decode`. Many of these are *token issuance* not *authorization decisions* (e.g. signing a Featurebase user-token for SSO has nothing to do with Ghost's authz model). Deep should down-rate the SSO-issuance cases. If deep consistently dismisses them, that's a signal to either lower the rule's confidence or split it into "decoding/verifying tokens for authz" vs "signing tokens for downstream services."

**FN: ownership patterns severely undercounted.**

One ownership match in 517k LOC of a multi-tenant publishing platform is implausible. The `===` ownership comparison is widespread (`post.author_id === user.id`, `member.id === req.member.id`); current rule's heuristic must be tightened. Confirm with deep.

## Deep pass

Run scoped to Ghost's permission engine itself — `ghost/core/core/server/services/permissions/` (5 files, ~500 LOC):

```bash
zift scan ~/zift-corpus/js/Ghost/ghost/core/core/server/services/permissions/ \
  --deep --agent-cmd "claude -p --output-format json" \
  --format json -o deep.json
```

| | |
|---|---|
| Transport | subprocess (`claude -p`) |
| Total findings | 5 (all semantic) |
| Structural findings (this subset) | 0 |
| Files with findings | 1 (`can-this.js`) |
| Cost reported | $0.00 |

**Deep-only findings — all in `can-this.js`:**

| Line | Category | Description |
|-----:|----------|-------------|
| 62 | rbac | Permission check matching `action_type` and `object_type` against user/API key permissions |
| 68 | ownership | Owner role bypass grants full user permission without checking permissions list |
| 77 | abac | API key vs user-context branching: staff-API-key uses user perms, traditional API key uses API key perms |
| 91 | business_rule | `TargetModel.permissible` hook lets the model override the authorization decision |
| 97 | custom | Final allow/deny: requires both user and API key permission, otherwise rejects with `NoPermissionError` |

This is the "deep finds what structural misses" story in concentrated form: structural patterns fire where authz is *called*; semantic analysis fires where authz is *defined*. `can-this.js` is the engine — no name pattern matches it — and deep correctly enumerates each of the five distinct authorization decisions inside one method.

## Diff structural ↔ deep

| Bucket | Count | Notes |
|--------|------:|-------|
| Both agree | 0 | Structural rules don't reach into the permission engine itself |
| Structural-only | 0 | No structural findings in this subset |
| Deep-only | 5 | Each maps to a distinct decision point in `can-this.js` |

The structural pass at the *whole-repo* level produced 32 findings (mostly `jwt-token-check` in unrelated files); deep scoped to the engine surfaces the actual policy authoring surface. To capture the broader gap on call sites (e.g. the `canThis(user).edit.post(post)` chain), we'd need either a new structural rule for chained permission DSLs or a wider deep pass over `ghost/core/core/server/api/`.
