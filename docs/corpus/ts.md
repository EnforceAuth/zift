# TypeScript — Cal.com

Real-world results from running Zift against [calcom/cal.com](https://github.com/calcom/cal.com), the open-source scheduling platform.

## Why this target

Cal.com is a Turborepo with two API surfaces — a Next.js app and a NestJS v2 API — plus a sprawling `packages/lib` of shared business logic. Authorization is everywhere: NestJS guards on every controller method (`@UseGuards(ApiAuthGuard, OrganizationRolesGuard, ...)`), Prisma-backed team / org / seat checks throughout `packages/lib/server`, and the usual JWT plumbing for sessions. No externalized PaC. Good monorepo + framework-decorator stress test.

## Target metadata

| | |
|---|---|
| Repo | [calcom/cal.com](https://github.com/calcom/cal.com) |
| Commit | `46eb533d` |
| TS/TSX files (excl. `node_modules`, `.next`) | 5,018 |
| LOC | 547,210 |
| Externalized PaC | None observed |
| Zift version | 0.1.6 |

## Structural pass

```bash
zift scan ~/zift-corpus/ts/cal.com --format json -o structural.json
```

| | |
|---|---|
| Wall time | 51.47s |
| Peak RSS | ~26 MB |
| Total findings | **166** |
| Files with findings | 64 |

**Findings per rule**

| Rule | Count |
|------|------:|
| `ts-nestjs-use-guards` | 123 |
| `ts-ownership-check` | 29 |
| `ts-jwt-token-check` | 6 |
| `ts-permission-check-call` | 4 |
| `ts-role-check-conditional` | 3 |
| `ts-express-auth-middleware` | 1 |

**Findings per category**

| Category | Count |
|----------|------:|
| `middleware` | 130 |
| `ownership` | 29 |
| `abac` | 4 |
| `rbac` | 3 |

**Top findings (sample)**

| File | Line | Snippet |
|------|-----:|---------|
| `apps/api/v2/.../api-keys/controllers/api-keys.controller.ts` | 18 | `@UseGuards(ApiAuthGuard)` |
| `apps/api/v2/.../atoms/controllers/atoms.event-types.controller.ts` | 46 | `@UseGuards(ApiAuthGuard)` |
| `apps/api/v2/.../atoms/controllers/atoms.event-types.controller.ts` | 78 | `@UseGuards(ApiAuthGuard)` |
| `apps/api/v2/.../atoms/controllers/atoms.event-types.controller.ts` | 92 | `@UseGuards(ApiAuthGuard)` |
| `apps/api/v2/.../atoms/controllers/atoms.schedules.controller.ts` | 56 | `@UseGuards(ApiAuthGuard)` |

## Gaps & follow-ups

**Calibration win: `ts-nestjs-use-guards` carries the report.** 123 of 166 findings (74%) come from one rule and they are all genuine. Confidence is `high` and deep should confirm.

**FN: Next.js `app/` route handlers and `getServerSession` checks.**

The bulk of Cal.com's web traffic flows through Next.js route handlers in `apps/web/app/api/`, where authorization usually looks like:

```ts
const session = await getServerSession(authOptions);
if (!session?.user) return new Response("Unauthorized", { status: 401 });
if (session.user.role !== "ADMIN") return new Response("Forbidden", { status: 403 });
```

Zero findings from the Next.js handler tree. Two issues:

- `ts-session-auth-check` evidently doesn't match the `getServerSession(...)` shape.
- The role-check pattern (`session.user.role !== "ADMIN"`) should fire `ts-role-check-conditional` but doesn't — the rule probably expects a bare `role` identifier, not a member access path.

Both are predicate-tightening fixes, not new rules.

**FN: tRPC procedures.**

Cal.com's web app uses tRPC heavily. Procedures like `protectedProcedure` and middleware like `isAdminMiddleware` are first-class authorization gates and produce **zero** Zift findings. Adding a `ts-trpc-protected-procedure` rule would pick up a popular framework with the same effort cost as the NestJS rules.

**FN: team / org membership checks.**

`packages/lib/server/queries/teams/...` is full of `userBelongsToTeam(userId, teamId)`, `isTeamAdmin(userId, teamId)` calls. None match. Same problem as Gitea — `permission-check-call` predicate is too narrow. Extending with `belongsTo|isTeamAdmin|isOrgOwner|hasMembership` would help.

**Monorepo handling: works.** Single-pass scan over the turborepo root produces sensible per-file findings. No path mangling, no double-counting.

**FP risk: low.** All sampled `@UseGuards` and ownership findings are genuine.

## Deep pass

Run scoped to Cal.com's NestJS auth module — `apps/api/v2/src/modules/auth/` (38 files, ~3,000 LOC of guards / strategies / decorators):

```bash
zift scan ~/zift-corpus/ts/cal.com/apps/api/v2/src/modules/auth/ \
  --deep --agent-cmd "claude -p --output-format json" \
  --format json -o deep.json
```

| | |
|---|---|
| Transport | subprocess (`claude -p`) |
| Wall time | ~3:14 |
| Total findings | 30 (1 structural retained + 29 semantic) |
| Files with findings | 7 |
| Cost reported | $0.00 |

**Findings per category**

| Category | Count |
|----------|------:|
| `rbac` | 12 |
| `middleware` | 11 |
| `ownership` | 4 |
| `business_rule` | 1 |
| `custom` | 1 |
| `feature_gate` | 1 |

**Notable deep-only findings — bypass and permissive-stub patterns:**

| File | Line | Category | Description |
|------|-----:|----------|-------------|
| `pbac.guard.ts` | 9 | middleware | PBAC guard is a **permissive stub that always returns true** — marks the request as not pbac-authorized but lets it through |
| `permissions.guard.ts` | 30 | middleware | **Skip authorization when the handler declares no required permissions** |
| `permissions.guard.ts` | 42 | middleware | **Bypasses permission enforcement for next-auth sessions, API keys, and third-party OAuth bearer tokens** |
| `or.guard.ts` | 9 | middleware | `Or()` factory: OR-combinator that grants access if any composed guard returns true |
| `optional-api-auth.guard.ts` | 8 | middleware | Optional API auth guard that allows unauthenticated requests through |
| `permissions.guard.ts` | 28 | rbac | Reads `Permissions` decorator metadata to determine required permissions |

The PBAC permissive-stub finding is the most interesting: a guard that's wired into routes via NestJS's standard mechanism but doesn't actually enforce anything. Structural rules would happily flag the `@UseGuards(PbacGuard)` annotation as a finding (and they do — that's the structural pass's job). But only deep can read the guard's body and tell you the guard itself is a no-op. That's exactly the kind of "looks like authz, isn't" that a security reviewer wants to know about.

## Diff structural ↔ deep

| Bucket | Count | Notes |
|--------|------:|-------|
| Both agree | 1 | One `@UseGuards(...)` annotation match retained from structural |
| Structural-only | 0 | No structural FPs in this subset |
| Deep-only | 29 | The full guard / strategy implementation surface, plus the bypass patterns above |

The whole-repo structural pass produced 166 findings; this 38-file deep slice produced 30 more semantic findings concentrated in the *implementation* of those guards — the engine, not the call sites, mirroring the Ghost pattern. Combining them gives a fuller security picture than either pass alone.
