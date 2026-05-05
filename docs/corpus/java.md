# Java — OpenMRS

Real-world results from running Zift against [openmrs/openmrs-core](https://github.com/openmrs/openmrs-core), the OpenMRS clinical platform.

## Why this target

OpenMRS is a 20-year-old electronic medical records platform with a custom authorization model — `Privilege` and `Role` domain objects, `Context.hasPrivilege("...")` calls scattered across services, and a homegrown `@Authorized` annotation interpreted by an AOP advisor. There is **no Spring Security expression language** and **no externalized PaC**: every authorization decision is embedded in service code or annotation arguments. That makes it a faithful test of how Zift handles authz that doesn't lean on a famous framework.

## Target metadata

| | |
|---|---|
| Repo | [openmrs/openmrs-core](https://github.com/openmrs/openmrs-core) |
| Commit | `a889bdee` |
| Java files | 1,273 |
| LOC (Java) | 264,206 |
| Externalized PaC | None observed |
| Zift version | 0.1.6 |

## Structural pass

```bash
zift scan ~/zift-corpus/java/openmrs-core --format json -o structural.json
```

| | |
|---|---|
| Peak RSS | ~24 MB |
| Total findings | **76** |
| Files with findings | 21 |
| Externalized % | 0% (no enforcement points emitted) |

**Findings per rule**

| Rule | Count |
|------|------:|
| `java-custom-authz-call` | 53 |
| `java-authenticated-check` | 12 |
| `java-has-role-call` | 9 |
| `java-role-equals-check` | 2 |

**Findings per category**

| Category | Count |
|----------|------:|
| `custom` | 53 |
| `middleware` | 12 |
| `rbac` | 11 |

**Top findings (sample)**

| File | Line | Snippet |
|------|-----:|---------|
| `api/.../org/openmrs/User.java` | 189 | `tmprole.hasPrivilege(privilege)` |
| `api/.../org/openmrs/User.java` | 204 | `hasRole(r, false)` |
| `api/.../org/openmrs/User.java` | 244 | `role.getRole().equalsIgnoreCase(roleName)` |
| `api/.../aop/AuthorizationAdvice.java` | 83 | `Context.hasPrivilege(privilege)` |
| `api/.../aop/AuthorizationAdvice.java` | 111 | `Context.isAuthenticated()` |
| `api/.../api/context/Context.java` | 729 | `getUserContext().hasPrivilege(privilege)` |
| `api/.../api/context/UserContext.java` | 397 | `isAuthenticated()` |
| `api/.../api/context/UserContext.java` | 398 | `getAuthenticatedUser().hasPrivilege(privilege)` |

The `custom-authz-call` heuristic catches `hasPrivilege` cleanly across the codebase.

## Gaps & follow-ups

**FN: `@Authorized` annotation (24 files affected, 0 findings).**
OpenMRS's primary policy surface is the custom `@Authorized({"Manage Users"})` annotation interpreted by `AuthorizationAdvice`. Zift currently has no rule for it. The Spring Security family of rules (`spring-secured`, `spring-roles-allowed`, `spring-preauthorize`) match annotation patterns but with different identifiers — extending `custom-authz-annotation.toml` (or generalizing the Spring rules to take a configurable annotation name) would close this gap.

**FN: heuristic limited to single-call surface.**
`Context.hasPrivilege(...)` and friends are caught, but constructor-style guard helpers like `requireAdmin(user)` or domain methods like `user.canManagePatients(patient)` would slip through unless their names happen to match the heuristic regex. Worth running deep against `api/src/main/java/org/openmrs/api/impl/` to see how many guard methods deep flags that structural misses.

**FP risk: low.** All 76 findings reviewed in the sample are genuine authorization sites. The `medium`-confidence label on `custom-authz-call` is well-calibrated for OpenMRS — every match is a real privilege check.

## Deep pass

Run scoped to OpenMRS's authentication / authorization core — `api/src/main/java/org/openmrs/api/context/` (12 files):

```bash
zift scan ~/zift-corpus/java/openmrs-core/api/src/main/java/org/openmrs/api/context/ \
  --deep --agent-cmd "claude -p --output-format json" \
  --format json -o deep.json
```

| | |
|---|---|
| Transport | subprocess (`claude -p`) |
| Wall time | ~2:30 |
| Total findings | 20 (6 structural retained + 14 semantic) |
| Files with findings | 3 (`Context.java`, `Daemon.java`, `UserContext.java`) |
| Cost reported | $0.00 |

**Notable deep-only findings:**

| File | Line | Category | Description |
|------|-----:|----------|-------------|
| `Context.java` | 333 | custom | `authenticate(...)` bypasses auth for daemon threads, returning `BasicAuthenticated` with the daemon user |
| `Context.java` | 375 | rbac | `becomeUser(systemId)` delegates impersonation to `UserContext`; Javadoc states only superusers should be able to do this — no enforcement in this method |
| `Context.java` | 678 | middleware | `isAuthenticated()` returns true unconditionally for daemon threads |
| `Context.java` | 724 | rbac | `hasPrivilege(...)` daemon-thread bypass: full access granted before any privilege check |
| `Daemon.java` | 80 | custom | Caller-class restriction: only `Daemon` or `ModuleFactory` may invoke `startModule` (stack-walker check) |
| `Daemon.java` | 256 | custom | Privilege guard: only daemon threads may spawn new daemon threads |
| `Daemon.java` | 336 | custom | Token-validation gate restricting execution to authenticated daemon callers |

The daemon-thread bypass is the most consequential finding: a real authorization decision point ("daemon threads have access to all things") that no name-based structural rule could reach. This is exactly the territory deep mode is built for.

## Diff structural ↔ deep

| Bucket | Count | Notes |
|--------|------:|-------|
| Both agree | 6 | Structural `hasPrivilege(...)` / `isAuthenticated()` matches retained alongside semantic findings |
| Structural-only | 0 | No structural FPs in this subset |
| Deep-only | 14 | Daemon-bypass family + `becomeUser` impersonation + token-validation gates + caller-class restriction |

The signal is loud: in OpenMRS's most safety-critical layer, deep finds **3× as much authz** as the structural pass. Most of the deep-only findings are not addressable by adding a single rule — they're behavioral patterns ("returns true unconditionally on daemon threads") that genuinely require semantic reasoning. The exception is `becomeUser` and `startModule` — caller-class restriction is a recognizable structural shape (a stack-walker check) that *could* be written as a rule if we see this pattern in other codebases.
