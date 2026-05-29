# Kotlin — Ktor Samples

Real-world results from running Zift against [ktorio/ktor-samples](https://github.com/ktorio/ktor-samples), the canonical Ktor sample apps maintained by JetBrains.

## Why this target

Ktor is the dominant Kotlin-native server framework, and `ktor-samples` is the corpus the Ktor team itself uses to demo and regression-test the framework's authentication, sessions, and routing DSLs. It exercises every Ktor auth shape Zift's structural pass aims at: `install(Authentication) { ... }` plugin registration with `jwt`, `basic`, `digest`, `oauth`, and `bearer` providers; `authenticate("name") { ... }` route guards (named and no-args); `install(Sessions)` cookie-backed sessions. There is no Spring Security here and no idiomatic role-comparison code — this target stresses the **Ktor side** of v0.2's Kotlin rule set, leaving the Spring-Kotlin rules to be exercised against future targets.

## Target metadata

| | |
|---|---|
| Repo | [ktorio/ktor-samples](https://github.com/ktorio/ktor-samples) |
| Commit | `c89f051e` |
| Kotlin files (`.kt` + `.kts`) | 204 |
| LOC (`.kt`) | 12,254 |
| Externalized PaC | None observed |

## Structural pass

```bash
zift scan ~/zift-corpus/kotlin/ktor-samples --format json -o structural.json
```

| | |
|---|---|
| Wall time | 0.96s |
| Peak RSS | ~54 MB |
| Total findings | **13** |
| Files with findings | 8 |
| Externalized % | 0% (no policy-import enforcement points emitted) |

**Findings per rule**

| Rule | Count |
|------|------:|
| `kotlin-ktor-authenticate-block` | 7 |
| `kotlin-ktor-install-authentication` | 6 |

**Findings per category**

| Category | Count |
|----------|------:|
| `middleware` | 13 |

**Top findings (sample)**

| File | Line | Snippet |
|------|-----:|---------|
| `httpbin/.../httpbin/Auth.kt` | 15 | `authenticate("basic")` |
| `httpbin/.../httpbin/Auth.kt` | 38 | `authenticate("bearer")` |
| `httpbin/.../httpbin/Auth.kt` | 61 | `authenticate("digest")` |
| `httpbin/.../httpbin/Server.kt` | 108 | `install(Authentication)` |
| `jwt-auth-tests/.../jwtauth/Main.kt` | 54 | `install(Authentication)` |
| `jwt-auth-tests/.../jwtauth/Main.kt` | 90 | `authenticate("auth-jwt")` |
| `openapi/.../Routing.kt` | 13 | `authenticate("auth-oauth-google")` |
| `kweet/.../kweet/KweetApplication.kt` | 145 | `install(Sessions)` |

The Ktor rules pick up every named-authenticator route guard cleanly and the entire `install(Authentication | Sessions)` family across the sample tree.

## Gaps & follow-ups

**Expected zero spring-kotlin findings.** Ktor samples don't use Spring Security, so the `kotlin-spring-preauthorize`, `kotlin-spring-secured`, `kotlin-roles-allowed`, `kotlin-has-role-call`, `kotlin-role-equals-check`, and `kotlin-role-collection-contains` rules contribute nothing here. They're exercised by the inline rule tests (`cargo run -- rules test`) and need a different corpus target — a real Spring-Boot-Kotlin codebase — for end-to-end calibration.

**FP risk: low.** Every match is a real Ktor auth surface. The `install(Sessions)` matches are deliberate — Ktor sessions back authentication state in nearly every sample that uses them, and the rule's `Authentication | Authorization | Sessions` predicate is calibrated to keep them in scope.

**Coverage caveat.** `ktor-samples` is intentionally minimal — the `httpbin` and `jwt-auth-tests` modules carry most of the auth surface area. The 13 findings here are not a stress test of Kotlin scale, just of Ktor pattern coverage. A larger Kotlin corpus target (e.g., a real Spring-Kotlin service) would be the natural next addition for v0.2.x.

## Deep pass

Not run for this target. The structural pass cleanly enumerates the Ktor auth surface; deep would primarily add noise on the credential-validator lambdas (`validate { credentials -> ... }`) that the structural pass already attributes to their enclosing `authenticate { ... }` block.
