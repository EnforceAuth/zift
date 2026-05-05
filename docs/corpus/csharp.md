# C# — Bitwarden Server

Real-world results from running Zift against [bitwarden/server](https://github.com/bitwarden/server), Bitwarden's server-side application.

## Why this target

Bitwarden is a production ASP.NET Core codebase with a mature authorization model. It uses controller attributes, policy names, anonymous endpoint overrides, and resource-based checks through `IAuthorizationService`. That makes it a strong first C# corpus target: it exercises framework-level middleware and service-layer authorization, not just toy `[Authorize]` examples.

## Target metadata

| | |
|---|---|
| Repo | [bitwarden/server](https://github.com/bitwarden/server) |
| Commit | `99923132` |
| C# files (excl. `bin/`, `obj/`) | 4,534 |
| LOC (C#) | 1,540,794 |
| Externalized PaC | None observed |
| Zift version | 0.1.9 |

## Structural pass

```bash
zift scan ~/zift-corpus/csharp/server --format json -o structural.json
```

| | |
|---|---|
| Wall time | 111.35s |
| Peak RSS | ~32 MB |
| Total findings | **318** |
| Files with findings | 116 |
| Externalized % | 0% (no policy-import enforcement points emitted) |

The full-repo result includes tests because the corpus methodology scans the shallow clone as-is. Production paths account for 172 findings under `src/` plus 4 under `bitwarden_license/src/`; tests account for 143 findings.

**Findings per rule**

| Rule | Count |
|------|------:|
| `csharp-authorization-service-authorize-async` | 186 |
| `csharp-aspnet-authorize-policy-shorthand` | 82 |
| `csharp-aspnet-allow-anonymous` | 34 |
| `csharp-aspnet-authorize-attribute` | 16 |

**Findings per category**

| Category | Count |
|----------|------:|
| `abac` | 268 |
| `middleware` | 50 |

**Top findings (sample)**

| File | Line | Snippet |
|------|-----:|---------|
| `src/Api/AdminConsole/Controllers/CollectionsController.cs` | 23 | `Authorize("Application")` |
| `src/Api/AdminConsole/Controllers/CollectionsController.cs` | 62 | `_authorizationService.AuthorizeAsync(User, collection, BulkCollectionOperations.Read)` |
| `src/Api/AdminConsole/Controllers/CollectionsController.cs` | 118 | `_authorizationService.AuthorizeAsync(User, CollectionOperations.ReadAll(orgId))` |
| `src/Api/AdminConsole/Controllers/GroupsController.cs` | 23 | `Authorize("Application")` |
| `src/Api/AdminConsole/Controllers/GroupsController.cs` | 134 | `_authorizationService.AuthorizeAsync(User, collections, BulkCollectionOperations.ModifyGroupAccess)` |
| `src/Api/AdminConsole/Controllers/OrganizationUsersController.cs` | 206 | `_authorizationService.AuthorizeAsync(User, new ManageUsersRequirement())` |
| `src/Api/Controllers/DevicesController.cs` | 243 | `AllowAnonymous` |
| `src/Admin/Controllers/UsersController.cs` | 19 | `Authorize` |

## Gaps & follow-ups

**FN: generic Bitwarden authorization attributes.**

Bitwarden uses a custom generic attribute form extensively:

```csharp
[Authorize<ManageUsersRequirement>]
```

A quick grep found 108 `Authorize<TRequirement>` occurrences in the shallow clone. The current C# rules catch the ASP.NET built-in `[Authorize]`, `[Authorize("Policy")]`, `[Authorize(Policy = "...")]`, and `[Authorize(Roles = "...")]` shapes, but not the generic Bitwarden helper. A dedicated `csharp-bitwarden-authorize-requirement` rule, or a more general generic-attribute rule, would close a large chunk of structural coverage.

**FN: `AuthorizeOrThrowAsync`.**

Bitwarden wraps authorization in `AuthorizeOrThrowAsync(...)` at command/service boundaries. A grep found 21 occurrences. The current `AuthorizeAsync` rule catches the standard ASP.NET method name but misses this wrapper. This is a good candidate for either widening the method predicate or adding a separate high-confidence C# rule.

**FN: policy-builder lambdas.**

Startup code contains policy assertions such as `policy.RequireAssertion(ctx => ctx.User.HasClaim(...))`. The direct `HasClaim(...)` call shape can be detected, but policy-builder context and lambda-based registration deserve their own rule if they show up across more ASP.NET projects.

**FP risk: low for the main structural hits.** The sampled `AuthorizeAsync`, `[Authorize("Application")]`, and `[AllowAnonymous]` findings are real authorization sites. Test files add noise to the whole-repo total, but they are still useful for rule-shape validation because they exercise the same authorization APIs through mocks and assertions.

## Deep pass

Run scoped to the Admin Console controllers — 14 C# files, ~3,400 LOC, concentrated around organization and collection management:

```bash
zift scan ~/zift-corpus/csharp/server/src/Api/AdminConsole/Controllers/ \
  --deep --agent-cmd "claude -p --output-format json" \
  --format json -o deep.json
```

| | |
|---|---|
| Transport | subprocess (`claude -p --output-format json`) |
| Wall time | 177.98s |
| Total findings | 88 (29 structural retained + 59 semantic) |
| Files with findings | 13 |
| Cost reported | $0.00 |

One candidate was skipped because the agent returned non-JSON for that prompt; Zift treated it as a per-candidate bad response and continued.

**Findings by pass**

| Pass | Count |
|------|------:|
| `semantic` | 59 |
| `structural` | 29 |

**Deep findings by category**

| Category | Count |
|----------|------:|
| `custom` | 23 |
| `middleware` | 22 |
| `ownership` | 5 |
| `abac` | 3 |
| `feature_gate` | 3 |
| `rbac` | 2 |
| `business_rule` | 1 |

**Notable deep-only findings**

| File | Line | Category | Description |
|------|-----:|----------|-------------|
| `GroupsController.cs` | 68 | middleware | `[Authorize<ManageGroupsRequirement>]` gates the endpoint |
| `GroupsController.cs` | 232 | ownership | `group.OrganizationId != orgId` tenant ownership check |
| `GroupsController.cs` | 254 | ownership | Bulk delete validates every group's `OrganizationId` |
| `OrganizationConnectionsController.cs` | 60 | custom | `HasPermissionAsync(...)` gates connection creation |
| `OrganizationConnectionsController.cs` | 178 | rbac | `HasPermissionAsync` chooses `ManageScim` vs `OrganizationOwner` |
| `OrganizationInviteLinksController.cs` | 15 | feature_gate | `[RequireFeature(FeatureFlagKeys.GenerateInviteLink)]` gates the controller |

## Diff structural ↔ deep

The subset had 36 structural findings in the whole-repo structural report. The deep run retained 29 structural findings and added 59 semantic findings.

| Bucket | Count | Notes |
|--------|------:|-------|
| Structural retained | 29 | Mostly `AuthorizeAsync`, `[Authorize("Application")]`, and `[AllowAnonymous]` |
| Deep-only | 59 | Generic authorization attributes, tenant ownership checks, helper gates, and feature flags |
| Structural not retained | 7 | Mostly lower-context structural candidates that deep did not echo back, plus one skipped malformed agent response |

The biggest actionable rule gap is the generic attribute family. In this subset alone, deep surfaced 19 `[Authorize<TRequirement>]` findings; across the full shallow clone, grep found 108 occurrences.
