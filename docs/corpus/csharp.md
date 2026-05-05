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

Not run for this PR. C# support landed after the initial corpus shakedown, so this page records the reproducible structural baseline first. A useful scoped deep pass would target:

```bash
zift scan ~/zift-corpus/csharp/server/src/Api/AdminConsole/Controllers/ \
  --deep --agent-cmd "claude -p --output-format json" \
  --format json -o deep.json
```

That subset concentrates the `IAuthorizationService.AuthorizeAsync(...)`, custom generic `[Authorize<TRequirement>]`, and organization-management authorization model in one place.
