# PHP — Monica + Symfony demo

Real-world results from running Zift against two open-source PHP codebases: [monicahq/monica](https://github.com/monicahq/monica) (Laravel) and [symfony/demo](https://github.com/symfony/demo) (Symfony). The pair is intentional — neither framework appears in the other's authz idioms, so they calibrate the Laravel and Symfony rule families independently.

## Why these targets

Monica is one of the largest mature open-source Laravel apps in active use (CRM/contact manager). It uses Laravel Gates *and* Policies *and* `Route::middleware('can:…')` simultaneously — so every Laravel rule has a real target to fire against, with no Spatie permissions plugin in the way to muddy the signal. The Symfony demo is the official example app maintained by the Symfony team; it's small but exercises the modern PHP 8 attribute syntax (`#[IsGranted]`), the docblock-free Voter idiom, and `denyAccessUnlessGranted` — every Symfony rule has a hit.

The pair confirms two things: that the Laravel rules don't fire on Symfony code (and vice versa), and that the Symfony attribute rule survives the PHP 8 `name: 'value'` argument shape without false positives on neighbouring attributes (`#[Route]`, `#[Cache]`, …).

## Target metadata

### Monica (Laravel)

| | |
|---|---|
| Repo | [monicahq/monica](https://github.com/monicahq/monica) |
| Commit | `e08e917` |
| PHP files (excl. `vendor/`) | 1,656 |
| LOC (`.php`, excl. `vendor/`) | 134,702 |
| Externalized PaC | None observed |
| Zift version | 0.2.2 |

### Symfony demo

| | |
|---|---|
| Repo | [symfony/demo](https://github.com/symfony/demo) |
| Commit | `83d4ac1` |
| PHP files (excl. `vendor/`) | 52 |
| LOC (`.php`, excl. `vendor/`) | 6,256 |
| Externalized PaC | None observed |
| Zift version | 0.2.2 |

## Structural pass — Monica

```bash
zift scan ~/zift-corpus/php/monica --language php --format json -o structural.json
```

| | |
|---|---|
| Wall time | 1.4s |
| Total findings | **41** |
| Files with findings | 13 |
| Externalized % | 0% (no policy-import enforcement points emitted) |

**Findings per rule**

| Rule | Count |
|------|------:|
| `php-laravel-route-middleware` | 13 |
| `php-laravel-gate-define` | 11 |
| `php-laravel-gate-allows-denies` | 7 |
| `php-laravel-authorize-helper` | 5 |
| `php-laravel-policy-class` | 5 |

**Findings per category**

| Category | Count |
|----------|------:|
| `rbac` | 28 |
| `middleware` | 13 |

**Top findings (sample)**

| File | Line | Snippet |
|------|-----:|---------|
| `app/Providers/AuthServiceProvider.php` | 32 | `Gate::define('administrator', function (User $user): bool { … })` |
| `app/Providers/AuthServiceProvider.php` | 42 | `Gate::define('vault-editor', function (User $user, $vault): bool { … })` |
| `app/Policies/VaultPolicy.php` | 22 | `public function view(User $user, Vault $vault): bool { … }` |
| `app/Policies/VaultPolicy.php` | 46 | `public function update(User $user, Vault $vault): bool { … }` |
| `app/Domains/Vault/ManageVault/Api/Controllers/VaultController.php` | 23 | `$this->middleware('abilities:read')` |
| `app/Domains/Contact/ManageContact/Web/Controllers/ContactController.php` | 57 | `Gate::authorize('vault-editor', $vault)` |
| `routes/web.php` | 199 | `Route::middleware('can:vault-viewer,vault')` |
| `routes/web.php` | 250 | `Route::middleware('can:contact-owner,vault,contact')` |

The shape lines up exactly with how Monica's authz is laid out: a single `AuthServiceProvider::boot()` declares the ability vocabulary (11 `Gate::define`s — `administrator`, `vault-editor`, `vault-viewer`, `vault-manager`, `contact-owner`, …), the controllers call `Gate::authorize('vault-editor', …)` per request, and `routes/web.php` attaches `can:<ability>,<resource>` middleware to grouped route trees. `VaultPolicy` carries the CRUD method shape the policy-class rule was designed for. Five `php-laravel-authorize-helper` matches in `tests/Feature/Auth/*` are real `$token->can('read')` calls in test fixtures — they're authz state assertions in tests, which is the right behaviour for the rule.

## Structural pass — Symfony demo

```bash
zift scan ~/zift-corpus/php/demo --language php --format json -o structural.json
```

| | |
|---|---|
| Wall time | 0.08s |
| Total findings | **4** |
| Files with findings | 3 |
| Externalized % | 0% |

**Findings per rule**

| Rule | Count |
|------|------:|
| `php-symfony-is-granted-attribute` | 3 |
| `php-symfony-voter-class` | 1 |

**All findings**

| File | Line | Snippet |
|------|-----:|---------|
| `src/Controller/Admin/BlogController.php` | 138 | `IsGranted('edit', subject: 'post', message: 'Posts can only be edited by their authors.')` |
| `src/Controller/Admin/BlogController.php` | 161 | `IsGranted('delete', subject: 'post')` |
| `src/Controller/BlogController.php` | 107 | `IsGranted('IS_AUTHENTICATED')` |
| `src/Security/PostVoter.php` | 30 | `final class PostVoter extends Voter { … }` |

Every Symfony idiom the demo uses gets exactly one hit per call site. `PostVoter` is the canonical Symfony Voter shape — class extends the framework `Voter` parent. The three `#[IsGranted]` attributes cover the PHP 8 attribute form including the named-argument syntax (`subject: 'post'`, `message: '…'`); the anchor in the rule's query keeps the captured `@role` pinned to the first positional argument so the downstream Rego template emits `IS_AUTHENTICATED` / `edit` / `delete` and not the message string.

## Zero-coverage rules (intentional)

Six rules fired zero findings across both targets — and that's correct:

| Rule | Monica | Symfony demo | Why zero is expected |
|------|------:|------:|---------------------|
| `php-symfony-voter-class` | 0 | 1 | Laravel doesn't use Voters; Symfony does. |
| `php-symfony-is-granted` | 0 | 0 | Symfony demo uses `#[IsGranted]` attributes exclusively; `$this->denyAccessUnlessGranted(…)` does appear in `BlogController.php:127` but its first positional argument is `PostVoter::SHOW` (a class constant ref), which the rule deliberately doesn't capture — see [Gaps & follow-ups](#gaps--follow-ups). |
| `php-symfony-is-granted-attribute` | 0 | 3 | Laravel/Monica isn't on Symfony's attribute family. |
| `php-role-equals-check` | 0 | 0 | Neither codebase spells RBAC as `$user->role === 'admin'` — both use Gates/Voters. |
| `php-in-array-role-check` | 0 | 0 | Same — neither hand-rolls `in_array('manager', $user->roles)`. |
| `php-has-role-call` | 0 | 0 | Neither pulls in spatie/laravel-permission, so `$user->hasRole(…)` doesn't appear. |

The three idiomatic rules (`role-equals-check`, `in-array-role-check`, `has-role-call`) are exercised by the inline rule tests (`cargo run -- rules test`) and need a hand-rolled-authz Laravel app or a Spatie-flavoured target for end-to-end calibration.

## Gaps & follow-ups

**Constant-ref first argument is intentionally dropped.** Symfony's `denyAccessUnlessGranted(PostVoter::SHOW, $post, …)` in `BlogController.php:127` *is* an authz call, but the first positional argument is a class constant (`PostVoter::SHOW`) — Zift can't resolve it to a literal at scan time, so the rule's anchor lets the call slip through structurally rather than fabricate a Rego template against the trailing message string. The trade-off here is a known FN on `<Voter>::CONSTANT`-shaped calls in exchange for honest output on the calls that *do* expose a literal. A follow-up could either widen the capture (record the constant ref textually as `@attribute` and let the template TODO-out the value) or pair the structural miss with a deep-pass rule. Tracked as a future ruleset refinement.

**`Gate::authorize` lives under the `allows`/`denies` rule.** Laravel ships `Gate::authorize($ability, $resource)` as a fourth verb alongside `allows`/`denies`/`check`. The rule's `method_name` regex includes it, so all seven `Gate::authorize('vault-editor', …)` calls in Monica land in `php-laravel-gate-allows-denies` rather than a dedicated rule. The category is correct (`rbac`); the verbosity is the only cost. Worth splitting only if downstream consumers need to bucket "decision boundaries" (`allows`/`denies`) separately from "imperative throws" (`authorize`) for reporting.

**`$this->middleware(…)` works inside controller constructors.** Monica uses both `Route::middleware(…)` at the route-tree level and `$this->middleware('abilities:read')` inside `__construct` of API controllers (e.g. `VaultController.php:23`). Both surface here because the rule matches any call literally named `middleware` whose argument list looks like an auth alias — the receiver isn't constrained. This is the right call for Laravel where both shapes are idiomatic, but worth pinning if a Lumen/Slim-flavoured corpus target later turns up other libraries that expose a same-named no-op.

**FP risk: low across the board.** Every match on both targets is a real authz surface. No false positives observed; the rule-level predicates (method-name regex, scope check, arg-shape constraints) carry the load. The one rule that survives both targets without firing — `php-role-equals-check` — would benefit from a corpus target that genuinely uses the `$user->role === 'admin'` shape to confirm the predicate breadth on the property name (`role|roles|user_role|account_type|user_type|permission|permissions`) is calibrated correctly.

## Deep pass

Not run for either target. Monica's structural pass yields a tight, high-signal slice of the privileged routes, gate definitions, and policy methods; Symfony demo is small enough that the structural pass essentially exhausts the visible authz surface. Deep would primarily add value on the parts of Monica's `Service` layer that wrap authz inside business logic without a Gate call — those are the gap to investigate first if a deep pass is run later.
