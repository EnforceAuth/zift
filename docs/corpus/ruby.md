# Ruby — Discourse

Real-world results from running Zift against [discourse/discourse](https://github.com/discourse/discourse), the open-source forum platform.

## Why this target

Discourse is the largest mature open-source Rails app in active use. It carries 10K+ Ruby files, deep controller hierarchies, and a hand-rolled `Guardian` authz layer that wraps Rails' `before_action` filter mechanism — so it exercises the Rails-side rules (`before_action`, `skip_before_action`) at scale and the Devise-style role-predicate rule (`current_user.staff?`, `current_user.admin?`) on a real privilege hierarchy. It does **not** use Pundit or CanCanCan, which makes it a useful contrast target: it confirms the Pundit/CanCanCan rules don't false-positive on Rails-flavored idioms that happen to share keywords.

## Target metadata

| | |
|---|---|
| Repo | [discourse/discourse](https://github.com/discourse/discourse) |
| Commit | `947c99ef` |
| Ruby files | 10,117 |
| LOC (`.rb`) | 1,103,264 |
| Externalized PaC | None observed |
| Zift version | 0.2.2 |

## Structural pass

```bash
zift scan ~/zift-corpus/ruby/discourse --language ruby --format json -o structural.json
```

| | |
|---|---|
| Wall time | 10.7s |
| Peak RSS | ~34 MB |
| Total findings | **339** |
| Files with findings | 172 |
| Externalized % | 0% (no policy-import enforcement points emitted) |
| Files skipped (policy-impl path) | 63 |

**Findings per rule**

| Rule | Count |
|------|------:|
| `ruby-rails-before-action-filter` | 180 |
| `ruby-current-user-role-predicate` | 159 |

**Findings per category**

| Category | Count |
|----------|------:|
| `middleware` | 180 |
| `rbac` | 159 |

**Top filter names (from `before_action` / `skip_before_action`)**

| Symbol | Count |
|--------|------:|
| `:check_xhr` | 74 |
| `:verify_authenticity_token` | 29 |
| `:ensure_logged_in` | 24 |
| `:ensure_admin` | 10 |
| `:ensure_staff` | 4 |
| `:check_permissions` | 2 |
| `:ensure_can_see` | 2 |

**Top role predicates (from `current_user.<role>?`)**

| Predicate | Approximate share |
|-----------|------:|
| `current_user.staff?` | majority |
| `current_user.admin?` | second |
| `current_user&.staff?` (safe-navigation) | also matched |

**Top findings (sample)**

| File | Line | Snippet |
|------|-----:|---------|
| `app/controllers/admin/admin_controller.rb` | 5 | `before_action :ensure_admin` |
| `app/controllers/admin/dashboard_controller.rb` | 13 | `current_user.admin?` |
| `app/controllers/application_controller.rb` | 758 | `current_user.staff?` |
| `app/controllers/application_controller.rb` | 762 | `current_user.admin?` |
| `app/controllers/groups_controller.rb` | 45 | `current_user&.staff?` |
| `app/controllers/admin/impersonate_controller.rb` | 4 | `skip_before_action :ensure_admin, only: :destroy` |
| `app/controllers/about_controller.rb` | 6 | `skip_before_action :check_xhr, only: [:index]` |

The two rules that did fire each surface a legitimate authz surface. `before_action` carries the privilege-gate logic for every admin and staff-only controller; the role-predicate rule catches Discourse's `current_user.staff?`-centric privilege model. Both rule categories show the expected high-confidence finding density on `app/controllers/admin/*` and `app/controllers/application_controller.rb` — Discourse's actual authz surface.

## Zero-coverage rules (intentional)

Seven Ruby rules contribute zero findings on Discourse — and that's correct:

| Rule | Why zero is expected |
|------|---------------------|
| `ruby-pundit-authorize` | Discourse doesn't use Pundit; it has its own `Guardian` |
| `ruby-pundit-policy-method` | Same |
| `ruby-pundit-policy-class` | Same — no `*Policy < ApplicationPolicy` shape in tree |
| `ruby-cancancan-can-declaration` | No CanCanCan in Discourse |
| `ruby-cancancan-can-check` | Same |
| `ruby-role-equals-check` | Discourse never spells RBAC as `user.role == "admin"` |
| `ruby-role-collection-include` | Privileges go through `Guardian`, not collection `.include?` |

The Pundit/CanCanCan rules are exercised by the inline rule tests (`cargo run -- rules test`) and need a Pundit-flavored or CanCanCan-flavored corpus target — a typical Rails-Pundit app — for end-to-end calibration. The Pundit sample suite (`varvet/pundit` test fixtures) lights up `ruby-pundit-policy-class` cleanly (18 findings, all in `spec/support/policies/`), confirming the class-declaration shape works as designed.

## Gaps & follow-ups

**FP risk: medium on framework filters.** `check_xhr` (74 hits) and `verify_authenticity_token` (29 hits) match `ruby-rails-before-action-filter` because the rule's filter-name regex includes `check_` and `verify_` prefixes. These are real Rails framework filters — `check_xhr` enforces XHR-only access on Discourse controllers; `verify_authenticity_token` is Rails' CSRF token check. Both *are* preconditions enforced via the controller filter mechanism, but a strict authz-vs-input-validation reader would dismiss them. The current breadth is deliberate (avoiding false negatives on hand-rolled `check_can_see`, `verify_user_active` etc.), but a narrower variant or a follow-up `not_match` predicate is worth filing once we see a second corpus target's filter inventory.

**Policy-implementation path skip is broader than intended.** The scanner's `is_policy_implementation_path` heuristic — shared with Java/Go/Python — silently skips files under any directory whose name contains a policy keyword. On Discourse that drops 63 files, including:

- 20 files under `plugins/discourse-policy/**` — a community plugin for *forum-style* policy acceptance posts, **not** an authz policy engine. These would otherwise be in scope for the consumer-side scan.
- ~6 files under `app/services/*/policy/*.rb` — Discourse's [`Service`](https://github.com/discourse/discourse/blob/main/lib/service/base.rb) result-pattern preconditions (`SettingsAreConfigurable`, `NotAlreadySilenced`). These are validators, not policy engines, but the path keyword causes the bypass.
- 4 files under `lib/content_security_policy/` and 1 under `spec/lib/content_security_policy/` — CSP header generation, not authz.

This is a known limitation of the shared keyword-bypass heuristic and a candidate for a Ruby-aware refinement: drop the bypass when the directory contains application code shapes (controllers, models) rather than implementation-side primitives. Tracked as a future rule-engine tweak.

**FN: Guardian call-site coverage.** Discourse's privilege checks largely go through `guardian.can_*?(...)` and `guardian.is_*?(...)` predicates (e.g. `guardian.can_see?(@topic)`, `guardian.is_admin?`). The current ruleset doesn't have a `guardian.*?` rule because Guardian is Discourse-specific — but the shape generalizes to any project that hand-rolls its own predicate-style authz wrapper. A follow-up rule targeting the `<receiver>.can_*?` / `<receiver>.is_*?` shape (gated by name regex to avoid `record.is_persisted?`-style noise) would convert a substantial chunk of Discourse's actual authz decisions to structural findings.

**FP risk: low on role predicates.** Every `current_user.<role>?` match here is a real RBAC decision. Discourse's privilege hierarchy (`staff` ⊃ `admin` ⊂ `moderator`) is exactly the kind of predicate-method idiom the rule was built for.

## Deep pass

Not run for this target. The structural pass yields a tight, high-signal slice of the privileged routes and role gates. Deep would primarily add value on the Guardian call sites flagged above (`guardian.can_*?`) — those are the gap to close before a deep pass adds new information.
