# Python — Zulip

Real-world results from running Zift against [zulip/zulip](https://github.com/zulip/zulip), the open-source team chat platform.

## Why this target

Zulip is a 12-year-old Django monolith with a sprawling permission model — `Realm`, `UserProfile`, group-based permissions, and per-stream / per-message authz. Authorization decisions are spread across `zerver/views/`, `zerver/lib/`, and `zerver/decorator.py`. The newer `has_permission("can_*_group")` API is gradually replacing direct role attribute checks. No externalized PaC.

## Target metadata

| | |
|---|---|
| Repo | [zulip/zulip](https://github.com/zulip/zulip) |
| Commit | `130cc7b9` |
| Python files | 2,002 |
| LOC (Python) | 412,996 |
| Externalized PaC | None observed |
| Zift version | 0.1.6 |

## Structural pass

```bash
zift scan ~/zift-corpus/python/zulip --format json -o structural.json
```

| | |
|---|---|
| Peak RSS | ~26 MB |
| Total findings | **39** |
| Files with findings | 17 |

**Findings per rule**

| Rule | Count |
|------|------:|
| `py-permission-check-call` | 23 |
| `ts-ownership-check` | 15 |
| `py-ownership-check` | 1 |

The 15 TS hits come from Zulip's `web/src/` frontend — that's correct routing across the mixed-language repo, not a bug.

**Top Python findings (sample)**

| File | Line | Snippet |
|------|-----:|---------|
| `zerver/lib/events.py` | 1624 | `user_profile.has_permission("can_invite_users_group")` |
| `zerver/lib/message.py` | 1496 | `sender.has_permission("can_mention_many_users_group")` |
| `zerver/models/users.py` | 812 | `self.has_permission("can_manage_billing_group")` |
| `zerver/models/users.py` | 860 | `self.has_permission("can_create_bots_group")` |
| `zerver/models/users.py` | 897 | `self.has_permission("can_create_public_channel_group", realm)` |
| `zerver/models/users.py` | 911 | `self.has_permission("can_add_subscribers_group")` |

Every Python match is a genuine `has_permission(...)` group-based authz call. Calibration is good.

## Gaps & follow-ups

**FN: Zulip's older `is_realm_admin` / `is_realm_owner` patterns are missed.**

Direct attribute checks like `if user_profile.is_realm_admin:` or `if not user_profile.is_realm_owner: raise JsonableError(...)` are widespread but produce zero structural findings. The `py-role-check-conditional` rule expects something like `role == "admin"`; Zulip never spells it that way. A predicate widening (or a Zulip-flavored heuristic for `is_realm_*` attribute access in conditionals) would close this gap.

**FN: `@require_*` decorators not detected.**

`zerver/decorator.py` exports a family of authorization decorators — `require_realm_admin`, `require_organization_member`, `require_member_or_admin`, `require_billing_access`, `require_post_params` — applied to view functions throughout `zerver/views/`. These are exactly the kind of framework-decorator pattern Zift's Java rules handle (`@Secured`, `@PreAuthorize`, `@RolesAllowed`), but the Python ruleset has no `py-require-decorator` analogue. Adding one would jump Zulip's finding count by an order of magnitude.

**FN: `do_check_*` / `check_can_*` helper family.**

Zulip wraps most authorization decisions in `check_can_invite_users(user_profile, ...)`, `check_basic_stream_access(...)`, `check_message_edit_access(...)` etc. These are the actual policy decision points. None match `py-permission-check-call`'s predicate. Heuristic could be widened to include `^check_(can_|access_|edit_)` prefixes.

**FP risk: low.** The 23 Python matches are all legitimate. The frontend TS ownership checks may be over-counted (UI state, not security gates) — deep should down-rate those.

## Deep pass

Run scoped to two high-yield files: `zerver/decorator.py` (1,101 LOC of authorization decorators) and `zerver/lib/users.py` (1,205 LOC of user / realm helpers).

```bash
zift scan ~/zift-corpus/python/zulip/zerver/decorator.py \
  --deep --agent-cmd "claude -p --output-format json" \
  --format json -o decorator-deep.json

zift scan ~/zift-corpus/python/zulip/zerver/lib/users.py \
  --deep --agent-cmd "claude -p --output-format json" \
  --format json -o users-deep.json
```

### `zerver/decorator.py`

| | |
|---|---|
| Total findings | 25 (all semantic) |
| Cost reported | $0.00 |
| Notes | One candidate at line 746 produced an unparseable agent response and was skipped — the scanner logged a `WARN` and continued. No fatal failures. |

**Findings per category**

| Category | Count |
|----------|------:|
| `middleware` | 14 |
| `abac` | 5 |
| `rbac` | 3 |
| `custom` | 2 |
| `feature_gate` | 1 |

**Notable deep-only findings:**

| Line | Category | Description |
|-----:|----------|-------------|
| 271 | abac | Webhook bot users are denied API access unless `allow_webhook_access` is set |
| 281 | feature_gate | Access denied when the user's realm (tenant) is deactivated |
| 283 | abac | Access denied when the user account is not active |
| 482 | abac | `logged_in_and_active` predicate gates on user-active state, realm deactivation, subdomain match |
| 510 | custom | Dummy-backend re-authentication gate before login proceeds |
| 560 | middleware | `human_users_only` decorator blocks bot accounts from the wrapped view |
| 577 | middleware | `zulip_login_required` decorator gates view access on `logged_in_and_active` via Django's `user_passes_test` |

The 14 `middleware` findings are exactly the `@require_*` / `@zulip_login_required` / `@human_users_only` decorator family the Python ruleset doesn't currently match. **Adding a `py-require-decorator` rule would convert this entire batch into structural findings** — see [follow-up #6](../../plans/todo/05-corpus-shakedown-followups.md).

### `zerver/lib/users.py`

| | |
|---|---|
| Total findings | 3 (all semantic) |
| Cost reported | $0.00 |

**Findings**

| Line | Category | Description |
|-----:|----------|-------------|
| 625 | abac | `can_access_delivery_email(acting_user, target_id, visibility)` gates email visibility |
| 643 | feature_gate | Spectators (`acting_user is None`) receive only day-level `date_joined` precision |
| 653 | feature_gate | Strip timezone field from response when `acting_user is None` (spectator) |

These are spectator-vs-authenticated visibility gates — pure semantic territory; no name pattern would catch them.

## Diff structural ↔ deep

| Bucket | decorator.py | lib/users.py | Notes |
|--------|-------------:|-------------:|-------|
| Both agree | 0 | 0 | Structural pass produced 0 findings in these files (the 23 `has_permission(...)` matches live in `zerver/models/users.py`, not `zerver/lib/users.py`) |
| Structural-only | 0 | 0 | — |
| Deep-only | 25 | 3 | All deep findings are net-new |

The `decorator.py` story is the headline: Zift currently has full structural rules for Java's `@PreAuthorize` family but nothing equivalent for Python's `@require_*` / `@zulip_login_required` style. **Adding one rule converts 14 of these 25 findings to structural matches** at no semantic-runtime cost.

## Scanner observations

- **Empty `code_snippet` on semantic findings.** All 28 deep findings across both files have `code_snippet: ""`. Should be populated from the line range. Filed as follow-up.
- **Robustness to bad agent output.** The Zulip `decorator.py` run hit one unparseable agent response and the scanner correctly logged `WARN` and continued. Good failure mode.
