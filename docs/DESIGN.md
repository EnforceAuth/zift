# zift — Design Document

## Vision

**zift** is an open-source CLI tool that scans application codebases for embedded authorization logic and helps developers externalize it into [Rego](https://www.openpolicyagent.org/docs/latest/policy-language/) policies for [OPA](https://www.openpolicyagent.org/).

Most applications scatter authorization decisions across application code: role checks in conditionals, permission guards in middleware, business rules that implicitly act as access control. This pattern is hard to audit, hard to test, and impossible to enforce consistently across services. zift finds these patterns and provides a path to centralized policy enforcement.

## Goals

1. **Detect** embedded authorization patterns across multiple languages and frameworks
2. **Classify** findings by type (RBAC, ABAC, middleware guards, business-rule auth, custom schemes)
3. **Generate** equivalent Rego policy stubs from detected patterns
4. **Report** findings in human-readable and machine-consumable formats
5. **Integrate** into CI pipelines as a policy-drift detector

## Non-goals (v1)

- Automated refactoring of source code (we generate Rego, we don't rewrite the app)
- Runtime enforcement or OPA integration — zift is a static analysis tool
- Supporting every language on day one — we ship with a priority set and expand

---

## Architecture

### Two-pass scanning model

zift uses a hybrid architecture that balances speed, cost, and detection depth.

```
                    ┌─────────────┐
                    │  Source Code │
                    └──────┬──────┘
                           │
                    ┌──────▼──────┐
                    │  Pass 1:    │
                    │  Structural │  tree-sitter AST parsing
                    │  Scan       │  Pattern rule matching
                    └──────┬──────┘
                           │
              ┌────────────┼────────────┐
              │            │            │
         High-conf    Med-conf     Low-conf
         findings     findings     candidates
              │            │            │
              │       ┌────▼────┐       │
              │       │ Pass 2: │       │
              │       │ Semantic│  LLM analysis
              │       │ Scan    │  (opt-in, --deep)
              │       └────┬────┘       │
              │            │            │
              └────────────┼────────────┘
                           │
                    ┌──────▼──────┐
                    │  Findings   │
                    │  + Rego     │
                    │  Generation │
                    └─────────────┘
```

### Pass 1: Structural scan (tree-sitter)

Fast, deterministic, zero-cost. Parses source code into ASTs using tree-sitter grammars and matches against a library of authorization pattern rules.

**What it catches:**

| Category | Examples |
|----------|---------|
| Role checks | `if user.role == "admin"`, `hasRole("MANAGER")` |
| Permission guards | `user.can("write", resource)`, `checkPermission(...)` |
| Framework annotations | `@PreAuthorize`, `@Secured`, `[Authorize]`, `@permission_required` |
| Middleware registration | `app.use(authMiddleware)`, `router.use(requireAuth)` |
| RBAC patterns | Role enums, role-to-permission mappings, role hierarchies |
| Token/session checks | `if req.headers.authorization`, `session.isAuthenticated` |
| Ownership checks | `if resource.owner_id == user.id` |
| Feature flags as auth | `if user.plan == "enterprise"`, `hasFeature("advanced")` |

**Pattern rule format:**

Each pattern rule specifies:
- Target language(s)
- Tree-sitter query (S-expression)
- Confidence level (high / medium / low)
- Category (RBAC, ABAC, middleware, business-rule, custom)
- Description (human-readable explanation)
- Rego template (stub for generation)

Example rule (conceptual):

```toml
[rule.role-check-conditional]
languages = ["typescript", "javascript"]
category = "RBAC"
confidence = "high"
description = "Direct role comparison in conditional"
query = """
(if_statement
  condition: (binary_expression
    left: (member_expression
      property: (property_identifier) @prop
      (#match? @prop "role|roles|userRole"))
    operator: ["==" "===" "!=" "!=="]
    right: (string) @role_value))
"""

[rule.role-check-conditional.rego_template]
template = """
package {{package}}

default allow := false

allow if {
    input.user.role == "{{role_value}}"
}
"""
```

### Pass 2: Semantic scan (LLM-assisted)

Opt-in via `--deep`. Sends candidate code regions (functions, classes, modules flagged as "interesting" by Pass 1 or by heuristics) to an LLM for semantic analysis.

**What it catches that Pass 1 cannot:**
- Business logic acting as authorization without auth vocabulary (`if department == "finance" && amount > 10000`)
- Custom authorization schemes that don't match known patterns
- Complex multi-step authorization flows spanning multiple functions
- Authorization logic hidden in data transformations (filtering query results by user permissions)

**Design constraints for LLM pass:**
- **Opt-in only** — never sends code to an LLM without explicit user consent
- **Configurable provider** — support OpenAI, Anthropic, local models (Ollama)
- **Minimal context** — send only the candidate code region + surrounding context, not the full file
- **Structured output** — LLM returns findings in the same schema as Pass 1
- **Cost transparency** — report token usage and estimated cost
- **Offline fallback** — tool is fully functional without LLM access (Pass 1 only)

### Findings schema

All findings (from both passes) conform to a unified schema:

```rust
struct Finding {
    id: String,                    // deterministic hash for dedup
    file: PathBuf,                 // relative to scan root
    line_start: usize,
    line_end: usize,
    code_snippet: String,          // the matched source code
    language: Language,
    category: AuthCategory,        // RBAC, ABAC, Middleware, BusinessRule, Custom
    confidence: Confidence,        // High, Medium, Low
    description: String,           // human-readable explanation
    pattern_rule: Option<String>,  // which rule matched (Pass 1 only)
    rego_stub: Option<String>,     // generated Rego (if available)
    pass: ScanPass,                // Structural or Semantic
}

enum AuthCategory {
    RBAC,           // role-based access control
    ABAC,           // attribute-based access control
    Middleware,     // auth middleware/interceptors
    BusinessRule,   // business logic acting as authorization
    Ownership,      // resource ownership checks
    FeatureGate,    // feature flags / plan-based gating
    Custom,         // doesn't fit other categories
}

enum Confidence {
    High,    // almost certainly authorization logic
    Medium,  // likely authorization, may need human review
    Low,     // possibly authorization, recommended for --deep
}
```

### Rego generation

For each finding (or group of related findings), zift generates a Rego policy stub:

```rego
# Generated by zift from src/api/orders.rs:47
# Category: RBAC | Confidence: High
# Original: if user.role == "admin" || user.role == "manager"
package app.orders.access

import rego.v1

default allow := false

allow if {
    input.user.role in {"admin", "manager"}
}
```

**Generation strategy:**
- High-confidence findings → complete Rego stubs
- Medium-confidence → partial stubs with `# TODO: verify` annotations
- Low-confidence → commented-out suggestions
- Related findings in the same file/module → grouped into a single package

---

## Language support

### Priority 1 (v0.1)

| Language | Key frameworks / patterns |
|----------|--------------------------|
| Java | Spring Security (`@PreAuthorize`, `@Secured`, `@RolesAllowed`), Jakarta Security, Apache Shiro, custom `if` checks |
| TypeScript | Express middleware, NestJS guards/decorators, Next.js middleware, `if (user.role)` patterns |
| JavaScript | Same as TypeScript minus type-specific patterns |

### Priority 2 (v0.2)

| Language | Key frameworks / patterns |
|----------|--------------------------|
| Python | Django (`@permission_required`, `has_perm()`), Flask-Login, FastAPI `Depends()` |
| Go | Custom middleware, Casbin, chi/gorilla middleware chains, `if claims.Role` |

### Priority 3 (v0.3)

| Language | Key frameworks / patterns |
|----------|--------------------------|
| C# | ASP.NET `[Authorize]`, policy-based authorization, `ClaimsPrincipal` checks |
| Kotlin | Spring Security (same patterns as Java), Ktor auth plugins |
| Ruby | Pundit, CanCanCan, Devise, `before_action` guards |
| PHP | Laravel Gates/Policies, Symfony Voters |

### Adding a new language

Adding a language requires:
1. A tree-sitter grammar (most languages already have one)
2. Pattern rules specific to that language's idioms and frameworks
3. Tests against representative code samples

Community contributions for new languages should be straightforward — the main work is writing pattern rules, not engine code.

---

## CLI design

```
zift <command> [options] [path]

COMMANDS:
    (default)       Scan a codebase (alias for scan behavior)
    extract         Generate Rego files from findings
    report          Generate a detailed report
    rules           List/validate/test pattern rules
    init            Create a .zift.toml configuration file

SCAN OPTIONS:
    <path>              Path to scan (default: .)
    --deep              Enable LLM-assisted semantic analysis
    --language, -l      Filter to specific language(s)
    --category, -c      Filter to specific auth category(s)
    --confidence        Minimum confidence level (high|medium|low)
    --exclude, -e       Glob patterns to exclude
    --format, -f        Output format (text|json|sarif)
    --output, -o        Write findings to file (default: stdout)
    --rules-dir         Additional pattern rules directory
    --config            Path to config file (default: .zift.toml)

DEEP SCAN OPTIONS:
    --provider          LLM provider (anthropic|openai|ollama)
    --model             Model to use (default: provider-specific)
    --max-cost          Maximum spend limit for LLM calls
    --api-key           API key (or set ZIFT_API_KEY / provider-specific env vars)

EXTRACT OPTIONS:
    --input, -i         Findings file (default: stdin or last scan)
    --output-dir        Directory for generated .rego files
    --package-prefix    Rego package prefix (default: app)
    --min-confidence    Skip findings below this confidence

REPORT OPTIONS:
    --input, -i         Findings file
    --format            Report format (text|html|markdown)

RULES OPTIONS:
    list                List all loaded pattern rules
    validate            Check rules for syntax errors
    test                Run rules against test fixtures
```

### Configuration file (.zift.toml)

```toml
[scan]
exclude = ["vendor/**", "node_modules/**", "**/*_test.go", "**/*.test.ts"]
languages = ["java", "typescript", "python"]
min_confidence = "medium"

[deep]
provider = "anthropic"
model = "claude-sonnet-4-20250514"
max_cost = 5.00  # USD

[extract]
package_prefix = "app.authz"
output_dir = "./policies/generated"

[rules]
# Additional rules directories (merged with built-in rules)
additional = ["./custom-rules"]
```

---

## Implementation plan

### Phase 0: Scaffolding (1-2 days)
- Rust project structure (cargo workspace if needed)
- CLI argument parsing (clap)
- Configuration file loading (toml)
- Basic logging and error handling
- CI setup (GitHub Actions: build, test, clippy, fmt)

### Phase 1: Core engine — single language (1-2 weeks)
- tree-sitter integration and AST traversal
- Pattern rule format definition and parser
- TypeScript/JavaScript as first language (familiar territory, rich auth patterns)
- 10-15 initial pattern rules covering Express middleware, NestJS, role checks
- Findings schema and JSON output
- Basic text reporter

### Phase 2: Rego generation (1 week)
- Template engine for Rego stubs
- Finding-to-Rego mapping for each auth category
- Package grouping logic (related findings → single .rego file)
- `extract` command

### Phase 3: Java support + rule expansion (1 week)
- Java tree-sitter grammar integration
- Spring Security annotation patterns
- Jakarta/Shiro patterns
- Custom conditional patterns for Java idioms
- 15-20 additional pattern rules

### Phase 4: LLM integration — `--deep` (1-2 weeks)
- Provider abstraction (Anthropic, OpenAI, Ollama)
- Candidate selection heuristics (what to send to the LLM)
- Prompt engineering for authorization detection
- Structured output parsing
- Cost tracking and limits
- Integration with findings pipeline

### Phase 5: CI integration + SARIF (3-5 days)
- SARIF output format (for GitHub Code Scanning, VS Code)
- Exit codes for CI (findings above threshold → non-zero)
- Baseline/diff mode (only report new findings since last scan)
- GitHub Actions example workflow

### Phase 6: Additional languages (ongoing)
- Python, Go, C#, Kotlin, Ruby, PHP
- Community contribution guide for adding languages
- Pattern rule testing framework

---

## Technical decisions

### Why Rust?

- **tree-sitter is written in Rust** — first-class bindings, no FFI overhead
- **Performance at scale** — scanning millions of LOC across large monorepos benefits from zero-cost abstractions
- **Code analysis ecosystem** — Rust dominates this space (Biome, oxc, Ruff's parser, turbopack)
- **Agent-assisted development** — Rust's learning curve is no longer a contributor barrier with modern AI coding tools
- **Single binary distribution** — no runtime dependencies, easy to install in CI

### Why tree-sitter (not regex, not language-specific parsers)?

- **One engine, many languages** — add a grammar, write patterns, done
- **Real AST, not text matching** — regex can't distinguish `user.role` in a conditional from `user.role` in a comment or string
- **Battle-tested** — GitHub, Neovim, Helix, Zed all rely on it
- **Incremental** — future IDE/LSP integration can reuse the same parsing infrastructure

### Why not build on Semgrep?

Considered but rejected for v1:
- Semgrep's OSS licensing has shifted — building a product dependency on it carries risk
- Semgrep rules are powerful but generic; zift's pattern rules can be tailored for auth-specific output (Rego templates, auth categories)
- We want first-class Rego generation as part of the finding, not bolted on
- If Semgrep rules prove popular, we can add a Semgrep-compatible rule import later

### Findings deduplication

Authorization logic often appears in patterns:
- A middleware function defined once, registered many times
- A role check helper called from multiple endpoints
- The same guard pattern copy-pasted across files

zift deduplicates by:
1. Content hashing (same code → same finding ID)
2. Definition tracking (prefer the definition site over call sites)
3. Grouping related findings in reports

---

## Open-source strategy

### Licensing
Apache-2.0 — permissive, enterprise-friendly, compatible with OPA's license.

### Community contribution model
- **Pattern rules are the primary contribution surface** — low barrier, high impact
- Each language has a `rules/{language}/` directory with self-contained rule files
- Rules include test fixtures (code samples + expected findings)
- `zift rules test` validates contributed rules

### Relationship to EnforceAuth
zift is a standalone diagnostic tool. It tells you where your authorization logic lives. EnforceAuth is the platform that helps you centralize and enforce it. zift generates Rego stubs; EnforceAuth manages the full policy lifecycle.

The funnel: **scan → discover → extract → enforce**

---

## Success metrics

| Metric | Target |
|--------|--------|
| Precision (high-confidence findings) | > 90% are actually auth logic |
| Language coverage | 5+ languages within 6 months |
| Pattern rule count | 100+ rules across all languages |
| GitHub stars | Awareness indicator |
| Time to first scan | < 30 seconds for a typical project |
| Community contributions | Pattern rules from 10+ contributors in year 1 |

---

## Risks and mitigations

| Risk | Mitigation |
|------|-----------|
| Low precision → users ignore findings | Invest heavily in rule quality; default to high-confidence only; let users tune |
| LLM costs scare off adoption | LLM is opt-in; structural scan is the default and is free |
| "Why not just use Semgrep?" | Auth-specific categories, Rego generation, and deep-scan differentiate |
| tree-sitter grammar quality varies | Start with well-maintained grammars (TS, Java, Python, Go); contribute fixes upstream |
| Scope creep into runtime enforcement | Explicit non-goal; stay in the static analysis lane |
| Pattern rules become stale as frameworks evolve | Test fixtures tied to real framework versions; CI tests against framework updates |
