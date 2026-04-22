# zift

Sift through your codebase for embedded authorization logic. Extract it into Rego for [OPA](https://www.openpolicyagent.org/).

> **Status:** Design phase — not yet functional.

## What is zift?

Most applications embed authorization decisions directly in application code: role checks in `if` statements, permission guards in middleware, business rules that act as access control. This scattered auth logic is hard to audit, hard to test, and impossible to enforce consistently.

**zift** scans your codebase, finds these embedded authorization patterns, and helps you externalize them into Rego policies that OPA can enforce centrally.

## How it works

```
zift .                          # scan current directory
zift --deep .                   # include LLM-assisted semantic analysis
zift extract ./findings.json    # generate Rego from scan findings
zift report .                   # detailed findings report
```

### Two-pass architecture

1. **Structural scan** (tree-sitter) — fast, deterministic, zero-cost. Finds known authorization patterns: role checks, permission guards, auth middleware, security annotations.

2. **Semantic scan** (LLM-assisted, opt-in) — analyzes candidate code regions for authorization logic that doesn't use explicit auth vocabulary. Catches business rules that implicitly encode access control.

## Supported languages

Priority order for language support:

| Language | Framework patterns |
|----------|-------------------|
| Java | Spring Security (`@PreAuthorize`, `@Secured`), Jakarta Security, Shiro |
| TypeScript/JavaScript | Express middleware, NestJS guards, Next.js middleware |
| Python | Django (`@permission_required`), Flask-Login, FastAPI dependencies |
| Go | Custom middleware, Casbin, chi/gorilla middleware chains |
| C# | ASP.NET (`[Authorize]`), policy-based authorization |

## Installation

```bash
cargo install zift      # from crates.io (planned)
```

Or download a binary from [Releases](https://github.com/EnforceAuth/zift/releases).

## License

Apache-2.0
