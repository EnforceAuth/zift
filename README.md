# zift

Sift through your codebase for embedded authorization logic. Extract it into Rego for [OPA](https://www.openpolicyagent.org/).

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

TypeScript, JavaScript, and Java (Python, Go, C#, Kotlin, Ruby, PHP planned).

## Installation

### Homebrew

```bash
brew tap EnforceAuth/tap
brew install zift
```

### Cargo

```bash
cargo binstall zift    # prebuilt binary
cargo install zift     # build from source
```

### Binary download

Prebuilt binaries for Linux, macOS, and Windows are available from [Releases](https://github.com/EnforceAuth/zift/releases).

## License

Apache-2.0
