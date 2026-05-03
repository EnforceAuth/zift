# Zift

Static analysis tool that scans codebases for embedded authorization logic and generates Policy as Code (PaC). Rego/OPA today; architecture is designed to grow into other policy languages (e.g. Cedar) over time.

## Setup

After cloning, configure the pre-commit hook:

```bash
git config core.hooksPath .githooks
```

## Build & Development

```bash
cargo build
cargo build --release
cargo test
cargo fmt          # required before committing
cargo clippy -- -D warnings
```

## Architecture

- **CLI** (`src/cli.rs`): Subcommands — `scan`, `extract`, `report`, `rules`, `init`
- **Scanner** (`src/scanner/`): Tree-sitter AST parsing and pattern matching across languages
- **Rules** (`rules/`): TOML-based pattern definitions with tree-sitter queries and policy templates (Rego today)
- **Rego** (`src/rego/`): Policy-as-Code generation from scan findings (Rego/OPA today; additional engines like Cedar planned)
- **Output** (`src/output/`): Formatters (JSON, text; SARIF planned)

### Design principles

- Two-pass architecture: structural scan (tree-sitter, fast) then optional semantic scan (LLM-assisted)
- Rules are data (TOML), not code — easy to add new patterns without touching Rust
- Same finding schema for both passes

### Language support

- v0.1: TypeScript, JavaScript (Java in progress)
- v0.2: Python, Go
- v0.3: C#, Kotlin, Ruby, PHP

## Conventional Commits & Versioning

Uses release-plz for automated version bumping and changelog generation.

Trigger prefixes (cause version bump):
- `feat:` — new feature (minor)
- `fix:` — bug fix (patch)
- `refactor:` — code refactoring (patch)
- `perf:` — performance improvement (patch)

Skipped prefixes (no version bump):
- `docs:`, `test:`, `ci:`, `chore:`, `style:`, `build:`

PR titles must use a conventional commit prefix.
