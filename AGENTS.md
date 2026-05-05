# Zift

Static analysis tool that scans codebases for embedded authorization logic and generates Policy as Code (PaC). Rego/OPA today; architecture is designed to grow into other policy languages (e.g. Cedar) over time.

> This file is the canonical instructions document for AI coding agents working on Zift. `CLAUDE.md` is a symlink to this file so Claude Code picks it up automatically; other agents (Codex, Aider, Cursor, etc.) should read `AGENTS.md` directly.

## Setup

After cloning, configure the pre-commit hook:

```bash
git config core.hooksPath .githooks
```

## Shared Agent Commands

When the user enters a slash command such as `/pr`, `/review`, `/commit`,
`/handoff`, or `/address-pr-feedback`, first check
`.agents/commands/<command>.md` and follow those instructions if present.
Claude's `.claude/commands` directory is a symlink to these shared command
definitions.

## Build & Development

```bash
cargo build
cargo build --release
cargo test --all-features
cargo fmt          # required before committing
cargo clippy --all-features -- -D warnings
```

## Architecture

- **CLI** (`src/cli.rs`): Subcommands — `scan`, `extract`, `report`, `rules`, `init`
- **Scanner** (`src/scanner/`): Tree-sitter AST parsing and pattern matching across languages
- **Rules** (`rules/`): TOML-based pattern definitions with tree-sitter queries and policy templates (Rego today)
- **Rego** (`src/rego/`): Policy-as-Code generation from scan findings (Rego/OPA today; additional engines like Cedar planned)
- **Output** (`src/output/`): Formatters (JSON, text)

### Design principles

- Two-pass architecture: structural scan (tree-sitter, fast) then optional semantic scan (LLM-assisted)
- Rules are data (TOML), not code — easy to add new patterns without touching Rust
- Same finding schema for both passes

### Language support

- v0.1: TypeScript, JavaScript, Java, Python, Go, C#
- v0.2 (planned): Kotlin, Ruby, PHP

## Conventional Commits & Versioning

Uses release-plz for automated version bumping and changelog generation.

Trigger prefixes (cause version bump — see bump table below; exact bump depends on pre/post-1.0):
- `feat:` — new feature
- `fix:` — bug fix
- `refactor:` — code refactoring
- `perf:` — performance improvement

Skipped prefixes (no version bump):
- `docs:`, `test:`, `ci:`, `chore:`, `style:`, `build:`

PR titles must use a conventional commit prefix.

### Bump size (Cargo 0.x SemVer)

While the crate is below `1.0.0`, release-plz follows Cargo's 0.x convention: the **minor** position acts as the major. That changes how prefixes map to bumps:

Placeholders below: pre-1.0 uses `0.M.p` (minor `M`, patch `p`); post-1.0 uses `m.n.p` (major `m`, minor `n`, patch `p`).

| Commit                                  | Pre-1.0 bump                | Post-1.0 bump               |
| --------------------------------------- | --------------------------- | --------------------------- |
| `fix:` / `refactor:` / `perf:`          | patch (`0.M.p → 0.M.(p+1)`) | patch (`m.n.p → m.n.(p+1)`) |
| `feat:`                                 | patch (`0.M.p → 0.M.(p+1)`) | minor (`m.n.p → m.(n+1).0`) |
| `feat!:` or `BREAKING CHANGE:` footer   | minor (`0.M.p → 0.(M+1).0`) | major (`m.n.p → (m+1).0.0`) |

Practical consequence: a plain `feat:` on `0.1.x` will **not** produce `0.2.0`. To cut `0.2.0` deliberately, land the headline change with `feat!:` (or include a `BREAKING CHANGE:` footer). For example, Python and Go structural support landed as plain `feat:` PRs and rolled into `v0.1.5`; the next language batch will use `feat!:` so it cuts `v0.2.0`.
