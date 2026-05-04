# Contributing to Zift

Thanks for your interest in Zift! This document covers how to get a working
development environment, the conventions we follow, and what to expect when
opening a pull request.

By participating in this project, you agree to abide by our
[Code of Conduct](CODE_OF_CONDUCT.md).

## Getting set up

```bash
git clone https://github.com/EnforceAuth/zift
cd zift
git config core.hooksPath .githooks   # enables the pre-commit hook

cargo build
cargo test
```

CI runs `rustfmt`, `clippy`, and the test suite. Please run all three locally
before pushing:

```bash
cargo fmt
cargo clippy -- -D warnings
cargo test
```

## Reporting bugs and asking questions

- **Bugs / feature requests:** open a [GitHub issue](https://github.com/EnforceAuth/zift/issues/new/choose).
- **Questions / ideas:** start a [Discussion](https://github.com/EnforceAuth/zift/discussions), or open an issue if Discussions aren't enabled yet.
- **Security vulnerabilities:** do **not** file a public issue. See [SECURITY.md](SECURITY.md).

## Pull requests

1. Fork the repo and create a topic branch from `main`.
2. Make your changes. Add tests where it makes sense.
3. Run `cargo fmt`, `cargo clippy -- -D warnings`, and `cargo test`.
4. Sign off your commits — see [DCO](#developer-certificate-of-origin) below.
5. Use a [Conventional Commits](https://www.conventionalcommits.org/) prefix in the PR title.
6. Open the PR. Be ready to iterate on review feedback.

### Conventional Commits

PR titles drive automated versioning via [release-plz](https://release-plz.dev/). Use one of:

| Prefix      | Meaning                       | Version bump |
|-------------|-------------------------------|--------------|
| `feat:`     | new feature                   | minor        |
| `fix:`      | bug fix                       | patch        |
| `refactor:` | code refactor                 | patch        |
| `perf:`     | performance improvement       | patch        |
| `docs:`     | documentation only            | none         |
| `test:`     | tests only                    | none         |
| `ci:`       | CI / workflow changes         | none         |
| `chore:`    | maintenance, deps, tooling    | none         |
| `style:`    | formatting, no code change    | none         |
| `build:`    | build system                  | none         |

A breaking change uses `feat!:` or `fix!:` and bumps the **major** version.

### Developer Certificate of Origin

Zift uses the [Developer Certificate of Origin](https://developercertificate.org/)
(DCO) instead of a CLA. Every commit must carry a `Signed-off-by:` line:

```text
Signed-off-by: Jane Doe <jane@example.com>
```

`git commit -s` adds it automatically. The sign-off attests that you have the
right to submit the work under the project's license.

## Adding rules

Detection rules live in [`rules/`](rules/) as TOML files — tree-sitter queries
plus optional Rego templates. Adding a rule does not require Rust changes; copy
an existing rule and follow its structure.

## Code style

- Follow what `rustfmt` and `clippy` say.
- Prefer small, reviewable PRs. If a change has independent parts, split them.
- Update `README.md` if you change user-visible behavior.

## License

By contributing, you agree that your contributions will be licensed under the
[Apache License, Version 2.0](LICENSE).
