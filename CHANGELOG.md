# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.3](https://github.com/EnforceAuth/zift/compare/v0.1.2...v0.1.3) - 2026-04-29

### Added

- *(deep)* subprocess transport via --agent-cmd ([#22](https://github.com/EnforceAuth/zift/pull/22))
- *(mcp)* add zift mcp subcommand exposing scanner, prompt, and Rego primitives over stdio ([#21](https://github.com/EnforceAuth/zift/pull/21))
- *(deep)* OpenAI-compatible HTTP transport for --deep mode ([#17](https://github.com/EnforceAuth/zift/pull/17))

### Fixed

- *(deep)* error prefix, semantic pattern_rule lineage, category serialization ([#23](https://github.com/EnforceAuth/zift/pull/23))

## [0.1.2](https://github.com/EnforceAuth/zift/compare/v0.1.1...v0.1.2) - 2026-04-28

### Added

- *(rules/java)* heuristic detection of custom authz service calls ([#13](https://github.com/EnforceAuth/zift/pull/13))
- detect namespace, require, and destructured policy imports ([#9](https://github.com/EnforceAuth/zift/pull/9))

### Fixed

- *(scanner/imports)* use code-side alias for named ES imports ([#14](https://github.com/EnforceAuth/zift/pull/14))
- *(rules/java)* match non-literal args in role/permission checks ([#12](https://github.com/EnforceAuth/zift/pull/12))
- *(rules/java)* repair invalid query in security-interface-impl ([#11](https://github.com/EnforceAuth/zift/pull/11))

## [0.1.1](https://github.com/EnforceAuth/zift/compare/v0.1.0...v0.1.1) - 2026-04-23

### Added

- add Java language support with 18 authz detection rules ([#3](https://github.com/EnforceAuth/zift/pull/3))
