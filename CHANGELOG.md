# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0](https://github.com/EnforceAuth/zift/compare/v0.1.9...v0.2.0) - 2026-05-05

### Added

- [**breaking**] add C# structural support ([#69](https://github.com/EnforceAuth/zift/pull/69))

## [0.1.9](https://github.com/EnforceAuth/zift/compare/v0.1.8...v0.1.9) - 2026-05-05

### Added

- *(scanner/imports)* detect policy imports across languages ([#67](https://github.com/EnforceAuth/zift/pull/67))

## [0.1.8](https://github.com/EnforceAuth/zift/compare/v0.1.7...v0.1.8) - 2026-05-05

### Added

- bound public API surface + fix broken CLI surface (OSS P0) ([#47](https://github.com/EnforceAuth/zift/pull/47))

## [0.1.7](https://github.com/EnforceAuth/zift/compare/v0.1.6...v0.1.7) - 2026-05-05

### Added

- *(output)* promote externalization percentage to headline ([#54](https://github.com/EnforceAuth/zift/pull/54))
- scanner output follow-ups (surface, snippet fallback, enforcement_points) ([#55](https://github.com/EnforceAuth/zift/pull/55))
- *(rules)* corpus shakedown rule pass — coverage for Gitea, Ghost, Cal.com, OpenMRS, Zulip ([#50](https://github.com/EnforceAuth/zift/pull/50))
- *(deep)* unwrap claude-code envelope and broaden Go authz coverage ([#48](https://github.com/EnforceAuth/zift/pull/48))

### Fixed

- *(output)* add missing surface field to test Finding constructors ([#59](https://github.com/EnforceAuth/zift/pull/59))

## [0.1.6](https://github.com/EnforceAuth/zift/compare/v0.1.5...v0.1.6) - 2026-05-04

### Fixed

- match bare-function middleware values in gin/echo rule ([#44](https://github.com/EnforceAuth/zift/pull/44))

## [0.1.5](https://github.com/EnforceAuth/zift/compare/v0.1.4...v0.1.5) - 2026-05-03

### Added

- add Go structural scanning support ([#32](https://github.com/EnforceAuth/zift/pull/32))
- add Python structural scanning support ([#29](https://github.com/EnforceAuth/zift/pull/29))

## [0.1.4](https://github.com/EnforceAuth/zift/compare/v0.1.3...v0.1.4) - 2026-04-30

### Fixed

- *(rules/java)* require principal-side getter in ownership-check ([#25](https://github.com/EnforceAuth/zift/pull/25))

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
