# Security Policy

Zift is a static analysis tool used in software supply chains, so we take
security reports seriously.

## Reporting a vulnerability

**Please do not file a public GitHub issue for suspected vulnerabilities.**

Use one of the following private channels:

1. **GitHub Private Vulnerability Reporting** — preferred. Open
   <https://github.com/EnforceAuth/zift/security/advisories/new> and submit a
   report. This creates a private advisory only the maintainers can see.
2. **Email** — `security@enforceauth.com`. PGP available on request.

Please include:

- A description of the issue and its impact.
- Steps to reproduce, or a proof-of-concept.
- The affected version(s) of Zift.
- Any suggested mitigation, if you have one.

## What to expect

- We will acknowledge your report within **3 business days**.
- We aim to provide an initial assessment within **7 business days**.
- We follow a **90-day coordinated disclosure** window. If we cannot ship a
  fix in that time, we will work with you to agree on an extension before any
  public disclosure.
- Once a fix is released, we will credit you in the release notes and
  associated advisory unless you prefer to remain anonymous.

## Supported versions

Zift is pre-1.0. We provide security fixes only against the latest released
minor version. Once Zift reaches 1.0, this policy will be revised to cover
the latest two minor releases.

## Scope

In scope:

- The `zift` CLI and library code in this repository.
- Detection rules under `rules/` that ship with the project.
- Release artifacts published from this repository (binaries, crates.io
  releases).

Out of scope:

- Findings that depend on running Zift against attacker-controlled source
  code with elevated privileges in a way that would be a misuse rather than a
  vulnerability. If in doubt, report it and let us decide.
- Vulnerabilities in third-party dependencies — please report those upstream
  first; we will track and update.

Thank you for helping keep Zift and its users safe.
