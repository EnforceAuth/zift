# Corpus shakedown

Real-world results from running Zift against well-known open-source codebases — one per supported language. The point is to give a new user something concrete to look at on day one: *"here's what Zift actually finds in projects you've heard of."*

## Methodology

For each target we ran two passes against a shallow clone (`git clone --depth 1`) of the upstream `main`:

1. **Structural** (`zift scan <path>`) — tree-sitter pattern rules. Fast, deterministic, no network.
2. **Deep** (`zift scan <path> --deep`) — semantic LLM-assisted pass over the same tree. Used to triangulate against the structural pass: deep-only findings are FN leads (potential new structural rules); structural-only findings that deep didn't echo back are FP leads.

Deep mode emits a single merged report — every finding is tagged `pass: structural | semantic`. We bucket the merged output:

| Bucket | Meaning | Action |
|--------|---------|--------|
| Both agree | Structural rule fired and deep retained the match | Confidence calibration win |
| Structural-only | Structural fired (whole-repo run); deep didn't echo it back | False-positive lead — tighten predicate |
| Deep-only | Deep flagged authz on a line with no structural match | False-negative lead — new rule or widen predicate |

We are **not** shipping policies for these projects. The runs exist to stress-test the scanner and rules.

## Targets

| Language | Repo | Structural (whole-repo) | Deep (scoped subset) | Headline |
|----------|------|------------------------:|---------------------:|----------|
| JavaScript | [TryGhost/Ghost](https://github.com/TryGhost/Ghost) | 32 | 5 (engine subset) | Deep enumerates 5 distinct decisions inside `can-this.js` — the permission engine itself, where no name pattern matches. See [js.md](js.md). |
| TypeScript | [calcom/cal.com](https://github.com/calcom/cal.com) | 166 | 30 (auth-module subset) | NestJS guards carry the structural pass (123 of 166); deep on the guard *implementations* surfaces a permissive-stub PBAC guard and explicit auth-bypass branches. See [ts.md](ts.md). |
| Java | [openmrs/openmrs-core](https://github.com/openmrs/openmrs-core) | 76 | 20 (context subset) | Deep surfaces a daemon-thread privilege bypass — a real authz decision invisible to any pattern rule. See [java.md](java.md). |
| Python | [zulip/zulip](https://github.com/zulip/zulip) | 39 | 28 (decorator + lib/users subset) | 14 of 25 deep findings in `decorator.py` are the `@require_*` family — adding one rule converts them all to structural. See [python.md](python.md). |
| Go | [go-gitea/gitea](https://github.com/go-gitea/gitea) | 18 | 23 (perm subset) | Deep surfaces the entire `IsAdmin`/`IsOwner`/`Has*` family the structural pass missed; one predicate widening on `go-has-role-call` closes most of the gap. See [go.md](go.md). |

> The "deep" column is intentionally a **scoped subset** rather than the whole repo — running deep against 5,000+ files per language is neither cheap nor necessary to surface gaps. Each per-language doc explains the subset and why.
>
> The numbers move as we tighten rules. Each per-language doc records the commit SHA scanned and the Zift version, so what you see here is reproducible.

## How to read these docs

Every per-language doc has the same shape:

1. **Target** — repo, commit SHA, file count, LOC, presence of any externalized PaC.
2. **Structural pass** — wall time, peak RSS, findings per rule, top findings with file:line, suspected false positives.
3. **Deep pass** — transport used, wall time, token cost (if reported), findings per category, deep-only findings.
4. **Diff** — both-agree / structural-only / deep-only bucket counts, with examples.
5. **Gaps & follow-ups** — issues filed against Zift as a result of this run.

## Reproducing

```bash
# Pick a target
git clone --depth 1 https://github.com/TryGhost/Ghost ~/zift-corpus/js/Ghost

# Structural
zift scan ~/zift-corpus/js/Ghost --format json -o structural.json

# Deep (any transport works — examples)
zift scan ~/zift-corpus/js/Ghost --deep --base-url http://localhost:11434/v1 --model llama3.1 -o deep.json
zift scan ~/zift-corpus/js/Ghost --deep --agent-cmd "claude -p --output-format json" -o deep.json

# Diff: deep.json already merges structural and semantic findings, each
# tagged with `pass: structural | semantic`. So we read deep.json alone:
jq '{
  by_pass: ([.findings[] | .pass] | group_by(.) | map({pass: .[0], n: length})),
  semantic_only_rules: ([.findings[] | select(.pass == "semantic") | .pattern_rule] | group_by(.) | map({rule: .[0], n: length}) | sort_by(-.n))
}' deep.json
```
