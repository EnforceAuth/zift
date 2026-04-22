# Code Review Branch Commits

Review all commits on the current branch since diverging from main.

## Prerequisites

**IMPORTANT**: Before starting the review, check if this is a fresh context/session:
- If there is prior conversation history in this session (e.g., you helped write the code being reviewed), STOP immediately
- Inform the user: "Code reviews should be done in a fresh context to avoid bias. Please start a new Claude Code session and run /review there."
- A reviewer should not be the same "person" who wrote the code

## Instructions

When activated, perform a thorough code review:

1. **Gather changes**:
   - Run `git log main..HEAD --oneline` to see all commits on this branch
   - Run `git diff main..HEAD` to see all changes
   - For each file changed, read enough context to understand the changes

2. **Run checks** (if project has been set up):
   - `cargo check` — does it compile?
   - `cargo clippy -- -D warnings` — lint
   - `cargo fmt --check` — formatting
   - `cargo test` — tests pass

3. **Review the changes** looking for:
   - **Correctness**: Logic errors, off-by-one, missing edge cases
   - **Safety**: Rust-specific issues — unwrap on fallible paths, unsafe blocks, panic in library code
   - **API design**: Public API ergonomics, naming consistency, idiomatic Rust patterns
   - **Error handling**: Proper error propagation, meaningful error messages
   - **Performance**: Unnecessary allocations, O(n²) where O(n) is possible
   - **Testing**: Missing test coverage for new code paths

4. **Present findings** as a severity-rated table:

   | # | Severity | File:Line | Issue | Suggestion |
   |---|----------|-----------|-------|------------|
   | 1 | High | path/to/file.rs:42 | Description | Fix |

   Severities: **High** (bugs, safety issues), **Medium** (code quality, missed patterns), **Low** (style, nits)

5. **Present a fix plan** for user approval before making any changes:

   | # | File | Issue | Proposed Action |
   |---|------|-------|-----------------|
   | 1 | path/to/file.rs:42 | Brief description | Fix / Skip / Ask |

   Wait for the user to approve. Then apply only approved fixes and re-run checks.
