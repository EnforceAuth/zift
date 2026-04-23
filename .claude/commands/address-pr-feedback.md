# Address PR Feedback

Fetch and address all review bot feedback on the current PR.

## Token Budget Awareness

This skill fetches external data (GitHub API). Every API response counts against the context window.
**Goal: stay under ~30K tokens for the fetch phase.** Use truncated previews first, full bodies only when needed.

## Instructions

### 1. Identify the PR

```bash
gh pr view --json number,url,state --jq '{number, url, state}'
```

If no PR exists for the current branch, abort with a message.

### 2. Check that review bots are done

Both CodeRabbit and Amazon Q review asynchronously. Before addressing feedback, verify they have finished.

```bash
# Get all reviews on the PR — compact output
gh pr view --json reviews --jq '.reviews[] | {author: .author.login, state: .state}'

# Check PR comments for bot activity
gh api "repos/{owner}/{repo}/pulls/{pr}/comments" --paginate \
  --jq '[.[] | .user.login] | unique'
```

**CodeRabbit**: Look for a PR comment containing "Walkthrough" or a review with `coderabbitai` as author. If not present, inform the user:
> "CodeRabbit hasn't reviewed this PR yet. Wait for its review or run `@coderabbitai review` as a PR comment, then re-run this command."

**Amazon Q**: Look for review comments from `amazon-q-developer[bot]`. If not present, inform the user:
> "Amazon Q hasn't reviewed this PR yet. Wait for its review, then re-run this command."

**If either bot hasn't finished, stop here.** Do not proceed to fixing issues with incomplete feedback.

### 3. Fetch review comments (token-efficient two-pass approach)

**CRITICAL: Always use `--paginate` with `gh api` for review comments.** The default page size is 30, which is easily exceeded when bots post 16+ inline comments plus replies. Without `--paginate`, you will miss comments from later review passes.

**CRITICAL: Use truncated previews first.** Full comment bodies contain analysis chains, shell scripts, and committable suggestions that can be 2-5KB each. Fetch summaries first, then only fetch full bodies for items you actually need to fix.

#### 3a. Pass 1 — Scan inline comments (truncated)

Fetch all bot inline comments with bodies truncated to 300 chars. This is enough to understand the issue and triage it. Run these two queries in parallel:

```bash
# Get bot inline comments — TRUNCATED bodies (saves ~80% tokens)
# MUST use --paginate to get all comments across pages
gh api "repos/{owner}/{repo}/pulls/{pr}/comments" --paginate \
  --jq '.[] | select(.in_reply_to_id == null)
  | select(.user.login == "coderabbitai[bot]" or .user.login == "amazon-q-developer[bot]")
  | {id, author: .user.login, path, line, created_at, body: (.body[:300])}'

# Get IDs already replied to by the PR author
gh api "repos/{owner}/{repo}/pulls/{pr}/comments" --paginate \
  --jq '[.[] | select(.in_reply_to_id != null) | select(.user.login != "coderabbitai[bot]" and .user.login != "amazon-q-developer[bot]") | .in_reply_to_id] | unique'
```

To identify **new unaddressed root comments**, filter by:
- `in_reply_to_id == null` (root comment, not a reply)
- `user.login` is a bot (`coderabbitai[bot]` or `amazon-q-developer[bot]`)
- No reply from the PR author exists with matching `in_reply_to_id`

Cross-reference to find **unreplied** bot comments only.

#### 3b. Pass 1 — Scan CodeRabbit review bodies (extract counts only)

CodeRabbit review bodies are the largest token consumers (3-8KB each). First extract just the actionable metadata:

```bash
# Get review metadata — NOT full bodies
gh api "repos/{owner}/{repo}/pulls/{pr}/reviews" --paginate \
  --jq '.[] | select(.user.login == "coderabbitai[bot]") | select(.body | length > 0)
  | {id,
     actionable: ((.body | try capture("Actionable comments posted: (?<n>[0-9]+)") catch null | .n) // "0"),
     has_nitpicks: (.body | test("Nitpick comments")),
     has_duplicates: (.body | test("Duplicate comments")),
     has_agent_prompt: (.body | test("Prompt for AI Agents"))}'
```

**Only fetch the full review body** if `has_nitpicks`, `has_duplicates`, or `has_agent_prompt` is true AND the review is from the latest round (i.e., after your last push). For earlier rounds where inline comments were already replied to, skip the full body fetch.

```bash
# Fetch full body ONLY for reviews that need it (one at a time)
gh api "repos/{owner}/{repo}/pulls/{pr}/reviews/{review_id}" \
  --jq '{id, body}'
```

Parse each fetched review body for:
- **"Nitpick comments (N)"** — valid code quality items; fix them
- **"Duplicate comments (N)"** — re-raised from prior reviews; fix them
- **"Outside diff range comments (N)"** — comments on code outside the changed lines; triage these the same as inline comments
- **"Prompt for AI Agents"** — structured fix instructions with file paths and line numbers

**The inline comments (3a) are only the Critical/Major items. Nitpicks, duplicates, and outside-diff-range items stay in the review body (3b).** If the user says "5 comments and 3 comments", those numbers come from "Actionable comments posted: N" in separate review bodies.

#### 3c. Amazon Q general comments (if any)

```bash
gh pr view --json comments \
  --jq '.comments[] | select(.author.login == "amazon-q-developer") | {bodyPreview: (.body[:300])}'
```

#### 3d. CodeRabbit summary comment — SKIP unless user asks

The walkthrough/summary comment is almost never actionable for code fixes. **Do not fetch it** unless the user specifically asks about it. This saves 10-20KB.

### 4. Pass 2 — Fetch full bodies for items to fix

For each unreplied comment you plan to fix (not dismiss), fetch the full body:

```bash
# Fetch full body for a single comment
gh api "repos/{owner}/{repo}/pulls/comments/{comment_id}" --jq '.body'
```

**Only do this for comments where the 300-char preview wasn't enough to understand the required fix.** Many fixes are obvious from the preview alone.

### 5. Identify actionable feedback

Collect ALL feedback from inline comments (3a), review body items (3b), and Amazon Q comments. **Do not skip nitpicks or duplicate items from the review body**; they get the same triage treatment as inline review comments:

- **CodeRabbit** (`coderabbitai[bot]`): Inline review comments (3a) + review body nitpicks/duplicates/actionable items (3b)
- **Amazon Q** (`amazon-q-developer[bot]`): Inline review comments (3a)

**Before applying any fix**, first verify the finding against the current code and decide whether a code change is actually needed. If the finding is not valid or no change is required, do not modify code for that item and briefly explain why it was skipped.

For each comment, determine:
1. **Valid concern** — fix it
2. **False positive** — reply explaining why (e.g., Drizzle parameterization handles SQL injection)
3. **Stale** — code was already changed/removed since the comment was posted
4. **Ambiguous** — ask the user which direction to take

### 6. Present decisions for approval

**STOP and present a table** before making any changes. The user must approve the plan first.

| # | Source | File | Line | Comment Summary | Decision | Rationale |
|---|--------|------|------|-----------------|----------|-----------|
| 1 | CR inline | `path/to/file.rs` | 42 | Brief summary | Fix / Dismiss / Stale | Why |
| 2 | CR review body | `path/to/file.rs` | 10 | Brief summary | Fix / Dismiss / Stale | Why |
| 3 | AQ inline | `path/to/file.rs` | 55 | Brief summary | Fix / Dismiss / Stale | Why |

Wait for the user to:
- **Approve all** — proceed with all decisions as proposed
- **Override specific rows** — change the decision for individual items (e.g., "dismiss #3 instead of fixing")
- **Ask questions** — clarify any items before approving

**Do not proceed to step 7 until the user approves.**

### 7. Address each item

**CRITICAL — Reply rules:**

1. **ALWAYS reply on the conversation thread** — use `gh api .../comments/{comment_id}/replies`. NEVER use `gh pr comment` to post a top-level PR comment. Bots track conversations by thread, not by scanning all PR comments.

2. **Bot reply prefixes** — replies MUST start with the correct prefix:
   - **Amazon Q**: `/q` (e.g., `/q Fixed — <explanation>`)
   - **CodeRabbit**: `@coderabbitai` (e.g., `@coderabbitai Fixed — <explanation>`)

Without thread replies and correct prefixes, the bots will NOT see your reply and the comment won't be resolved.

For valid concerns:
1. Read the file and understand the context around the flagged line
2. Apply the fix
3. Reply to the review comment thread explaining what was fixed:
   ```bash
   # For Amazon Q comments — MUST start with /q
   gh api "repos/{owner}/{repo}/pulls/{pr}/comments/{comment_id}/replies" \
     -X POST -f body="/q Fixed — <brief explanation>"

   # For CodeRabbit comments — MUST start with @coderabbitai
   gh api "repos/{owner}/{repo}/pulls/{pr}/comments/{comment_id}/replies" \
     -X POST -f body="@coderabbitai Fixed — <brief explanation>"
   ```

For false positives:
1. Reply to the review comment thread explaining why it's not an issue:
   ```bash
   # For Amazon Q comments — MUST start with /q
   gh api "repos/{owner}/{repo}/pulls/{pr}/comments/{comment_id}/replies" \
     -X POST -f body="/q <explanation of why this is safe>"

   # For CodeRabbit comments — MUST start with @coderabbitai
   gh api "repos/{owner}/{repo}/pulls/{pr}/comments/{comment_id}/replies" \
     -X POST -f body="@coderabbitai <explanation of why this is safe>"
   ```

### 8. Run checks

After all fixes are applied:

```bash
cargo check && cargo clippy -- -D warnings && cargo test
```

All must pass before committing.

### 9. Commit and push

If any code changes were made:

```bash
git add -A
git commit -m "fix: address PR review feedback"
git push
```

### 10. Report summary

Present a summary to the user:

- **Fixed**: List of issues that were fixed with brief descriptions
- **Dismissed**: List of false positives with reasoning
- **Stale**: Comments on code that was already changed/removed
- **Needs input**: Any ambiguous items requiring user decision
- **Checks**: Pass/fail status
