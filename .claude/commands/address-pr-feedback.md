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

**Amazon Q**: Look for activity from `amazon-q-developer[bot]` in *either* channel:
- review/inline comments (pulls comments endpoint), or
- PR-level comments (issues comments endpoint — this is where AQ posts its "Critical Issue" summary).

If neither is present, inform the user:
> "Amazon Q hasn't reviewed this PR yet. Wait for its review, then re-run this command."

```bash
# Check both channels for AQ activity
gh api "repos/{owner}/{repo}/pulls/{pr}/comments" --paginate \
  --jq '[.[] | select(.user.login == "amazon-q-developer[bot]")] | length'
gh api "repos/{owner}/{repo}/issues/{pr}/comments" --paginate \
  --jq '[.[] | select(.user.login == "amazon-q-developer[bot]")] | length'
```

**If either bot hasn't finished, stop here.** Do not proceed to fixing issues with incomplete feedback.

#### 2a. Confirm the latest bot review covers the latest commit

CodeRabbit re-reviews on every push. If you ran a previous round of `/address-pr-feedback`, pushed a fix commit, and CodeRabbit's response to that push hasn't landed yet, the next round will miss the new findings and cause exactly the bug this section exists to prevent.

**Amazon Q does NOT re-review automatically on push** — it only reviews on initial PR open (or when explicitly triggered). After any fix push, AQ's `commit_id` will lag HEAD and that is *expected*. Don't block on it.

```bash
# Compare the head SHA of the PR to the most recent CodeRabbit review's commit_id
HEAD_SHA=$(gh api "repos/{owner}/{repo}/pulls/{pr}" --jq .head.sha)
LATEST_CR_COMMIT=$(gh api "repos/{owner}/{repo}/pulls/{pr}/reviews" --paginate \
  --jq '[.[] | select(.user.login == "coderabbitai[bot]")] | sort_by(.submitted_at) | last | .commit_id')
echo "PR head:  $HEAD_SHA"
echo "Last CR review commit: $LATEST_CR_COMMIT"
```

If `$LATEST_CR_COMMIT` does not match `$HEAD_SHA`, CodeRabbit hasn't reviewed the latest commit yet. Tell the user:
> "CodeRabbit's latest review is on commit `<short-SHA>` but PR head is `<short-SHA>`. Wait a few minutes for the new review to land, then re-run."

For Amazon Q, optionally surface its review `commit_id` for context but **do not block** on a mismatch — note to the user that AQ's findings (if any) will be from its initial review pass and proceed.

### 3. Fetch review comments (token-efficient two-pass approach)

**CRITICAL: Always use `--paginate` with `gh api` for review comments.** The default page size is 30, which is easily exceeded when bots post 16+ inline comments plus replies. Without `--paginate`, you will miss comments from later review passes.

**CRITICAL: Use truncated previews first.** Full comment bodies contain analysis chains, shell scripts, and committable suggestions that can be 2-5KB each. Fetch summaries first, then only fetch full bodies for items you actually need to fix.

#### 3a. Pass 1 — Scan inline comments (truncated)

Fetch all bot inline comments with bodies truncated to 300 chars. This is enough to understand the issue and triage it. Run these two queries in parallel:

```bash
# Get bot inline comments — TRUNCATED bodies (saves ~80% tokens)
gh api "repos/{owner}/{repo}/pulls/{pr}/comments" --paginate \
  --jq '.[] | select(.in_reply_to_id == null)
  | select(.user.login == "coderabbitai[bot]" or .user.login == "amazon-q-developer[bot]")
  | {id, author: .user.login, path, line, created_at, body: (.body[:300])}'

# Get IDs already replied to by the PR author
gh api "repos/{owner}/{repo}/pulls/{pr}/comments" --paginate \
  --jq '[.[] | select(.in_reply_to_id != null) | select(.user.login != "coderabbitai[bot]" and .user.login != "amazon-q-developer[bot]") | .in_reply_to_id] | unique'
```

Cross-reference to find **unreplied** bot comments only.

Useful shortcut to see how many review batches exist:

```bash
gh api "repos/{owner}/{repo}/pulls/{pr}/comments" --paginate \
  --jq '.[] | select(.user.login == "coderabbitai[bot]") | select(.in_reply_to_id == null) | .created_at' \
  | sort | uniq -c | sort -rn
```

Each unique timestamp cluster represents one review pass.

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
     has_outside_diff: (.body | test("Outside diff range")),
     has_agent_prompt: (.body | test("Prompt for AI Agents"))}'
```

**Only fetch the full review body** if `has_nitpicks`, `has_duplicates`, `has_outside_diff`, or `has_agent_prompt` is true AND the review is from the latest round (i.e., after your last push). For earlier rounds where inline comments were already replied to, skip the full-body fetch.

```bash
# Fetch full body ONLY for reviews that need it (one at a time)
gh api "repos/{owner}/{repo}/pulls/{pr}/reviews/{review_id}" \
  --jq '{id, body}'
```

Parse each fetched review body for:
- **"🧹 Nitpick comments (N)"** — valid code quality items; fix them
- **"♻️ Duplicate comments (N)"** — re-raised from prior reviews; fix them
- **"⚠️ Outside diff range comments (N)"** — comments on code not in the current diff but related to the change; these contain file paths, line numbers, and the same format as inline comments. **Easy to miss** — always check for this section
- **"🤖 Prompt for AI Agents"** — structured fix instructions with file paths and line numbers

**The inline comments (3a) are only the Critical/Major items. Nitpicks, duplicates, and outside-diff-range items stay in the review body (3b).** If the user says "5 comments and 3 comments", those numbers come from "Actionable comments posted: N" in separate review bodies.

#### 3c. General PR comments (issues endpoint)

Bots may also post general PR-level comments (not inline on code). Fetch these with pagination:

```bash
gh api "repos/{owner}/{repo}/issues/{pr}/comments" --paginate \
  --jq '.[] | select(.user.login == "coderabbitai[bot]" or .user.login == "amazon-q-developer[bot]")
  | {id, author: .user.login, created_at, bodyPreview: (.body[:300])}'
```

**Amazon Q "Critical Issue" callouts.** Amazon Q posts a single PR-level comment summarizing severity counts ("Critical Issue: …", "Recommendations: …"). The headline items here are NOT always duplicated in the inline comments — they may only exist in this summary. Always read the full body of the latest Amazon Q PR-level comment and triage each callout as a separate item:

```bash
# Fetch the latest Amazon Q PR-level comment in full
gh api "repos/{owner}/{repo}/issues/{pr}/comments" --paginate \
  --jq '[.[] | select(.user.login == "amazon-q-developer[bot]")] | sort_by(.created_at) | last | .body'
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

Collect ALL feedback from inline comments (3a), review body items (3b), and general PR comments (3c). **Do not skip nitpicks, duplicate items, or outside-diff-range items from the review body**; they get the same triage treatment as inline review comments:

- **CodeRabbit** (`coderabbitai[bot]`): Inline review comments (3a) + review body nitpicks/duplicates/outside-diff-range/actionable items (3b) + general PR comments (3c)
- **Amazon Q** (`amazon-q-developer[bot]`): Inline review comments (3a) + general PR comments (3c, including the "Critical Issue" summary)

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
| 2 | CR nitpick | `path/to/file.rs` | 10 | Brief summary | Fix / Dismiss / Stale | Why |
| 3 | CR outside-diff | `path/to/file.rs` | 78 | Brief summary | Fix / Dismiss / Stale | Why |
| 4 | AQ inline | `path/to/file.rs` | 55 | Brief summary | Fix / Dismiss / Stale | Why |
| 5 | AQ critical (PR-level) | `path/to/file.rs` | n/a | Brief summary | Fix / Dismiss / Stale | Why |

Wait for the user to:
- **Approve all** — proceed with all decisions as proposed
- **Override specific rows** — change the decision for individual items (e.g., "dismiss #3 instead of fixing")
- **Ask questions** — clarify any items before approving

**Do not proceed to step 7 until the user approves.**

### 7. Apply fixes locally (do NOT reply to bots yet)

**CRITICAL — DO NOT reply to bot threads in this step.** Bot replies must happen *after* push so the bot can verify against the actual remote. Replying with "Fixed" before the commit is on the remote causes the bot to re-flag the comment as unfixed (it reads the remote, not your working tree).

For each item that needs a code change:

1. Read the file and understand the context around the flagged line.
2. Apply the fix.

Do not post any thread replies, PR comments, or "Fixed" messages yet. Just edit code.

For dismissals and stale items, also hold off on replies — batch them with the post-push replies in step 10. Sending dismissal replies early is technically safe (no code dependency), but mixing early dismissals with late "Fixed" replies makes the timeline confusing for bots and humans, and easy to get wrong.

### 8. Run quality gates

After all fixes are applied:

```bash
cargo fmt
cargo clippy --all-targets -- -D warnings
cargo test
```

All must pass before committing.

### 9. Commit and push

If any code changes were made:

```bash
git add -A
git commit -m "fix: address PR review feedback"
git push
```

**Verify the push landed before moving on.** Confirm `git log origin/<branch> -1` matches your local HEAD, or check `gh api repos/{owner}/{repo}/pulls/{pr} --jq .head.sha`. The bots will read this SHA when re-evaluating, so the reply in step 10 must reference code that is actually on it.

### 10. Reply to bot threads

Now that the fix is on the remote, post replies. Reference the new commit SHA in "Fixed" replies so the bot can verify and so the timeline is auditable later.

**Reply rules:**

1. **Inline review comments (3a)** — reply on the conversation thread using `gh api .../comments/{comment_id}/replies`.

2. **Review-body/outside-diff items (3b)** — no inline thread exists. Post a top-level PR comment (`gh pr comment`) summarizing fixes/dismissals.

3. **General PR comments (3c)** — these are issue-endpoint comments with no inline review thread. Issue comments don't support threaded replies, so post a new PR comment referencing the original:
   ```bash
   gh pr comment {pr} --body "@coderabbitai Re: comment {comment_id} — Fixed in <sha> — <explanation>"
   ```

4. **Bot reply prefixes** — replies MUST start with the correct prefix:
   - **Amazon Q**: `/q` (e.g., `/q Fixed in <sha> — <explanation>`)
   - **CodeRabbit**: `@coderabbitai` (e.g., `@coderabbitai Fixed in <sha> — <explanation>`)

Without thread replies and correct prefixes, the bots will NOT see your reply and the comment won't be resolved.

For valid concerns (fixed):
```bash
# For Amazon Q comments — MUST start with /q
gh api "repos/{owner}/{repo}/pulls/{pr}/comments/{comment_id}/replies" \
  -X POST -f body="/q Fixed in <sha> — <brief explanation>"

# For CodeRabbit comments — MUST start with @coderabbitai
gh api "repos/{owner}/{repo}/pulls/{pr}/comments/{comment_id}/replies" \
  -X POST -f body="@coderabbitai Fixed in <sha> — <brief explanation>"
```

For false positives (dismissed):
```bash
# For Amazon Q comments — MUST start with /q
gh api "repos/{owner}/{repo}/pulls/{pr}/comments/{comment_id}/replies" \
  -X POST -f body="/q <explanation of why this is safe>"

# For CodeRabbit comments — MUST start with @coderabbitai
gh api "repos/{owner}/{repo}/pulls/{pr}/comments/{comment_id}/replies" \
  -X POST -f body="@coderabbitai <explanation of why this is safe>"
```

For outside-diff-range and review body items (no inline comment ID to reply to):
```bash
gh pr comment {pr} --body "@coderabbitai Addressed in <sha>:
- Fixed: <list of fixes with file:line references>
- Dismissed: <list with reasoning>"
```

### 11. Report summary and offer a follow-up pass

Present a summary to the user:

- **Fixed**: List of issues that were fixed with brief descriptions
- **Dismissed**: List of false positives with reasoning
- **Stale**: Comments on code that was already changed/removed
- **Needs input**: Any ambiguous items requiring user decision
- **Quality gates**: Pass/fail status

Then **proactively remind the user**:
> "The push will trigger another bot review pass. If new findings come back, re-run `/address-pr-feedback` in a few minutes to address them."

This is the recurring pattern: every fix push spawns a fresh review, and missing it leaves real findings unaddressed at merge time.
