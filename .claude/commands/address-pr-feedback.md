# Address PR Feedback

Fetch and address all review feedback on the current PR.

## Instructions

### 1. Identify the PR

```bash
gh pr view --json number,url,state --jq '{number, url, state}'
```

If no PR exists for the current branch, abort with a message.

### 2. Fetch review comments

```bash
# Get all reviews on the PR
gh pr view --json reviews --jq '.reviews[] | {author: .author.login, state: .state}'

# Get inline review comments (truncated to save tokens)
gh api "repos/{owner}/{repo}/pulls/{pr}/comments" --paginate \
  --jq '.[] | select(.in_reply_to_id == null)
  | {id, author: .user.login, path, line, created_at, body: (.body[:300])}'

# Get IDs already replied to
gh api "repos/{owner}/{repo}/pulls/{pr}/comments" --paginate \
  --jq '[.[] | select(.in_reply_to_id != null) | .in_reply_to_id] | unique'
```

Cross-reference to find **unreplied** comments only.

### 3. Identify actionable feedback

For each unreplied comment, verify the finding against current code and decide:
1. **Valid concern** — fix it
2. **False positive** — reply explaining why
3. **Stale** — code was already changed/removed since the comment was posted
4. **Ambiguous** — ask the user which direction to take

### 4. Present decisions for approval

**STOP and present a table** before making any changes. The user must approve the plan first.

| # | Source | File | Line | Comment Summary | Decision | Rationale |
|---|--------|------|------|-----------------|----------|-----------|
| 1 | reviewer | `path/to/file.rs` | 42 | Brief summary | Fix / Dismiss / Stale | Why |

Wait for the user to approve before proceeding.

### 5. Address each item

For valid concerns:
1. Read the file and understand the context around the flagged line
2. Apply the fix
3. Reply to the review comment thread explaining what was fixed:
   ```bash
   gh api "repos/{owner}/{repo}/pulls/{pr}/comments/{comment_id}/replies" \
     -X POST -f body="Fixed — <brief explanation>"
   ```

For false positives:
1. Reply to the review comment thread explaining why:
   ```bash
   gh api "repos/{owner}/{repo}/pulls/{pr}/comments/{comment_id}/replies" \
     -X POST -f body="<explanation of why this is not an issue>"
   ```

### 6. Run checks

After all fixes are applied:

```bash
cargo check && cargo clippy -- -D warnings && cargo test
```

All must pass before committing.

### 7. Commit and push

If any code changes were made:

```bash
git add -A
git commit -m "fix: address PR review feedback"
git push
```

### 8. Report summary

- **Fixed**: List of issues fixed with brief descriptions
- **Dismissed**: List of false positives with reasoning
- **Stale**: Comments on code already changed/removed
- **Needs input**: Any ambiguous items requiring user decision
- **Checks**: Pass/fail status
