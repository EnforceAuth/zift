# Create Pull Request

Create a pull request for the current branch.

## Instructions

When activated, create a pull request for the current branch:

1. **Verify branch state**:
   - Run `git branch --show-current` to get the current branch name
   - Ensure we're not on `main` (abort if so)
   - Run `git log main..HEAD --oneline` to see commits to include

2. **Move completed plan to done** (if applicable):
   - Extract an issue/feature token from the branch name (e.g., `fix/896-buffer-import` → `896`; otherwise the kebab-case feature slug after the type prefix)
   - Search `plans/todo/` for files whose **filename** contains the token, and as a fallback files whose **content** contains it
   - If **no match**: skip this step
   - If **multiple matches**: list them and skip — require human disambiguation rather than guessing
   - If **exactly one match**: inspect its checklist items
     - If the file has zero `- [ ]` / `- [x]` items, treat it as "no checklist" and skip the move
     - If any `- [ ]` items remain unchecked, leave it in `plans/todo/`
     - Only when every checklist item is `- [x]`: `mkdir -p plans/done && git mv plans/todo/<file> plans/done/<file>` and commit `docs: move completed plan to plans/done/`

3. **Push the branch** (if not already pushed):
   - Run `git push -u origin <branch-name>`

4. **Check for related issues**:
   - Look at the branch name for issue numbers (e.g., `fix/896-buffer-import` references #896)
   - Check commit messages for issue references
   - Run `gh issue list --state open --limit 20` to see recent open issues that might be related
   - If the PR resolves an issue, note it for the body

5. **Generate PR title and body**:
   - Title: Use conventional commit format based on the primary change (e.g., `feat: add tree-sitter Java pattern matching`)
   - Keep the title under 72 characters
   - Body should include:
     - **Summary**: Brief description of what this PR does
     - **Changes**: Bullet list of key changes
     - **Testing**: How to test the changes (e.g., `cargo test`, manual CLI usage)
     - **Issue references**: Add `Fixes #XXX` or `Closes #XXX` for any issues this PR resolves (these will auto-close the issues when merged)

6. **Create the PR**:
   ```bash
   gh pr create --title "<title>" --body "<body>" --base main --assignee @me
   ```

7. **Report the PR URL** to the user

If the user provides arguments (e.g., `/pr "Custom title"`), use that as the PR title instead of generating one.
