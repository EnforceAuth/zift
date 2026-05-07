# Commit Changes

Stage and commit the current changes with a well-crafted message.

## Instructions

When activated, commit the current working tree changes:

1. **Sync with remote**:
   - Run `git fetch origin main` to get latest upstream
   - Run `git log HEAD..origin/main --oneline` to check if main has moved ahead
   - If it has, pull main into the working state before committing — either
     `git merge origin/main` on a feature branch, or use the new-branch path
     in step 2 if the current branch is no longer the right home for this work
     (e.g. its name references a different issue/PR than what's being committed).

2. **Ensure we're on a branch dedicated to this work**:
   - Run `git branch --show-current`
   - Create a fresh feature branch off `origin/main` if **any** of the following hold:
     - Current branch is `main`
     - Current branch's name references a different issue/PR than the work being
       committed (e.g. branch is `refactor/71-…` but the diff implements #58)
     - Current branch already merged upstream (its work is in `origin/main`)
   - To create the new branch:
     - Stash uncommitted work (`git stash push -m "wip: <issue>"`)
     - `git checkout -b <type>/<issue-number>-<descriptive-name> origin/main`
     - If a prior commit on the old branch belongs to this work, cherry-pick it:
       `git cherry-pick <hash>`
     - `git stash pop`
     - Inform the user of the new branch name

3. **Review changes**:
   - Run `git diff --stat` and `git diff --staged --stat` to see what's changed
   - If nothing is staged, run `git add -A` to stage everything
   - Run `git diff --staged --stat` to confirm what will be committed

4. **Generate commit message**:
   - Use conventional commit format: `type: short description`
   - Types: `feat`, `fix`, `refactor`, `chore`, `docs`, `test`
   - If the change is substantial, add a body paragraph separated by a blank line
   - Body should explain **what** changed and **why**, not how (the diff shows how)
   - Keep the subject line under 72 characters

5. **Commit**:
   ```bash
   git commit -m "<message>"
   ```

6. **Report** the commit hash and summary to the user

If the user provides arguments (e.g., `/commit "fix: resolve tree-sitter parse edge case"`), use that as the commit message instead of generating one.
