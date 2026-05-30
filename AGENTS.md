# Repository Instructions

Follow the conventions in `CLAUDE.md` and `CONTRIBUTING.md`.

For Codex sessions, prefix shell commands with `rtk`.

## Pull Requests And Releases

Use conventional-commit PR titles. This repository squash-merges PRs, and the squash commit message comes from the PR title.

The `Auto Release` workflow only creates a new version tag when both release gates pass:

- The merge changes Go code, `go.mod`, or `go.sum`.
- The squash commit starts with `feat:`, `feat(...)`, `fix:`, or `fix(...)`.

When a Go change should publish new binaries, title the PR with a release-triggering prefix such as `fix(scope): ...` or `feat(scope): ...`.
