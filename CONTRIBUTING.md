# Contributing to PantherClaw

## Status

PantherClaw is being built in the open under a source-available license. **Outside code contributions are not yet accepted**: the Contributor License Agreement ([CLA.md](CLA.md)) must be in place first. Issues with bug reports and design feedback are welcome. Security issues: see [SECURITY.md](SECURITY.md) — never file them publicly.

## How work happens (also for the maintainer)

All changes follow [docs/BUILD_GUIDE.md](docs/BUILD_GUIDE.md) and the gates in [docs/security/GATES_AND_REVIEW.md](docs/security/GATES_AND_REVIEW.md):

1. **G0 brief** exists for the milestone (scope, threat slice, constraints, tests).
2. Work on a short-lived branch from `origin/main` in your own worktree, so parallel sessions don't overwrite each other ([docs/PARALLEL_WORK.md](docs/PARALLEL_WORK.md)).
3. Every source file carries the SPDX + copyright header (`task license:fix`).
4. Tests first for security-relevant behavior; reference requirement IDs (`F###`, `PN-###`, `HR-###`, `T-###`) in test names or comments.
5. `task check` must pass locally (format, lint, unit tests, headers, secrets scan), and so must `task test:integration` (start the cluster with `task up PROFILE=test`) and `task trace` when the change touches what they cover. A change to `internal/authority`, `internal/gateway`, `internal/sandbox`, `internal/redteam`, `packages/`, `redteam/` or `test/e2e/` also runs `task range` (`SANDBOX=1 task range` when `internal/sandbox` changed).
6. Commit with a [Conventional Commit](https://www.conventionalcommits.org/) message, push the branch and open a pull request. CI runs on it and `ci-ok` must be green; the founder then gives the G1 approval (a comment "G1: approved <sha>" at least 1 hour after the pull request was ready) and merges it. Commits on `main` are signed once the founder enables `required_signatures` ([EX-004](docs/security/GATES_AND_REVIEW.md#4-exceptions) ended 2026-10-15).

## Development setup

Windows, macOS and Linux are supported for development. Requirements: Go (toolchain pinned in `go.mod`) and Docker; [Task](https://taskfile.dev) is optional (a pinned copy runs via `go tool -modfile=tools/pins/task/go.mod task`); and for SDK work `uv` (Python) and `pnpm` via Corepack (TypeScript). Race detector, integration and signal tests run on Linux (`task test:linux` uses a container).

```bash
task setup    # configure git hooks (.githooks) and build the pinned dev tools
task check    # fmt + lint + unit tests + license headers + secret scan
```

## Commit conventions

- Conventional Commits (`feat:`, `fix:`, `sec:`, `docs:`, `chore:`, `refactor:`, `test:`, `ci:`, `build:`).
- One logical change per PR; generated code committed alongside its source change.
- Never commit secrets, real customer data, or descriptions of unfixed vulnerabilities.
