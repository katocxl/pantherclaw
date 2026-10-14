# Notes for AI coding sessions (Claude Code)

## Every task ends as a pull request; only the founder merges

There is no CI ([EX-004](docs/security/GATES_AND_REVIEW.md#4-exceptions), founder decisions 2026-10-09). GitHub runs nothing on a pull request: no checks, no security scans, no AI review. `main` accepts changes only through a pull request, and the founder merges them, usually in a batch when a piece of work is done. Several sessions may work at the same time; [docs/PARALLEL_WORK.md](docs/PARALLEL_WORK.md) has the details. In short:

1. Work in your own worktree, on your own branch, starting from the latest `origin/main`: `git fetch origin`, then `git switch -c <type>/<slug> origin/main` (in a desktop worktree that already has a `claude/…` branch, run `git rebase origin/main` before your first commit). Never commit on `main`. If your task builds on a pull request that is not merged yet, branch from that pull request's branch instead.
2. Commit with Conventional Commit messages. Before you open the pull request, run `task check`; also run `task test:integration` (test cluster on 127.0.0.1:5433; `task up PROFILE=test`) when you touched database, server, gateway or end-to-end code, and `task trace` when you added or renamed `HR-###`/`T-###` tests. Also run `task range` (the adversarial range; `SANDBOX=1 task range` when you touched `internal/sandbox`) when you touched `internal/authority`, `internal/gateway`, `internal/sandbox`, `internal/redteam`, `packages/` or `redteam/`, and report its result. Run long commands in the background.
3. Push your branch and open a pull request with `gh pr create`: base `main`, or the branch you built on for stacked work. The description says what changed, which checks you ran and their result, and which pull request it depends on, if any.
4. Stop there, report the pull request link to the founder, and take the next task. Never merge a pull request, never push to `main`, and never weaken a test or an `HR-###` rule to make a check pass. If a check fails or cannot run (for example Docker is down), say so in the description and to the founder.

To update an open pull request (review feedback, or a conflict after another one merged), merge `origin/main` (or the updated base branch) into your branch, run the checks again and push. Do not force-push a branch another pull request is stacked on.

Without a global Task install, run `go tool -modfile=tools/pins/task/go.mod task <name>`. On Windows run it from Git Bash, not PowerShell, which splits the `-modfile` argument.

## Where the plan lives

Start each session with [docs/BUILD_GUIDE.md](docs/BUILD_GUIDE.md) §0–§4 and the current milestone's G0 brief in [docs/g0/](docs/g0/). Binding rules are in [docs/security/HARDENING_RULES.md](docs/security/HARDENING_RULES.md). Implement only what the brief covers, and ask the founder about any security decision it leaves open. [CONTRIBUTING.md](CONTRIBUTING.md) has the conventions.
