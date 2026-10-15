# Notes for AI coding sessions (Claude Code)

## Every task ends as a pull request that merges itself once CI is green

CI runs on every pull request, and `main` accepts a change only through a pull request whose required check `ci-ok` is green. A pull request merges itself: the session that opens it turns on squash auto-merge, and GitHub merges it when `ci-ok` passes ([EX-005](docs/security/GATES_AND_REVIEW.md#4-exceptions), founder decision 2026-10-15). A pull request that changes anything under `.github/` (workflows, release, permissions) never gets auto-merge; the founder merges it. Several sessions may work at the same time; [docs/PARALLEL_WORK.md](docs/PARALLEL_WORK.md) has the details. In short:

1. Work in your own worktree, on your own branch, starting from the latest `origin/main`: `git fetch origin`, then `git switch -c <type>/<slug> origin/main` (in a desktop worktree that already has a `claude/…` branch, run `git rebase origin/main` before your first commit). Never commit on `main`. If your task builds on a pull request that is not merged yet, branch from that pull request's branch instead.
2. Commit with Conventional Commit messages. Before you open the pull request, run `task check`; also run `task test:integration` (test cluster on 127.0.0.1:5433; `task up PROFILE=test`) when you touched database, server, gateway or end-to-end code, and `task trace` when you added or renamed `HR-###`/`T-###` tests. Also run `task range` (the adversarial range; `SANDBOX=1 task range` when you touched `internal/sandbox`) when you touched `internal/authority`, `internal/gateway`, `internal/sandbox`, `internal/redteam`, `packages/`, `redteam/` or `test/e2e/`, and report its result. Run long commands in the background.
3. Push your branch and open a pull request with `gh pr create`: base `main`, or the branch you built on for stacked work. The description says what changed, which checks you ran and their result, and which pull request it depends on, if any.
4. Turn on auto-merge: `gh pr merge <number> --auto --squash`. Only for a pull request whose base is `main`, that is not a draft, and whose diff changes nothing under `.github/` (`gh pr diff <number> --name-only`). A stacked pull request gets it once GitHub retargets it to `main` after its base merged. A `.github/` change waits for the founder.
5. Report the pull request link to the founder and watch its CI. If `ci-ok` fails, fix the cause on your branch and push; auto-merge stays on and merges after the next green run. Never merge by hand (`gh pr merge` without `--auto`), never push to `main`, never turn off a required check or auto-merge rule, and never weaken a test or an `HR-###` rule to make a check pass. If a check fails or cannot run and you can't fix it, say so in the description and to the founder.

To update an open pull request (review feedback, or a conflict after another one merged), merge `origin/main` (or the updated base branch) into your branch, run the checks again and push. Do not force-push a branch another pull request is stacked on.

Without a global Task install, run `go tool -modfile=tools/pins/task/go.mod task <name>`. On Windows run it from Git Bash, not PowerShell, which splits the `-modfile` argument.

## Where the plan lives

Start each session with [docs/BUILD_GUIDE.md](docs/BUILD_GUIDE.md) §0–§4 and the current milestone's G0 brief in [docs/g0/](docs/g0/). Binding rules are in [docs/security/HARDENING_RULES.md](docs/security/HARDENING_RULES.md). Implement only what the brief covers, and ask the founder about any security decision it leaves open. [CONTRIBUTING.md](CONTRIBUTING.md) has the conventions.
