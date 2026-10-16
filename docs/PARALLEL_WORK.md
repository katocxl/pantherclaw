# Parallel work: several AI sessions on one repository

Read this before you start any task in this repository. It applies to every Claude Code session (desktop tab, terminal or IDE) and to people. It works together with the pull-request rule in [CLAUDE.md](../CLAUDE.md) ([EX-005](security/GATES_AND_REVIEW.md#4-exceptions)).

## How work reaches `main`

Every task ends as a pull request. CI runs on it, and the session turns on squash auto-merge, so GitHub merges it as soon as the required check `ci-ok` is green. A pull request that changes `.github/` is the exception: the founder merges it. Two tasks can still change the same lines; that shows up as a conflict on the second pull request after the first one merges, and the session that owns it resolves it on its branch.

| Branch | What it is | Rules |
|---|---|---|
| `main` | What is on GitHub. | Changes only through a merged pull request with a green `ci-ok` (the `main` ruleset requires both). Never commit on it or push to it. |
| your branch | One task: `feat/…`, `fix/…`, `docs/…`, or the `claude/…` branch the desktop app gave your worktree. | One session per branch, in its own worktree. Push it and open a pull request. |

## The loop for every task

1. **Get a worktree of your own.** The desktop app gives each session one under `.claude/worktrees/`. Never work in another session's worktree: two sessions in one folder overwrite each other's files. A new worktree lacks the git-ignored `deploy/compose/.env` (the test database password), so copy it from the main checkout before you run the integration tests: `cp "$(git worktree list | head -1 | cut -d' ' -f1)/deploy/compose/.env" deploy/compose/.env`.
2. **Look at what is in flight:** `gh pr list` shows the open pull requests and `gh pr diff <n> --name-only` the files each one changes. If your task needs the same files, tell the founder before you start. Either build on that pull request's branch (a stacked pull request), or put your code in new files and keep your edits to the shared files to a few lines.
3. **Start** from the latest `origin/main`: `git fetch origin`, then `git switch -c <type>/<slug> origin/main`. In a desktop worktree that already has a `claude/…` branch, run `git rebase origin/main` before your first commit. For stacked work, start from the branch you build on instead.
4. **Work in small steps.** A task should take about 30–60 minutes of agent time and stay under about 600 lines of non-generated diff ([BUILD_GUIDE](BUILD_GUIDE.md) §0). Split bigger work into several pull requests. Commit often.
5. **Check locally** before you push. CI runs the same checks again, and a red `ci-ok` only delays the merge, so catch failures here:
   - always `task check` (format, headers, lint, unit tests, secret scan);
   - `task test:integration` when you touched database, server, gateway or end-to-end code (cluster on `127.0.0.1:5433`; start it with `task up PROFILE=test`);
   - `task trace` when you added or renamed `HR-###` or `T-###` tests.
   - `task range` when you touched `internal/authority`, `internal/gateway`, `internal/sandbox`, `internal/redteam`, `packages/`, `redteam/` or `test/e2e/` (cluster as above; `SANDBOX=1 task range` when `internal/sandbox` changed, needs Docker). It runs every attack scenario against the simulators; CI's `range` job repeats it. Report its result.

   They take minutes, so run them in the background. Never weaken a test or an `HR-###` rule to make one pass.
6. **Open the pull request:** `git push -u origin HEAD`, then `gh pr create --base main` (or `--base <branch>` for stacked work). Say what changed, which checks ran and their result, and which pull request yours depends on.
7. **Turn on auto-merge:** `gh pr merge <number> --auto --squash`, only when the base is `main`, the pull request is not a draft and `gh pr diff <number> --name-only` shows nothing under `.github/`. GitHub merges it when `ci-ok` passes.
8. **Report** the pull request link to the founder and keep an eye on its CI (`gh pr checks <number>`). If `ci-ok` fails, fix the cause on your branch and push; auto-merge stays on. Then start the next task. Never merge by hand, not even your own pull request.

## Keeping an open pull request up to date

When your pull request conflicts (for example after another one merged), merge `origin/main` into your branch, resolve the conflicts, run the checks again and push; auto-merge then waits for the new `ci-ok`. Merging keeps branches stacked on yours intact; never force-push a branch another pull request is built on. When a stacked pull request's base merges, GitHub retargets the next one to `main` and deletes the merged branch; its owner then turns on auto-merge for it (step 7).

## Shared files: where conflicts come from

These files are touched by many tasks. Keep your edits to them small and prefer new files:

- server wiring: `internal/server/server.go`, `procedures.go`, `config.go` (add a `register…` function or a `wiring_<area>.go` file instead of growing `apiHandler`);
- the permission and role catalog: `internal/tenancy/domain/permissions.go`, `roles.go`;
- generated code: `internal/gen/**` (from `queries/*.sql`, `proto/**`, `sqlc.yaml`, `buf.gen.yaml`);
- `go.mod` / `go.sum`, `Taskfile.yml`;
- numbered things: `migrations/000NN_*.sql`, `HR-###` in [HARDENING_RULES](security/HARDENING_RULES.md), `T-###` in [THREAT_MODEL](security/THREAT_MODEL.md), proto field numbers;
- G0 briefs in `docs/g0/` and [FEATURES.md](FEATURES.md).

**Numbers.** Use the range the founder or the G0 brief gave your task. If there is none, take the next number that is free on `main` *and* in every open pull request (`gh pr list`, then look at their diffs), and say which numbers you took in the pull request description. A duplicate migration version makes `task test:integration` fail once both are merged; renumber in the pull request that is not merged yet.

## Resolving a conflict

- **Generated code** (`internal/gen/**`): take either side, run `task gen` (it regenerates and fixes headers), and `git add` the result. Never hand-merge generated files.
- **`go.sum`**: take either side, then `go mod tidy`.
- **Everything else**: keep both sides' intent. Never drop another task's change to make yours fit. If you cannot tell what the other change needs, stop and ask the founder.
- Then commit the merge, run the checks again and push.

## Shared resources

- **Test database:** all sessions share the cluster on `127.0.0.1:5433`. Each test creates its own database, so concurrent runs are safe. If it is down, `task up PROFILE=test`. Never stop, reset or wipe containers another session may be using.
- **Targeted database tests:** to run a few database tests directly with `go test -run …` instead of `task test:integration`, set `PC_TEST_PG_ADMIN_URL` to the test cluster's admin URL (as the Taskfile does, with the password from `deploy/compose/.env`) and `PC_TEST_REQUIRE_DB=1`. Without the URL those tests skip and the run looks green; with `PC_TEST_REQUIRE_DB=1` a missing database fails instead.
- **Lint:** golangci-lint keeps one lock per machine; `task lint` waits for another session's run instead of failing.
- **Ports:** if you run a local server or gateway, use ports no other session uses.
- **Docker, the founder's credentials and GitHub settings** are shared. Change none of them unless the founder asks.

## What never happens

- No pushes to `main` and no merges by hand: a pull request merges only through auto-merge after a green `ci-ok`, or by the founder.
- No auto-merge on a pull request that changes `.github/`, and no change to the `main` ruleset, its required checks or the repository's merge settings.
- No force-push of a branch another pull request is built on, and no `git push --delete` of a branch someone else owns.

## Quick reference

```bash
gh pr list                                    # open pull requests (what is in flight)
git fetch origin && git switch -c feat/x origin/main
go tool -modfile=tools/pins/task/go.mod task check
git push -u origin HEAD && gh pr create --base main
gh pr diff <n> --name-only | grep -q '^\.github/' || gh pr merge <n> --auto --squash
gh pr checks <n>                              # watch ci-ok
```
