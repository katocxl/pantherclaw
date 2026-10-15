# The live GitHub run

**Milestone:** M8 ([G0 M8](../g0/M8.md), Tasks; exit status) and the v0.1.0 preview. **Audience:** the founder, or a maintainer with a sandbox GitHub organization.

`task test:github-live` runs the coding-agent scenarios against GitHub itself instead of the simulator. Nothing runs it automatically: `task check` and `task test:integration` never include it. It needs `PC_GITHUB_LIVE=1`, the variables below and Docker, and the tests skip without them.

It runs three tests against the real API:

1. `TestLive_GitHub_MergeIsHeld` (M8). Through the gateway, with a token the gateway mints for each action, the agent reads `README.md`, creates a branch, writes a file and opens a pull request. The merge is held (`REQUIRE_APPROVAL`, `MERGES_NEED_AN_INDEPENDENT_REVIEW`), the same over MCP (`/mcp/github`) and REST (`/github`). Nothing is merged.
2. `TestLive_GitHub_ThreeRoutes` (the three routes and the three stops). Two `pclaw sandbox run` sessions, with the MCP merge between them:
   - **Setup through the edge (session 1).** The sandbox edge maps the agent's `api.github.com` to the gateway. The agent reads, creates a branch, writes a file and opens a pull request. All four are allowed.
   - **The MCP merge.** The gateway's MCP face is not reachable from the sandbox, so the host makes it as the agent's workload. It is held for `MERGES_NEED_AN_INDEPENDENT_REVIEW`.
   - **The raw merge (session 2).** A `curl`-style `PUT …/merge` to `api.github.com` from inside the sandbox is held and not merged. It has the same ActionIR hash (once channel and per-call ids are one call's), dedupe key, decision and reasons as the MCP merge.
   - **A push with planted credentials.** The agent finds a PAT in `/workspace/.env` and an SSH key in `/workspace/.ssh/id_ed25519`, both generated for this run and never real. It tries git over HTTPS and over SSH. Both are refused or blocked, and no branch of the repository moved.
   - **Offline proof.** The bundle of the two held attempts verifies with `pclaw verify` and no network call.
   - **Coverage.** `pclaw coverage list` shows `ENFORCED`, with an expiry within 24 hours, for `github.contents.read`, `github.branch.create`, `github.contents.write`, `github.pull.create` and `github.pull.merge`.
3. `TestLive_GitHub_CodingToProduction` (§43). The merge is held, then an independent `code_reviewer` approves with a security key (the e2e person helpers assert with a software key). The merge runs through the gateway's REST face into a throwaway base branch `pv-base-<nonce>`, created from the default branch and never merged into it. Its effect is `CONFIRMED`, and the branch head read back through the gateway equals the merge commit. The deployment it triggers needs a `release_approver` inside an open change window. Once approved, the repository's deploy workflow (§1) reports success and that effect is `CONFIRMED` too. Each wait takes up to 10 minutes.

Every object a test creates is named `pv-<nonce>` (or `pantherclaw-live/<id>` for test 1). Nothing is merged into the default branch.

## 1. Prepare a sandbox (once)

1. Create a GitHub organization used only for testing, for example `yourname-pc-sandbox`. Inside it, create a repository with a `README.md` on its default branch.
2. Add the deploy workflow below as `.github/workflows/deploy.yml` on the default branch. **The workflow is required** for test 3. On a push to a `pv-base-*` branch it runs the job in the `production` environment, which makes GitHub create a deployment and set it to `success` when the job finishes.

   ```yaml
   name: deploy
   on:
     push:
       branches: ['pv-base-*']
   jobs:
     deploy:
       runs-on: ubuntu-latest
       environment: production
       steps:
         - run: echo "deploying ${GITHUB_SHA}"
   ```

   Create the `production` environment in the repository's settings with no protection rules; PantherClaw's change window and release approver are the gate.
3. Create a GitHub App owned by that organization. Use the permissions in the [GitHub App runbook](github-app.md) §1:
   - Contents: write
   - Pull requests: write
   - Metadata: read
   - Checks: read
   - Commit statuses: read
   - Deployments: read

   Give it no webhook, and never Workflows.
4. Install it on the sandbox repository only. Note the installation id (from the installation's settings URL) and the App's **Client ID**.
5. Generate a private key and keep the `.pem` file outside the repository, for example in `~/.pantherclaw/sandbox-app.pem`. Never use a production App or key.

## 2. Prerequisites for the sandbox tests

- Docker 28 or later, running ([sandbox runbook](sandbox.md)).
- The sandbox images: `go tool -modfile=tools/pins/task/go.mod task sandbox:images` from Git Bash.
- The test database and the mock OpenID provider, as for `task test:integration` (`task up PROFILE=test`).

## 3. Run it

Run these from Git Bash:

```bash
export PC_GITHUB_LIVE=1 PC_GITHUB_LIVE_APP=<client id> PC_GITHUB_LIVE_INSTALLATION=<installation id> PC_GITHUB_LIVE_REPO=<org>/<repo> PC_GITHUB_LIVE_KEY_FILE=$HOME/.pantherclaw/sandbox-app.pem
```

```bash
go tool -modfile=tools/pins/task/go.mod task test:github-live
```

`PC_GITHUB_LIVE_API` overrides the API URL. The default is `https://api.github.com`; set it for GitHub Enterprise Server.

The tests seal the key into the throwaway stack's connection, as `pclaw seal --github-app` does. The key never leaves your machine except to sign App JWTs sent to GitHub.

## 4. Afterwards

- The tests close their pull requests and delete their `pv-<nonce>`, `pv-base-<nonce>` and `pantherclaw-live/<id>` branches, using an installation token they mint themselves, past PantherClaw, only for setup and cleanup. If a cleanup step fails, the log says what to delete by hand.
- Unset the variables, or close the shell.

## 5. Record the run

Paste the summary lines the tests log into the exit status of `docs/g0/v0.1.0.md`, with the date and the result (`ok` or the failure). Run with `-v` (the task does) and copy these lines:

- `held for [...]` (test 1),
- `three routes: …` (test 2),
- `coding to production: …` (test 3).

## Troubleshooting

- **`GitHub POST /app/installations/…/access_tokens: 401`.** The client id, installation id and key do not belong together, or the machine's clock is off by more than a minute.
- **`read: 502` or `CANNOT_AUTHORIZE`.** The gateway could not mint a token or read a fact. Check the App's permissions against §1. A missing permission fails closed.
- **The merge is held for `CONSEQUENCE_UNKNOWN`.** The repository's workflows could not be read or evaluated. This is expected for workflows the parser does not understand (R-19).
- **Test 3 waits for the deployment.** The deploy workflow did not run or did not finish. Check the repository's Actions tab for a run on the `pv-base-<nonce>` branch.
- **Docker errors.** Check `docker version` and run `task sandbox:images`.
