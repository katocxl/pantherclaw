# The live GitHub run

**Milestone:** M8 ([G0 M8](../g0/M8.md), Tasks; exit status). **Audience:** the founder, or a maintainer with a sandbox GitHub organization.

`task test:github-live` runs the first steps of the coding-to-production scenario (§43) against GitHub itself instead of the simulator. Nothing runs it automatically: `task check` and `task test:integration` never include it. It needs `PC_GITHUB_LIVE=1` and the variables below, and the test skips without them.

The run checks these things against the real API:

1. Through the gateway, with a token the gateway mints for each action, the agent can do four things: read `README.md`, create a branch, write a file on that branch, and open a pull request.
2. The merge is held (`REQUIRE_APPROVAL`, `MERGES_NEED_AN_INDEPENDENT_REVIEW`). The decision and its reasons are the same over MCP (`/mcp/github`) and over REST (`/github`).
3. Nothing is merged.

The approval, change window and budget steps stay on the simulator (`TestE2E_M8_CodingToProduction`). They need people and keys that a sandbox organization does not have.

## 1. Prepare a sandbox (once)

1. Create a GitHub organization used only for testing, for example `yourname-pc-sandbox`. Inside it, create a repository with a `README.md` on its default branch. A repository with no deploy workflow works. Optionally, add a workflow that deploys on push to the default branch with an `environment:`. The merge is then also held for `DEPLOYMENTS_NEED_A_RELEASE`.
2. Create a GitHub App owned by that organization. Use the permissions in the [GitHub App runbook](github-app.md) §1:
   - Contents: write
   - Pull requests: write
   - Metadata: read
   - Checks: read
   - Commit statuses: read
   - Deployments: read

   Give it no webhook, and never Workflows.
3. Install it on the sandbox repository only. Note the installation id (from the installation's settings URL) and the App's **Client ID**.
4. Generate a private key and keep the `.pem` file outside the repository, for example in `~/.pantherclaw/sandbox-app.pem`. Never use a production App or key.

## 2. Run it

Start the test database and the mock OpenID provider as for `task test:integration` (`task up PROFILE=test`). Then run these from Git Bash:

```bash
export PC_GITHUB_LIVE=1 PC_GITHUB_LIVE_APP=<client id> PC_GITHUB_LIVE_INSTALLATION=<installation id> PC_GITHUB_LIVE_REPO=<org>/<repo> PC_GITHUB_LIVE_KEY_FILE=$HOME/.pantherclaw/sandbox-app.pem
```

```bash
go tool -modfile=tools/pins/task/go.mod task test:github-live
```

`PC_GITHUB_LIVE_API` overrides the API URL. The default is `https://api.github.com`; set it for GitHub Enterprise Server.

The test seals the key into the throwaway stack's connection, as `pclaw seal --github-app` does. The key never leaves your machine except to sign App JWTs sent to GitHub.

## 3. Afterwards

- The test closes its pull request and deletes its `pantherclaw-live/<id>` branch, using an installation token it mints itself, past PantherClaw, only for setup and cleanup. If a cleanup step fails, the log says what to delete by hand.
- The log line `held for [...]` shows the reasons. Record the date, the result and those reasons in the M8 exit status ([G0 M8](../g0/M8.md)).
- Unset the variables, or close the shell.

## Troubleshooting

- **`GitHub POST /app/installations/…/access_tokens: 401`.** The client id, installation id and key do not belong together, or the machine's clock is off by more than a minute.
- **`read: 502` or `CANNOT_AUTHORIZE`.** The gateway could not mint a token or read a fact. Check the App's permissions against §1. A missing permission fails closed.
- **The merge is held for `CONSEQUENCE_UNKNOWN`.** The repository's workflows could not be read or evaluated. This is expected for workflows the parser does not understand (R-19).
