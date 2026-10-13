# GitHub App connections

**Milestone:** M8 ([G0 M8](../g0/M8.md) decisions 3 and 5, ADR-0021, HR-160, HR-203, HR-204, HR-206). **Audience:** an org admin who connects coding agents to GitHub through PantherClaw.

A GitHub App connection keeps the App's private key sealed to one gateway. For each action PantherClaw authorizes, that gateway does five things:

1. It signs an App JWT that lives at most 10 minutes.
2. It asks GitHub for an installation token for exactly the action's repository and its operation's declared permissions (`credential_scopes` in `packages/pc-github`).
3. It places the token on the request.
4. It sends the request.
5. It revokes the token.

The agent never holds a GitHub credential. Tokens are never cached between actions, returned, logged or stored.

## 1. Create the App (once, on GitHub)

1. Create a GitHub App owned by the organization. Set no webhook and no callback URL. Do not let it be installed outside the organization.
2. Repository permissions: give it what the operations you will allow need, and nothing more:

   | Permission | Level | Operations |
   |---|---|---|
   | Metadata | read | always (GitHub adds it); `github.installation.repositories` (the connection test); the fact reads of branch rules and of who pushed |
   | Contents | read | `github.contents.read`; the fact reads of workflow files |
   | Contents | write | `github.branch.create`, `github.contents.write`, `github.pull.merge` |
   | Pull requests | read | `github.pull.read` (also the merge verifier); the fact reads of a pull request, its commits, files and reviews |
   | Pull requests | write | `github.pull.create` |
   | Checks | read | the fact read of a pull request's check runs |
   | Administration | write | `github.repo.settings.update` only; leave it off unless you allow it |

   Never grant **Workflows**: no operation declares it, and `github.contents.write` refuses `.github/` paths.

   An operation that needs a permission the App lacks fails closed. GitHub refuses the token, and nothing is sent.
3. Install the App on the repositories the agents may touch. Note the installation id from the installation's settings URL, and the App's client id.
4. Generate a private key. GitHub downloads it once as a `.pem` file.

## 2. Create the connection

The gateway that will hold the key must already have registered its broker key ([gateway runbook](gateway.md)). Then:

```bash
pclaw connection create github --kind http --gateway <gateway id> --package pc.github --base-url https://api.github.com \
  --access pantherclaw_held --header Authorization --scheme Bearer --class public --default-mode enforce
pclaw seal --connection <connection id> --github-app <client id> --installation <installation id> --account <org login, lowercase> \
  --from-file app.pem --fingerprint <broker key fingerprint from the gateway's operator>
```

`pclaw seal` checks the key (RSA, at least 2048 bits), the account and the connection's `Authorization: Bearer` binding before it seals. It seals the App's id, installation, account and key as one GitHub App credential, bound to the connection, its hosts, the broker key and its kind. It also records the App, the installation and the account as the connection's installation. These are configuration, not secrets: `pclaw connection get` shows them, and the gateway refuses a seal that holds another installation. Then **delete every copy of the `.pem` file**: the sealed credential is the only one PantherClaw needs. To rotate, generate a new key on GitHub, seal it again (a new version supersedes the old one) and delete the old key on GitHub.

## 3. Register the gateway as the connection's fact provider

Before it decides a merge, a contents write or a branch creation, PantherClaw needs facts that only GitHub knows. These are the pull request's head, its people, reviews and checks, the base branch's rules, and whether the push would start a deployment ([G0 M8](../g0/M8.md) decision 5, HR-160, HR-206). The gateway that holds the App reads them just before each such decision, with a read-only token of its own (`metadata`, `contents`, `pull_requests` and `checks`, all `read`). The token is revoked after the read, and the gateway reports the facts as the connection's provider. Register it once:

```bash
pclaw fact-provider register --name github --gateway <gateway id> --connection <connection id> \
  --fact github.pull.head:object:github.pull_request:30s --fact github.pull.people:object:github.pull_request:30s \
  --fact github.pull.reviews:object:github.pull_request:30s --fact github.pull.checks:object:github.pull_request:30s \
  --fact github.branch.rules:object:github.pull_request:30s --fact github.repo.deploy_triggers:object:github.pull_request:30s \
  --fact github.branch.deploy_triggers:object:github.branch:30s
```

Only a person holding `fact.provider.manage` can register it. Only the gateway that serves the connection may be registered, and only for facts the connection's package names. The reads must finish within the gateway's `github.fact_timeout` (default 2s, at most 5s, in the gateway configuration under `github`).

When a fact cannot be read in time, nothing is reported for it, and the decision never guesses:

- A merge whose prerequisite is missing is `CANNOT_AUTHORIZE`.
- A missing deploy-trigger fact holds the action with "Consequence unknown", which needs a release approver.
- A workflow the gateway's parser cannot evaluate, or a pull request that changes `.github/workflows/` or `.github/actions/`, also gives "Consequence unknown".

## 4. Link people to their GitHub accounts

A reviewer must be independent of a pull request: PantherClaw refuses as reviewer anyone who authored, committed or pushed to it (HR-207). It knows those people by GitHub user id, so each person links their own GitHub account, by signing in to GitHub (founder decision 2026-10-13).

First turn GitHub sign-in on, once. Sign-in uses its own GitHub App, never the App that merges: a sign-in gives a user access token that can do whatever its App may do, so the sign-in App has no permissions and is installed nowhere.

1. Create a second GitHub App, for example "PantherClaw sign-in", under the same owner. Leave every repository, organization and account permission at **No access**. Untick **Webhook → Active**. Do not install it anywhere.
2. In its settings, under *Identifying and authorizing users*, tick **Enable Device Flow**.
3. Generate a **client secret** and save it in a file only the server can read, for example `/etc/pantherclaw/github-signin-secret` (mode 0400).
4. Put the sign-in App's **Client ID** (from its settings page, not the App ID) and the secret's file in the server configuration, then restart the server:

   ```json
   "github": { "client_id": "Iv23li…", "client_secret_file": "/etc/pantherclaw/github-signin-secret" }
   ```

   `github.web_url` and `github.api_url` default to `https://github.com` and `https://api.github.com`. For GitHub Enterprise Server, set them to `https://HOST` and `https://HOST/api/v3`. Plain `http` is accepted only for a loopback address (the GitHub simulator). Without `client_id`, nobody can link an account, so nobody can review GitHub merges.

Then each person runs:

```bash
pclaw github link            # prints a code to enter at GitHub; links the account you sign in as
pclaw github unlink          # removes your link, again by signing in to GitHub
pclaw github identity list [--user <user id>]
```

pclaw shows the code only with a sign-in page on the configured GitHub address. Enter it only at that address, and only when you ran `pclaw github link` or `unlink` yourself. An agent that asks you to enter a code is asking you to sign in for it.

The server asks GitHub, as the sign-in App, which account the token belongs to. GitHub answers only for a token the sign-in App issued, so a personal access token or a `gh` token proves nothing. The server then links the account to you, with the time you proved it, and revokes the token, so it works nowhere afterwards; PantherClaw never keeps it. Nobody can link an account for someone else. A GitHub user id links to one person; signing in again renews your link.


- **A reviewer of a GitHub merge needs a proved link.** A code reviewer or release approver without one is refused (`GITHUB_NOT_LINKED`), because PantherClaw could not tell whether they wrote the change.
- **Everyone who worked on the pull request must be linked, or exempted.** While its author, a commit author or committer, or a pusher is a person linked to nobody in the org, every approval of the merge is refused (`GITHUB_PEOPLE_NOT_LINKED`), because the approver could be that person under another account. Ask them to run `pclaw github link`. Accounts that are not people, a GitHub App's bot (`name[bot]`) or a machine user, are exempted by an identity manager:

  ```bash
  pclaw github exemption add 41898282 github-actions[bot] "GitHub Actions"
  pclaw github exemption list
  pclaw github exemption remove 41898282
  ```

  Find an account's user id at `https://api.github.com/users/LOGIN`. Every exemption change is audited and sent to the security channels. An account someone has ever linked as their own is a person and cannot be exempted, and you cannot review pull requests that list an account you exempted. Exempt the PantherClaw App's own bot, which pushes the agents' commits.
- **Links at the request count too.** The people linked to a pull request's author, committers and pushers when the merge was held stay excluded from that request, even if they unlink before it is decided.
- **Unlinking someone else:** a person holding `github.identity.manage` (Org Admin) can remove another person's link with `pclaw github identity unlink <link id>`, never their own.
- Every link and unlink is audited and sends `security.github_identity_linked` or `security.github_identity_unlinked` to the security channels. A refused attempt to link someone else's account is audited as `github.identity_link_refused`. Unlinking does not undo exclusion: whoever once proved a link to a GitHub account stays excluded from reviewing pull requests that account worked on. A service account cannot link or unlink, even when it holds the role.
- Someone who touched a pull request but is linked to no person cannot be excluded by name, so the review page shows them as "not linked".

## 5. Check it

- `pclaw credential list <connection id>` shows the active version with kind `github_app`, and `pclaw connection get <connection id>` shows the installation.
- An allowed read through the gateway (`GET /github/repos/<owner>/<repo>`) answers. In the App's GitHub audit log, each action shows one token created and one revoked.
- A repository on another account is refused with `CANNOT_AUTHORIZE` `WRONG_ACCOUNT` before it is decided, and nothing reaches GitHub.
- An operation whose permission the App lacks is refused with `credential_unavailable`. Nothing reaches GitHub except the refused token request.

## Failure modes

| Symptom | Cause | What to do |
|---|---|---|
| Every action `credential_unavailable` | The App was uninstalled, the key was deleted on GitHub, or the gateway cannot reach `api.github.com` | Check the installation; seal a new key; check the gateway's egress allow-list |
| One operation refused | The App lacks the permission its definition declares | Grant it on GitHub (the owner approves the new permission), or leave the operation refused |
| `gateway.installation_token_not_revoked` in the gateway log | Revocation failed after a dispatch or a fact read | The token expires within an hour. Look for GitHub availability problems; nothing else is needed |
| Merges `CANNOT_AUTHORIZE`, `gateway.facts_unavailable` in the gateway log | The fact token was refused: the App lacks Checks, Contents or Pull requests read | Grant the read permissions in section 1 |
| `gateway.facts_not_reported` in the gateway log | The gateway is not the connection's registered fact provider, or a fact is not declared | Register it as in section 3 |
| Merges `AUTHORSHIP_UNKNOWN` | `github.pull.people` is incomplete: a fork, more than 100 commits or pushes, or the activity feed could not be read | Expected for forks. Otherwise check that the App can read the repository's activity (Metadata read) |
