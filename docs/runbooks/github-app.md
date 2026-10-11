# GitHub App connections

**Milestone:** M8 ([G0 M8](../g0/M8.md) decision 3, ADR-0021, HR-203, HR-204). **Audience:** an org admin who connects coding agents to GitHub through PantherClaw.

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
   | Metadata | read | always (GitHub adds it) |
   | Contents | read | `github.contents.get`, `github.branch.list` |
   | Contents | write | `github.branch.create`, `github.pull_request.merge` |
   | Pull requests | read | `github.pull_request.reviews.list` and the merge verifier |
   | Pull requests | write | `github.pull_request.create` |
   | Administration | write | `github.repository.update` only; leave it off unless you allow it |

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

`pclaw seal` checks the key (RSA, at least 2048 bits), the account and the connection's `Authorization: Bearer` binding before it seals. It seals the App's id, installation, account and key as one GitHub App credential, bound to the connection, its hosts, the broker key and its kind. Then **delete every copy of the `.pem` file**: the sealed credential is the only one PantherClaw needs. To rotate, generate a new key on GitHub, seal it again (a new version supersedes the old one) and delete the old key on GitHub.

## 3. Check it

- `pclaw credential list <connection id>` shows the active version with kind `github_app`.
- An allowed read through the gateway (`GET /github/repos/<owner>/<repo>`) answers. In the App's GitHub audit log, each action shows one token created and one revoked.
- A repository on another account, or an operation whose permission the App lacks, is refused with `credential_unavailable`. Nothing reaches GitHub except the refused token request.

## Failure modes

| Symptom | Cause | What to do |
|---|---|---|
| Every action `credential_unavailable` | The App was uninstalled, the key was deleted on GitHub, or the gateway cannot reach `api.github.com` | Check the installation; seal a new key; check the gateway's egress allow-list |
| One operation refused | The App lacks the permission its definition declares | Grant it on GitHub (the owner approves the new permission), or leave the operation refused |
| `gateway.installation_token_not_revoked` in the gateway log | Revocation failed after a dispatch | The token expires within an hour. Look for GitHub availability problems; nothing else is needed |
