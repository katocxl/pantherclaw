# PantherClaw policy check for GitHub Actions (Apache-2.0)

Runs `pclaw ci check` on a pull request. The check reads files only: it needs no PantherClaw server, no API key and no secret. It validates the policy, runs its scenarios and the mutation gate, compares its rules with the base, and fails when the change is not provably tighter.

```yaml
name: policy
on:
  pull_request:

permissions:
  contents: read

jobs:
  check:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@<full commit sha>
        with:
          persist-credentials: false
      - uses: katocxl/pantherclaw/integrations/github-action@<full commit sha>
        with:
          policy: policies/refunds.json
          pclaw-version: 1.0.0
```

| Input | Required | Meaning |
|---|---|---|
| `policy` | yes | Path of the policy bundle (JSON), inside the repository. |
| `pclaw-version` | yes | The `pclaw` release to run. There is no `latest`. |
| `base-ref` | no | Commit or branch to compare with. Default: the pull request's base commit. A policy the base does not have is checked with nothing to compare. |
| `scenarios` | no | Directory of scenario fixtures. |
| `packages` | no | Directory of `package.yaml` files, with an optional `facts.json`. Default: the packages built into `pclaw`. |
| `comment` | no | `true` posts the report on the pull request. Default `false`. |

## Rules for using it

- **Use `pull_request` only, never `pull_request_target`.** The action reads files from the pull request. Under `pull_request_target` those files would run with your repository's token. The action refuses any event but `pull_request`.
- **Pin this action, and every other, by full commit SHA.** The action's own steps are pinned the same way, and `tools/cicheck` holds them to it.
- **It needs no secrets.** Without `comment`, the job needs `contents: read` and nothing else.
- **To comment, grant only `pull-requests: write`** on that job:

  ```yaml
  permissions:
    contents: read
    pull-requests: write
  ```

  The comment step is the only step that receives `GITHUB_TOKEN` for writing. It is skipped for a pull request from a fork, where GitHub gives no write token anyway, and the report stays in the job summary.
- **`pclaw` is verified before it runs.** The action downloads the release archive and refuses it unless its SHA-256 matches the release's `checksums.txt`.

## What the report means

Exit 0 passed, 1 the check failed, 2 it could not run on what it was given.

Text from a policy file is untrusted: the Markdown report escapes it, so it cannot render markup or mention a person, and the report is capped at 60 KiB. `--format json` has the rest.

Outcome samples are generated actions. The report says how many ran, because **an empty sample proves nothing**: samples can miss an action the two versions decide differently, and they show the policy engine alone, not grants, budgets, facts or holds. The rule diff is what decides `widen`; samples only add to it.

The check does not know who holds a role or which provider supplies a fact, because those are server records. The report names those checks as not made.
