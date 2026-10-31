# PantherClaw policy check for GitLab CI (Apache-2.0)

A CI component that runs `pclaw ci check` on a merge request. The check reads files only: it needs no PantherClaw server, no API key and no CI/CD variable of yours. It validates the policy, runs its scenarios and the mutation gate, compares its rules with the merge request's base, and fails when the change is not provably tighter.

```yaml
include:
  - component: $CI_SERVER_FQDN/<your mirror>/pantherclaw-check@<full commit sha>
    inputs:
      policy: policies/refunds.json
      pclaw-version: 1.0.0
```

GitLab components are served from a project on your GitLab instance, so mirror this directory into one, with `templates/pantherclaw-check.yml` at its root, and include it by full commit SHA.

| Input | Required | Meaning |
|---|---|---|
| `policy` | yes | Path of the policy bundle (JSON), inside the repository. |
| `pclaw-version` | yes | The `pclaw` release to run. There is no `latest`. |
| `base-ref` | no | Commit or branch to compare with. Default: the merge request's diff base. A policy the base does not have is checked with nothing to compare; a base that cannot be fetched stops the job with exit 2. |
| `scenarios` | no | Directory of scenario fixtures. |
| `packages` | no | Directory of `package.yaml` files, with an optional `facts.json`. Default: the packages built into `pclaw`. |
| `stage` | no | The job's stage. Default `test`. |

The job runs on merge request pipelines only. It downloads the release archive and refuses it unless its SHA-256 matches the release's `checksums.txt`. It posts no comment: the job log has the text report, and `pantherclaw-report.md` is exposed on the merge request as an artifact.

## What the report means

Exit 0 passed, 1 the check failed, 2 it could not run on what it was given.

Text from a policy file is untrusted: the Markdown report keeps it in code spans, so it cannot render markup, mention a person or link an issue or commit, and the report is capped at 60 KiB.

Outcome samples are generated actions. The report says how many ran, because **an empty sample proves nothing**: samples can miss an action the two versions decide differently, and they show the policy engine alone, not grants, budgets, facts or holds. The rule diff is what decides `widen`; samples only add to it.

The check runs on the merge request's own files, so a merge request can change its scenarios and packages along with the policy. Review those as closely as the policy.

The check does not know who holds a role or which provider supplies a fact, because those are server records. The report names those checks as not made.
