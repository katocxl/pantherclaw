# `pclaw ci check`

**Milestone:** M23 ([G0 M23](../g0/M23.md) D120–D124). **Audience:** teams that keep policy in a repository. This page follows the brief and was written before the command landed; the M23 exit status records any change.

`pclaw ci check` checks a policy change from files alone, with no server and no network.

```
pclaw ci check --policy F [--base F] [--scenarios DIR] [--packages DIR] [--format text|json|markdown] [--fail-on widen|any]
```

| Flag | Meaning |
|---|---|
| `--policy F` | The policy file to check |
| `--base F` | The policy to compare with |
| `--scenarios DIR` | Scenario fixtures |
| `--packages DIR` | Tool package definitions |
| `--format` | `text`, `json` or `markdown` |
| `--fail-on` | Fail on a widening (`widen`) or on any change (`any`) |

| Exit code | Meaning |
|---|---|
| 0 | Passed |
| 1 | A check failed |
| 2 | Usage error |

## What the report shows

Validation, scenario results, rule changes by direction, and outcome samples. Samples state how many were taken: "N sampled; an empty sample proves nothing". A passing check shows that these checks passed on these inputs. It says nothing about routes or live behaviour.

Markdown output escapes everything that comes from a policy file (backticks, `@`, links, HTML) and is capped at 60 KiB, so policy text cannot mention a person or render markup.

## GitHub Action

`integrations/github-action` is a composite action, Apache-2.0. It needs no secrets, pins its steps by SHA and checksum-verifies `pclaw`.

| Input | Meaning |
|---|---|
| `policy` | The policy file |
| `base-ref` | The ref to compare with |
| `scenarios` | Scenario directory |
| `packages` | Package directory |
| `pclaw-version` | The `pclaw` version to fetch |
| `comment` | Post the report on the pull request |

Run it on `pull_request` only, never `pull_request_target`. The comment is skipped on forks. A comment needs `GITHUB_TOKEN` with `pull-requests: write` and nothing more.

## GitLab component

`integrations/gitlab/templates/pantherclaw-check.yml` is a CI component, Apache-2.0, that runs the same check. Its README lists the inputs.
