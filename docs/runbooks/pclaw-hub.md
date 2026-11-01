# `pclaw hub`

**Milestone:** M23 ([G0 M23](../g0/M23.md) D100–D107). **Audience:** people who install PantherClaw's signed content. This page follows the brief and was written before the commands landed; the M23 exit status records any change.

Hub is a static directory of signed content published by PantherClaw: policy templates, detection rules, range scenarios, tool packages and automations. Items hold no code. Until the offline root ceremony, Hub signs with the development key, which works on loopback only; elsewhere an empty root refuses with `HUB_NO_ROOT`.

**Installing changes no behaviour.** An install creates a draft or imports a package. Nothing is activated, published, enabled or pinned, and the normal review gates then apply.

## Commands

| Command | What it does |
|---|---|
| `pclaw hub search` | Searches the index |
| `pclaw hub show` | Shows one item |
| `pclaw hub install` | Installs an item; the server verifies it again |
| `pclaw hub update` | Reports newer versions of installed items; it installs nothing |
| `pclaw hub status` | Shows the accepted index and whether updates exist. It also lists failed installs as `name@ver  FAILED  "reason"`; the reason is at most 500 characters and shows the error code and public message |

| Flag | Meaning |
|---|---|
| `--source URL\|DIR` | Where to read the index: HTTPS only except loopback, no cross-host redirects, or a directory |
| `--set k=v` | Sets a parameter of the item |
| `--dry-run` | Shows what would happen and changes nothing |
| `--scenario-dir` | Where a range scenario is written locally; default `./pantherclaw-scenarios` |

Installing needs the permission `hub.install`, which only a person can hold; reading needs `hub.read`. OrgAdmin, SecurityAdmin, PolicyAuthor and AutomationAuthor hold both, and Auditor holds `hub.read`. Each kind's own gate still applies. Installing is in every edition, but a detection rule keeps its Business gate.

An item is at most 384 KiB and a compact index at most 624 KiB, with at most 1,000 items. Anything larger is refused, never cut short.

## What each kind becomes

| Kind | After install |
|---|---|
| `policy_template` | A DRAFT policy version |
| `detection_rule` | A draft custom rule (Business) |
| `automation` | A draft automation |
| `tool_package` | A package import, the same as importing it yourself: it advances package anti-rollback, and the version stays REVIEWED and decides nothing until activated |
| `range_scenario` | A local file; the server refuses it with `KIND_LOCAL_ONLY`. Reports label it customer-authored, and it never enters an attested pack |

## Refusals

| Code | Meaning |
|---|---|
| `HUB_SIGNATURE` | The signature does not verify |
| `HUB_EXPIRED` | The index has expired (an index lives at most 180 days) |
| `HUB_ROLLBACK` | A lower index version, or the same version with another digest |
| `HUB_DIGEST` | The item does not match the digest in the index |
| `HUB_NO_ROOT` | No root is configured and the source is not loopback |
| `HUB_ITEM_INVALID` | The item is not valid |
| `HUB_ENVIRONMENT` | No single active environment has that slug |
| `HUB_INSTALL_BUSY` | The same install is already in progress |

Installing the same digest again is idempotent. A crash during a policy install can leave one unused draft: a retry that cannot match it makes a new draft and records that one, and the first stays inert. An automation install accepts a leftover draft, including one an admin already validated or tested, so retrying picks it up, and nothing activates. One that finds a retired or published leftover ends FAILED, with a reason naming that automation. The server never fetches the index: `pclaw` carries it, and keeps its own rollback state and cache in its config directory.

## Building an index

For PantherClaw's own content, with the key held offline:

```
pclaw-admin hub build --dir hub --out DIR --key F --passphrase-file F --version N --expires-days D
```
