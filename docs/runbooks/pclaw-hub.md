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
| `pclaw hub update` | Installs newer versions of installed items |
| `pclaw hub status` | Shows the accepted index and whether updates exist |

| Flag | Meaning |
|---|---|
| `--source URL\|DIR` | Where to read the index: HTTPS only except loopback, no cross-host redirects, or a directory |
| `--set k=v` | Sets a parameter of the item |
| `--dry-run` | Shows what would happen and changes nothing |

Installing needs the permission `hub.install`, which only a person can hold; reading needs `hub.read`. Installing is in every edition, but a detection rule keeps its Business gate.

## What each kind becomes

| Kind | After install |
|---|---|
| `policy_template` | A DRAFT policy version |
| `detection_rule` | A draft custom rule (Business) |
| `automation` | A draft automation |
| `tool_package` | A package import, the same as importing it yourself |
| `range_scenario` | A local file; the server refuses it with `KIND_LOCAL_ONLY`. Reports label it customer-authored, and it never enters an attested pack |

## Refusals

| Code | Meaning |
|---|---|
| `HUB_SIGNATURE` | The signature does not verify |
| `HUB_EXPIRED` | The index has expired (an index lives at most 180 days) |
| `HUB_ROLLBACK` | A lower index version, or the same version with another digest |
| `HUB_DIGEST` | The item does not match the digest in the index |
| `HUB_NO_ROOT` | No root is configured and the source is not loopback |

Installing the same digest again is idempotent. The server never fetches the index: `pclaw` carries it, and keeps its own rollback state and cache in its config directory.

## Building an index

For PantherClaw's own content, with the key held offline:

```
pclaw-admin hub build --dir hub --out DIR --key F --passphrase-file F --version N --expires-days D
```
