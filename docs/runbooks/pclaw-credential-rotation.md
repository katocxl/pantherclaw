# `pclaw credential rotation`

**Milestone:** M22 ([G0 M22](../g0/M22.md) D5). **Audience:** operators who rotate a GitHub App key held in PantherClaw custody. This page follows the brief and was written before the commands landed; the M22 exit status records any change.

Rotation is target-confirmed (F424): the new key is tested at GitHub through the gateway before it is used, rollback stays possible until confirmation, and the old key is revoked only when GitHub refuses it. M22 makes the existing service reachable from the command line. It adds no new rule: permissions, step-up, protected change, edition and audit stay as the service enforces them, and no command prints a secret (HR-553).

## Commands

| Command | What it does |
|---|---|
| `pclaw credential rotation request` | Opens a rotation for a connection |
| `pclaw credential rotation seal` | Seals the candidate key |
| `pclaw credential rotation test` | Tests the candidate at GitHub through a gateway lease |
| `pclaw credential rotation activate` | Activates a tested candidate: a person, a fresh step-up and a protected change |
| `pclaw credential rotation rollback` | Goes back to the old key, only before confirmation; gated like activation |
| `pclaw credential rotation confirm` | Asks the gateway to check that GitHub refuses the old key, then revokes it |
| `pclaw credential rotation cancel` | Cancels a rotation that has not been activated |
| `pclaw credential rotation get` | Shows one rotation |
| `pclaw credential rotation list` | Lists rotations |

Flags are in `pclaw credential rotation <command> --help` once the commands land.

## Order of a rotation

1. `request`, then `seal`, then `test`.
2. `activate` after the test passes. The change waits for its publisher if the protected surface needs one.
3. Check that the connection works, then `confirm`. If it does not work, `rollback`.

Only one rotation of a connection runs at a time (`ROTATION_IN_PROGRESS`), and only a GitHub App key can be rotated this way (`ROTATION_NOT_GITHUB_APP`). In the console, secret entry stays on a server page.

See also [key-rotation.md](key-rotation.md) for the keys PantherClaw itself holds.
