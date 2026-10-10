# Runbook — Evidence verification and integrity failures

**Milestone:** M7 · **Owner:** the platform operator, with the org's security admins · **Status:** the reset is a tested procedure (M7 integration tests: a reset org is checkpointed again when its data is intact and fails again when it is not); the investigation steps are an outline, drilled with the restore drill in M13.

Every org's evidence ledger is an RFC 9162 Merkle tree over its chained entries, with a signed checkpoint per `evidence.checkpoint_interval` and a daily re-verification of the whole chain. Background: [g0/M7.md](../g0/M7.md) design decision 8; HR-194, HR-111.

## What a failure is

The checkpoint job or the daily verification found a mismatch. The org's evidence integrity becomes `FAILED`:

- no new checkpoint is signed and the daily verification stops for that org;
- `security.evidence_integrity_failed` is written to the org's audit ledger, with the check that failed, the failure code and the first position involved (`seq`);
- the org's channels get the Critical notification of the same name (org and security admins).

Authorization never waits for this. Receipts are still written and chained, so the chain keeps growing past the last checkpoint.

| Code | Found by | Meaning |
|---|---|---|
| `CHAIN_LINK` | either | An entry's recomputed link differs from the stored one, or a position is missing: an entry was edited, inserted or deleted. |
| `CHAIN_HEAD` | checkpoint | The recomputed chain does not end at the stored head. |
| `CHECKPOINT_INVALID` | either | A stored checkpoint's signed note does not verify, or does not match its row. |
| `CHECKPOINT_MISSING` | checkpoint | The tiles hold more leaves than the latest checkpoint covers: a checkpoint was deleted. |
| `TREE_INCONSISTENT` | checkpoint | The new tree does not extend the previous checkpoint's tree (tiles under it were altered). |
| `TREE_MISMATCH` | either | The tiles or the chain give another root than the checkpoint, or tiles are missing. |

## Check the status

As the read-only evidence role `pc_audit_ro` (RLS applies, so set the org first):

```sql
BEGIN;
SELECT set_config('app.org_id', '<org id>', true);
SELECT state, failure_code, failed_seq, failed_at, verified_size, verified_at FROM pc.evidence_integrity;
SELECT tree_size, created_at FROM pc.checkpoints ORDER BY tree_size DESC LIMIT 1;
COMMIT;
```

No row means the org never failed and was never verified yet.

## Investigate before anything else

1. Treat the failure as a possible attack on the evidence until it is explained: follow [incident-response.md](incident-response.md). PantherClaw's own roles cannot edit or delete chained entries, tiles or checkpoints (`pc_app` may only insert them, HR-055). An edit or a deletion needs other write access to the database; an extra tile or checkpoint row needs the `pc_app` credentials.
2. Restore the most recent backup from before `failed_at` into an isolated environment ([backup-restore.md](backup-restore.md)) and compare, around `failed_seq`, the rows of `ledger_entries`, `ledger_chain`, `ledger_tiles` and `checkpoints` for the org. Run `pclaw verify` on a bundle exported from each side.
3. Find out who changed what, and when, from the database's own logs and access records.
4. Tell the org's security admins what you found. They received the failure notification and will receive the reset notification.

Then choose:

- **The data can be put back exactly** (the original bytes, from a backup): put it back as the database owner, record what you changed, then reset.
- **The cause was not a change to evidence** (for example a restore that dropped rows, which you then recovered): fix the cause, then reset.
- **The evidence cannot be put back:** do not reset in the hope that it passes. It fails again, because no checkpoint is ever signed over a tree inconsistent with the last one (HR-194), and nothing re-signs history. Keep the org `FAILED`, record the affected range in the incident, and tell the org's admins and auditors which period their evidence no longer proves.

## Reset

Run on a host with the server's configuration (database access as `pc_app`):

```bash
pantherclaw-server evidence integrity reset --org <org id> --reason "<what you found and what you did>" --confirm --config /etc/pantherclaw/server.json
```

In one tenant transaction, as `pc_app`:

- the status goes from `FAILED` back to `OK`; only a `FAILED` row changes (HR-004), and the failure fields and the last verification are cleared;
- `evidence.integrity_reset` is written to the org's audit ledger, by `operator`/`evidence-integrity-reset`, with the cleared `failure_code`, `failed_seq` and `failed_at`, and your reason;
- the org's channels get `security.evidence_integrity_reset` (Warning). It names the cleared code only: the reason is free text, so it stays in the audit ledger (HR-158).

Without `--confirm` nothing changes. The reason must be 1 to 500 bytes on one line, without control or bidi characters. For an org that is not `FAILED` the command prints `nothing changed`, exits 0, and audits and notifies nothing.

## After the reset: nothing was repaired

The reset only lets the checks run again. The command says so too.

- **Checkpoint job.** The reset's own audit entry grows the org's chain, so within `evidence.checkpoint_interval` (default 5 minutes) the dispatcher lists the org again. The job verifies the latest checkpoint's signed note against its row, checks that the tiles hold no more leaves than it covers, recomputes every chain link since it from the entries, and proves the new tree consistent with it before signing.
- **Daily verification.** The reset cleared the last verification, so the next hourly dispatch lists the org at once. It recomputes every link from genesis and the root from the chain, and checks every stored tile.
- **If anything is still broken,** the org fails again: a new `security.evidence_integrity_failed` entry and notification, and checkpointing stops again. An entry edited inside a range a checkpoint already covers, or a full tile altered under it, is found only by the daily verification. So do not close the incident before it has run.

The incident is closed when the status query shows `OK` with a `verified_at` later than the reset, and a checkpoint whose `tree_size` covers the reset's audit entry.

## Errors

| Message | Meaning |
|---|---|
| `run again with --confirm` | Nothing changed. Investigate first, then confirm. |
| `a reason of 1 to 500 bytes …` | Give a one-line reason without control or bidi characters. |
| `no such organization` | Check the org id. |
| `… is not FAILED: nothing changed` | The org has not failed, or another operator reset it already. Check the status. |
