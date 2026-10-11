# Runbook — Evidence verification, integrity failures and packs

**Milestone:** M7 · **Owner:** the platform operator, with the org's security admins; anyone with `evidence.read` verifies · **Status:** offline verification and the reset are tested procedures (M7 integration and end-to-end tests: bundles and packs from a running server verify offline and fail when tampered with; a reset org is checkpointed again when its data is intact and fails again when it is not); the investigation steps are an outline, drilled with the restore drill in M13.

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

## Verify evidence offline

Anyone holding `evidence.read` can check a transaction's evidence without trusting the deployment's database or API (G0 M7 design decision 13, HR-196, PN-007.4). Tested end to end against a running server, gateway and simulator by `TestE2E_M7_VerifyBundleOffline` and `TestE2E_M7_TamperDetected`.

1. **Pin the keys once** (trust on first use). `pclaw evidence trust` fetches `/.well-known/pantherclaw/evidence-keys.json`, prints every key's fingerprint and writes the trust file (it refuses to overwrite one). Compare the fingerprints with ones published through another channel (the operator's own page, a signed message), then keep the file:

   ```bash
   pclaw evidence trust --out trust.json --server https://pantherclaw.example.com
   ```

2. **Export a bundle** of transactions (`--txn`, up to 50; scoped like `run.read`), or of a range of at most 1,000 ledger positions (`--from`/`--to`; needs `evidence.read` and `audit.read` at org scope). Keep a checkpoint you saved earlier, for example from an earlier bundle, and pass it as `--previous`: the bundle then also holds the proof that today's tree extends it.

   ```bash
   pclaw evidence bundle --txn <transaction id> --previous saved-checkpoint.txt --out bundle.json
   ```

3. **Verify, offline.** `pclaw verify` makes no network call and needs no login. Give it Sigstore's `trusted_root.json` to check an anchor's log entry and timestamp ([anchoring.md](anchoring.md) says where to get it):

   ```bash
   pclaw verify bundle.json --trust trust.json --previous saved-checkpoint.txt --sigstore-trusted-root trusted_root.json [--json]
   ```

The report lists every check as `passed`, `failed` or `not_available`, and exits non-zero when one failed:

| Check | What it establishes |
|---|---|
| `bundle.origin` | the bundle belongs to the log origin and org the trust file names |
| `checkpoint.signature`, `checkpoint.cosignature` | each checkpoint is signed by a pinned `checkpoints` key (and the ML-DSA-65 line by a pinned `checkpoints_pq` key, when present); two different trees of the same size fail as a forked history |
| `checkpoint.consistency` | each checkpoint extends the one before it, including the one an anchor commits to |
| `witness.previous` | the bundle's history extends the checkpoint you saved (`--previous`); not available without one |
| `entry.link`, `entry.inclusion` | each entry's hash is recomputed from the entry and its predecessor's hash, and the entry is in the checkpoint's tree; a body removed by retention is not available, with the policy and the date |
| `receipt.signature`, `receipt.ledger` | each decision, execution and effect receipt is signed by a pinned `receipts` key valid when it was issued, and a chained entry records it |
| `receipt.coverage` | a decision receipt's coverage claim (G0 M9, HR-217, PAP-1 §9.1) matches the snapshot ledger. The claimed snapshot's verified `coverage.snapshot` entry has the receipt's agent, connection and operation, the claim's `snapshot_state` and exclusions, and was computed before the decision. A claim that did not lapse holds the snapshot's state, and the snapshot had not expired, no `coverage.invalidation` of the scope and no newer snapshot came before the decision. A lapsed claim is never `ENFORCED`, and its `reason` holds: the snapshot expired before the decision, or an invalidation of that kind came in between. A transaction's bundle carries, for each claim, the claimed snapshot, the scope's next snapshot and its invalidations up to the decision; a missing one is not available, and receipts without a claim have no such check |
| `anchor.leaf`, `anchor.root`, `anchor.signature`, `anchor.log`, `anchor.timestamp` | the org's blinded leaf is in the anchored global root, the statement is signed by a pinned `anchors` key, the transparency log includes it, and an authority timestamped the signature; `anchor` is not available when nothing is anchored yet, and the last two without `--sigstore-trusted-root` |

Every report ends with its limits: what passed shows the integrity of the evidence in the bundle, issued by the holder of the keys you pinned. It does not show that the bundle is complete, that an external effect happened, or that anything is certified.

**What a failure means.**
- `entry.link` failed: a stored entry no longer matches its hash. Someone changed the database; the daily verification finds the same thing (`CHAIN_LINK`, above).
- `witness.previous` or `checkpoint.consistency` failed: the deployment shows a history that does not extend one it showed before. A rewritten history signed again with the real `checkpoints` key verifies on its own (a signature proves who signed, not that nothing changed), so keep checkpoints from earlier bundles and anchor the root: they are what exposes it.
- A signature by a key that is not in your trust file: either the bundle comes from another deployment, or the deployment rotated its keys. Pin again only after checking the new fingerprints through another channel ([key-rotation.md](key-rotation.md) §7).

## Evidence packs

An evidence pack (Team edition; G0 M7 design decision 15, HR-196) is a ZIP of canonical JSON with a signed manifest. A person holding `evidence.export` asks for one with `pclaw pack create` (transactions, a run, an agent, or a time range); the worker builds it from that person's permissions when the job runs, and what they could not read is left out and listed as a gap with its reason. Download it within 7 days with `pclaw pack download ID --out pack.zip`; every download is audited (`evidence.pack_downloaded`). Check it offline with the same trust file as bundles:

```bash
pclaw verify pack.zip --trust trust.json [--sigstore-trusted-root trusted_root.json]
```

`pclaw verify` checks the manifest's signature by a pinned `evidence_packs` key, the origin, every file's SHA-256, that no file was added, the optional ML-DSA-65 co-signature, the fixed sentence "This pack supports review; it does not certify compliance.", and every verify bundle inside (receipts, chain links, inclusion proofs, checkpoints, the anchor). The gaps the manifest declares (removed bodies, transactions outside the creator's permissions, not checkpointed, not anchored, captures not available) are reported as not available. A pack that fails is changed or not from your deployment: do not rely on it.
