# Runbook — Backup and restore

**Status:** stub (completed and drilled in M13).

- **Local/self-hosted:** nightly `pg_dump --format=custom` of the PantherClaw database, encrypted with `age` to an offline recipient key, retained 14 days; WAL archiving for PITR when running on a VM.
- **Managed Postgres (upgrade):** provider PITR (≥ 7 days) + weekly logical export.
- **What must also be backed up:** KEK material (via the key provider, never alongside DB backups), gateway broker keys (or re-enroll gateways), offline roots (offline media, two copies).
- **Restore drill (quarterly from M13):** restore into an isolated environment → run `pclaw verify` over the ledger (chain + checkpoints) → run invariant suite against restored data → record RTO/RPO achieved in GATES_AND_REVIEW (G4 entry).
- After restore, keep the maintenance hold on while replaying the shipped tightening security events and running `pantherclaw-server keys bump-epochs --all --confirm`. The command raises every non-DELETED org's epoch, including SUSPENDED orgs, and reports the number of irreversible DELETED orgs it skipped without writing to them (D57). Gateways must re-sync containment snapshots before serving.

## Durable security-event delivery

The ledger chainer stores the bounded security projection in `pc.security_event_outbox` in the same transaction as its ledger link. A worker retries unacknowledged rows in batches of 500, at least five minutes after their last attempt. An attempt records local scheduling state; writing a log line does not prove that the external log store saved it. Duplicate `(org, ledger_seq)` records are expected and restore deduplicates identical copies. Conflicting copies fail validation before any changes.

The operator can export a page to a new exclusive file. Successful export fsyncs the file and leaves all rows unacknowledged:

```sh
pantherclaw-server security-log export --org ORG_UUID --out security-001.ndjson --limit 500 --config server.json
# Continue with --after LAST_SEQUENCE into a different new file.
```

Copy each page to the durable external log store, verify the complete prefix there, then explicitly acknowledge the last stored security-event sequence:

```sh
pantherclaw-server security-log ack --org ORG_UUID --through LAST_SEQUENCE --confirm --config server.json
```

ACK is audited and retains the outbox rows. Never acknowledge a prefix on the strength of a local log write or export alone. Before restoring, obtain the external security-event log covering the backup time through the incident; keep the maintenance hold on if any required record or deletion handler is missing.

Irreversible org and account erasure waits until the exact deletion-intent event is chained and explicitly ACKed after external-copy verification (F19). A missing event, an emission attempt, or an exported local file keeps the org frozen or the account pending and allows retry. Verify the external copy before using `ack`; acknowledging the wrong prefix can defeat this restore safeguard.

```sh
pantherclaw-server restore reapply --from shipped-security.ndjson --since BACKUP_RFC3339 --confirm --config server.json
pantherclaw-server keys bump-epochs --all --confirm --config server.json
```

`org.deletion_started` and `account.deletion_started` describe durable deletion intent, not verified completion. Restore applies them through the same restricted deletion handlers as their completion events, preserving the closed state while erasure resumes. Completion events carry the signed record digest separately. The external shipper and its durable retention remain operating dependencies.
