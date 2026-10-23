# Runbook — Backup and restore

**Status:** stub (completed and drilled in M13).

- **Local/self-hosted:** nightly `pg_dump --format=custom` of the PantherClaw database, encrypted with `age` to an offline recipient key, retained 14 days; WAL archiving for PITR when running on a VM.
- **Managed Postgres (upgrade):** provider PITR (≥ 7 days) + weekly logical export.
- **What must also be backed up:** KEK material (via the key provider, never alongside DB backups), gateway broker keys (or re-enroll gateways), offline roots (offline media, two copies).
- **Restore drill (quarterly from M13):** restore into an isolated environment → run `pclaw verify` over the ledger (chain + checkpoints) → run invariant suite against restored data → record RTO/RPO achieved in GATES_AND_REVIEW (G4 entry).
- After restore, keep the maintenance hold on while replaying the shipped tightening security events and running `pantherclaw-server keys bump-epochs --all --confirm`. The command raises every non-DELETED org's epoch, including SUSPENDED orgs, and reports the number of irreversible DELETED orgs it skipped without writing to them (D57). Gateways must re-sync containment snapshots before serving.
