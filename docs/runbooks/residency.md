# Runbook — Data residency by deployment mode

**Milestone:** M13 · **Owner:** the platform operator (self-hosted), PantherClaw (the hosted control plane) · **Status:** reference (F523; founder 2026-10-28).

Where PantherClaw keeps your data depends on the deployment mode ([ARCHITECTURE §13](../ARCHITECTURE.md#13-deployment-modes)). Retention inside the database is set per category in [retention.md](retention.md); export and deletion are in [data-requests.md](data-requests.md) and [ADR-0035](../adr/0035-export-deletion-and-lapse-retention.md).

## Self-hosted

- **All data stays in your PostgreSQL database:** organization configuration, grants, policies, the ledger, receipts, evidence, payload captures, accounts and sealed credentials.
- **Backups** follow the retention you configure for them ([backup-restore.md](backup-restore.md)).
- **Telemetry** leaves only to an OTLP endpoint you set (`telemetry.otlp.endpoint`, empty by default, so off; [observability.md](observability.md)).

## Hybrid (hosted control plane, your gateway)

The hosted control plane holds:

- organization configuration, grants and policies;
- the ledger, receipts and evidence;
- payload captures, only under a capture profile and for at most 30 days ([retention.md](retention.md#restricted-payload-capture-records-manager-auditor));
- account and IdP data;
- billing data.

**Target credentials.** They are sealed to your gateway's broker key (HPKE X-Wing) and opened only inside your gateway. The control plane stores the sealed ciphertext (`pc.credentials.sealed`) and sends it to that gateway with its configuration (HR-182). It never holds the broker key or sees the plaintext (HR-061).

**Traffic.** The gateway connects outbound only, over mTLS. Target payloads pass through your gateway; the control plane sees them only as a payload capture.

**Region.** The hosted region is named in your order form and on the PantherClaw trust page.

## SaaS

Not offered at v1.0.

## Retention after a lapse or deletion

- **Lapse.** For 90 days after a subscription lapses, enforcement, reads and export keep working. Then the organization is deleted and the deletion is verified: no rows remain in any organization table ([ADR-0035](../adr/0035-export-deletion-and-lapse-retention.md)).
- **Backups.** Data in backups lasts until those backups expire. The deletion record states that date.
