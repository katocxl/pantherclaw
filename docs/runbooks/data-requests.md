# Runbook — Data requests: export, deletion, lapsed plans and account deletion

**Milestone:** M13 wave 2 ([G0 M13](../g0/M13.md) D22, D34; [ADR-0035](../adr/0035-export-deletion-and-lapse-retention.md); HR-390..394, T-176, T-177). **Audience:** customers' org admins, account holders and the operator. RPC names and flags follow the brief; the M13 exit status records any change.

## 1. Export an organization (org admin)

1. In Settings › Data, or with `DataRequestService.CreateExport`, start an export. It needs your step-up.
2. A background job builds the export:
   - one canonical JSONL file per table, for a curated list of organization tables;
   - the evidence bundle for the whole range, with its proofs.
   Wrapped keys and DEKs, sealed credentials, token and secret hashes, and session secrets are never included (T-177).
3. The manifest is signed with the `evidence_packs` key, plus an ML-DSA co-signature on Enterprise. Verify it, and the bundle, offline with `pclaw verify` ([evidence-verification.md](evidence-verification.md)).
4. Download the parts (each at most 64 MiB) within **7 days**; after that they expire. Every download is audited before its first byte.
5. Exports larger than 2 GiB are refused with `EXPORT_TOO_LARGE`. Narrow the range, or contact support.

## 2. Delete an organization (org admin)

1. Request deletion (Settings › Data, or `RequestDeletion`). It needs your step-up.
2. **A 7-day cancellation window** opens. Every org admin is notified, and any admin can cancel during the window. Take an export first if you need one (§1).
3. **Legal holds:** an organization-scoped legal hold blocks deletion (`DELETION_HELD`) until it is released ([retention.md](retention.md)).
4. When the window ends, the deletion job runs as the `pc_deleter` role (HR-391):
   1. it marks the organization DELETED, so sign-in, API calls, gateway mTLS and workload authentication fail closed at once and never open (HR-392);
   2. it deletes every organization table's rows in batches;
   3. it destroys the organization's encryption keys;
   4. it reduces the organization record to a tombstone;
   5. it verifies that no rows remain.
5. **The deletion record** (HR-390) is signed with the receipts key and kept in the platform organization's ledger. It holds the organization, the reason, the requester, the window, the times, the per-table counts, the verification result, and the date the last backup holding the data expires (at most 60 days, under Object Lock). The requesting account can fetch it with `GetDeletionRecord`.

## 3. Lapsed plans (hosted)

A lapsed or paused plan never turns protection off (HR-357):

| Day after the lapse | What happens |
|---|---|
| 0 | Changes are blocked; enforcement, reads and export keep working. Org admins get the first reminder |
| 30, 60, 83 | Further reminders (`billing.lapse_reminder`) |
| before 90 | Paying again clears the lapse and restores everything |
| 90 or later | A deletion request with the reason `lapse_90d` is created with no further window (the reminders were the notice), and runs as in §2, including legal holds and the deletion record (HR-393) |

Operator checks: the daily lapse job sends at most one reminder per organization, lapse and day. A comp plan or a recovered subscription clears `lapsed_at`, and no deletion request follows ([comp-plans.md](comp-plans.md), [billing-webhooks.md](billing-webhooks.md)).

## 4. Delete your account (any hosted account)

1. Sign in again (a recent sign-in is required), then delete your account in Account settings.
2. Deletion is refused with `LAST_ADMIN` while you are the last org admin of any active organization. Add another admin, or delete that organization first.
3. Otherwise (HR-394):
   - your users in every organization are disabled and renamed "deleted user <short id>";
   - your account's personal data is removed;
   - your sessions are revoked.
   Evidence keeps opaque ids, so receipts and audit trails stay verifiable.

## 5. If something goes wrong

- **A deletion you did not expect:** any org admin can cancel it during the window. After the window, the organization cannot be restored from the database. A backup restore brings it back only for the whole deployment, and only within the backup's retention ([backup-restore.md](backup-restore.md)). Treat an unexpected request as an incident (T-176).
- **A deletion job that stops:** the organization stays DELETED and keeps failing closed. The job resumes on retry; the deletion record is written only once verification succeeds.
