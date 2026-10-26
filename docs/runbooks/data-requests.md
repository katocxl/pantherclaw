# Runbook — Data requests: export, deletion, lapsed plans and account deletion

**Milestone:** M13 wave 2 ([G0 M13](../g0/M13.md) D22, D34; [ADR-0035](../adr/0035-export-deletion-and-lapse-retention.md); HR-390..394, T-176, T-177). **Audience:** customers' org admins, account holders and the operator. RPC names and flags follow the brief; the M13 exit status records any change.

## 1. Export an organization (org admin)

1. In Settings › Data & deletion, choose **Request an export**. The canonical `/data/export` page confirms your organization and needs your security-key step-up. The Connect `CreateExport` RPC refuses `STEP_UP_REQUIRED`.
2. A background job builds the export:
   - one canonical JSONL file per table, for a curated list of organization tables;
   - the evidence bundle for the whole range, with its proofs.
   Wrapped keys and DEKs, sealed credentials, token and secret hashes, and session secrets are never included (T-177).
3. The manifest is signed with the `evidence_packs` key, plus an ML-DSA co-signature on Enterprise. Verify it, and the bundle, offline with `pclaw verify` ([evidence-verification.md](evidence-verification.md)).
4. Download the parts (each at most 64 MiB) within **7 days**; after that they expire. Every download is audited before its first byte.
5. Exports larger than 2 GiB are refused with `EXPORT_TOO_LARGE`. There is no user-selected range for an organization export; larger exports need the future object-storage path.

## 2. Delete an organization (org admin)

1. In Settings › Data & deletion, choose **Request organization deletion**. The canonical `/data/delete` page needs your security-key step-up. The Connect `RequestDeletion` RPC refuses `STEP_UP_REQUIRED`.
2. **A 7-day cancellation window** opens. Every org admin is notified, and any admin can cancel during the window. Take an export first if you need one (§1).
3. **Legal holds:** an organization-scoped legal hold blocks deletion (`DELETION_HELD`) until it is released ([retention.md](retention.md)).
4. When the window ends, the deletion job runs as the `pc_deleter` role (HR-391):
   1. it marks the organization DELETED, so sign-in, API calls, gateway mTLS and workload authentication fail closed at once and never open (HR-392);
   2. it deletes every organization table's rows in batches;
   3. it destroys the organization's encryption keys;
   4. it reduces the organization record to a tombstone;
   5. it verifies that no rows remain.
5. **The deletion record** (HR-390) is signed with the receipts key and kept in the platform organization's ledger. It holds the organization, the reason, the requester, the window, the times, the per-table counts, the verification result, and the date the last backup holding the data expires, from the configured backup retention (`backups.retention_days`, default 60, under Object Lock). The requesting account can fetch it with `GetDeletionRecord`.

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

1. Open `/account/delete` (also linked from Settings › Data & deletion). It forces a new provider sign-in with `prompt=login` and `max_age=0` before confirmation. A recent existing session is insufficient. The Connect `DeleteAccount` RPC refuses `REAUTH_REQUIRED`.
2. Deletion is refused with `LAST_ADMIN` while you are the last org admin of any active organization. Add another admin, or delete that organization first.
3. Otherwise (HR-394):
   - your users in every organization are disabled and renamed "deleted user <short id>";
   - your account's personal data is removed;
   - your sessions are revoked.
   Evidence keeps opaque ids, so receipts and audit trails stay verifiable.

Deletion is resumable. Sign-in is blocked while the durable journal prepares each organization's changes. The last-administrator checks and reservations use the same per-org locks as role changes. If any organization refuses deletion, preparation rolls back before sign-in is available again; previously revoked sessions remain revoked. Once the journal enters irreversible deletion, retries finish every linked user and the account tombstone. Older unlinked users are covered by the restricted hashed-identity guard as well. The procedure never changes tenant context inside a transaction and adds no SECURITY DEFINER function.

## 5. If something goes wrong

- **A deletion you did not expect:** any org admin can cancel it during the window. After the window, the organization cannot be brought back. Treat an unexpected request as an incident (T-176).
- **A database restore after a deletion** (operator; D41). A restore from a dump taken before the deletion brings the organization back in the restored copy. But deletions are `security_event` kinds (`org.deleted`, `account.deleted`), so `restore reapply` performs them again:
  - the organization is set to DELETED at once and fails closed;
  - its deletion is requeued;
  - a new deletion record notes "re-applied after restore" with the original record's digest;
  - deleted accounts are pseudonymised again and their sessions revoked.

  This is part of the restore procedure ([backup-restore.md](backup-restore.md) §7). Do not lift the maintenance hold until it has run.
- **A deletion job that stops:** the organization stays DELETED and keeps failing closed. The job resumes on retry; the deletion record is written only once verification succeeds.
