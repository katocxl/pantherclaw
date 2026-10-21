# ADR-0035 — Export, deletion and retention after a lapsed plan

**Status:** Accepted (2026-10-21; G0 M13 founder decision F2 and coordinator decisions D22, D34 and D41; the [G0 M13 brief](../g0/M13.md) records them). It answers the follow-up "retention after a plan lapses" left by milestone UI ([ADR-0031](0031-hosted-accounts-per-org-plans-and-test-seams.md), D85). Operating procedure: [data-requests.md](../runbooks/data-requests.md).

**Context.** PN-012.5 requires two things:
- a tenant-wide export of records and evidence;
- a verified tenant deletion that keeps a deletion record.

Milestone UI decided that a lapsed plan never turns protection off and that evidence stays readable and exportable for at least 30 days. It left the end of that period to M13; until now, lapsed and paused organizations have kept read access with no cutoff. People also need to be able to delete their own hosted account.

**Decision.**
1. **Export.** An org admin with a step-up creates an export, and a background job builds it:
   - canonical JSONL per table for a curated allow-list of organization tables;
   - the full-range evidence bundle with its proofs, which `pclaw verify` checks offline.

   The allow-list excludes wrapped keys and DEKs, sealed credentials, token and secret hashes, and session secrets.
   - **Manifest.** The manifest is signed with the `evidence_packs` key, plus an ML-DSA co-signature on Enterprise.
   - **Storage.** The export is stored as parts of at most 64 MiB that expire after 7 days.
   - **Size.** An export is capped at 2 GiB (`EXPORT_TOO_LARGE`); object storage for larger exports is a follow-up.
   - **Download.** Every download is audited before its first byte.
2. **Deletion on request.** An org admin with a step-up requests deletion. A 7-day cancellation window opens, every admin is notified, and any admin can cancel.
3. **The lapse** (F2, HR-393).
   - For 90 days after a lapse, enforcement, reads and export keep working, and changes stay blocked (HR-357 is unchanged).
   - The organization's admins get reminders on days 0, 30, 60 and 83.
   - Paying again before day 90 clears the lapse and restores the organization fully.
   - On day 90 or later the lapse creates a deletion request with the reason `lapse_90d` and no window, since the reminders were the notice.
4. **Executing a deletion** (HR-390..392).
   - **The role.** A dedicated database role, `pc_deleter`, used only by the deletion job, deletes the data. It can delete only an organization already marked DELETED. Organization-scoped legal holds block deletion until they are released.
   - **The order.** The job:
     1. marks the organization DELETED first, so authentication, gateway mTLS and workload authentication fail closed (D22: never open);
     2. deletes in foreign-key order, in bounded batches;
     3. destroys the organization's DEKs;
     4. reduces the organization row to a tombstone;
     5. verifies that no rows remain in any organization table.
5. **The deletion record** (HR-390).
   - It is written in the platform organization's ledger and signed with the receipts key.
   - It holds the organization, the reason, the requester, the window, start and completion times, per-table counts, the verification result and the date the last backup holding the data expires, from the configured backup retention (`backups.retention_days`, default 60, under Object Lock).
   - The requesting account can fetch it afterwards.
6. **Restores never bring deletions back** (D41).
   - Organization and account deletions are written in the platform organization's ledger as the tightening kinds `org.deleted` and `account.deleted`.
   - Their `security_event` lines are shipped off the host and carry the deletion record's digest.
   - After a restore from an earlier dump, `restore reapply` (HR-384):
     - sets the organization DELETED again, which fails closed at once;
     - requeues its deletion;
     - writes a new deletion record that notes it was re-applied, citing the original record's digest;
     - pseudonymises deleted accounts again and revokes their sessions.
7. **Account deletion** (HR-394).
   - A person deletes their own hosted account after a recent sign-in.
   - It is refused while the account is the last org admin of any active organization (`LAST_ADMIN`).
   - Otherwise:
     - the account's users in each organization are disabled and pseudonymised;
     - its personal data is scrubbed;
     - its sessions are revoked.
   - Evidence keeps opaque ids.

**Consequences.**
- PRODUCT §7 states 90 days followed by verified deletion.
- Data removed from the database survives in encrypted backups until they expire. The deletion record states that date, and F523's residency and retention commitments say so.
- New tables and the deleter role in migrations `00176`–`00179`. New threats: T-176 (premature or malicious deletion) and T-177 (export exfiltration).

**Alternatives.**
- Keeping lapsed organizations' data indefinitely: cost, and data-protection exposure.
- Deleting at the lapse: no time to pay or to export.
- Deletion without a record: unverifiable.
- Deleting with the application role: a bug or a compromise could delete across organizations.
- Exports that include secret material: a leaked export would expose credentials.
