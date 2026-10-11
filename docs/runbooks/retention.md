# Runbook — Evidence retention and legal holds

**Milestone:** M7 · **Owner:** the platform operator (the role and the job), the org's Records Manager (periods and holds) · **Status:** tested procedure (M7 integration tests: bodies are removed only after their period and outside holds, the chain and checkpoints still verify, a shortening waits 7 days); the operator steps are drilled with the restore drill in M13.

PantherClaw keeps every evidence record, and removes only the **body** of a record whose retention period has passed: the receipt's JWS, a ledger entry's body, observed values, replay inputs, approval notes (and, with capture, payload captures). The row stays with its hashes, its chain link, its Merkle leaf and a tombstone: when the body was removed and under which policy revision. Checkpoints and `pclaw verify` still verify; a removed body is reported as *not available: body removed by retention policy receipts r2 on 2027-10-10T00:00:00Z*. Removed content is never rebuilt. Background: [g0/M7.md](../g0/M7.md) design decision 9, founder decision 4; HR-198, HR-055, T-075.

## Categories

| Category | What it covers | Default | Bounds |
|---|---|---|---|
| `payloads` | restricted payload captures | 7 days | 1–30 |
| `normalized_facts` | replay inputs, observed values | 90 days | 7–730 |
| `receipts` | decision, execution and effect receipt bodies; `receipt.*` ledger entries | 365 days | 30–3,650 |
| `approvals` | `audit.approval.*` ledger entries; approval notes | 365 days | 365–3,650 |
| `security_audit` | every other `audit.*` ledger entry | 365 days | 365–3,650 |

Grant, policy, package and connection revisions are kept while any retained receipt references them; M7 never removes them. Operational logs and traces live outside the database (SB-4, 14 days).

## The retention role and the job

`pc_retention` is a login role of its own, created by `pantherclaw-server db bootstrap`. It can only null the body columns of the evidence tables and set their tombstone, delete replay inputs (and payload captures), read the columns it needs to choose them, and append its own audit entry. A trigger refuses every other change of an evidence row, a second removal, and a rebuilt body. `pc_app` still has no UPDATE or DELETE on any evidence table (HR-055).

The worker's job runs daily per org through the audited cross-org lister (`retention_due`): an hourly dispatcher finds the orgs without a successful run in the last day. For each category it removes, oldest first and in batches of 500, the bodies older than the period in effect, and writes one `audit.evidence.retention_removed` ledger entry per batch (category, items, count, oldest, newest, policy revision). It never touches:

- anything inside an active legal hold;
- a ledger entry that no checkpoint covers yet (its body is checked against its hash first);
- chain links, Merkle tiles or checkpoints.

### Set up (new or existing deployment)

Migration `00072_retention.sql` refuses to run until the role exists. On an existing database run the bootstrap again with the new flag, then migrate:

```bash
openssl rand -hex 24 > deploy/dev/secrets/pc_retention.pw
go run ./cmd/pantherclaw-server db bootstrap --admin-url-file deploy/dev/secrets/admin.url \
  --app-password-file deploy/dev/secrets/pc_app.pw --migrator-password-file deploy/dev/secrets/pc_migrator.pw \
  --audit-password-file deploy/dev/secrets/pc_audit_ro.pw --retention-password-file deploy/dev/secrets/pc_retention.pw
go run ./cmd/pantherclaw-server migrate up --config deploy/dev/server.example.json
```

The bootstrap is idempotent; it sets the other roles' passwords again from the files you pass.

Give the worker the role's password (worker or `all` role only; the API never uses it):

```json
"database": { "retention_user": "pc_retention", "retention_password_file": "deploy/dev/secrets/pc_retention.pw" }
```

Without `database.retention_password_file` the server starts, logs `evidence.retention_disabled`, removes nothing, and every run records `ROLE_UNAVAILABLE`.

### Check the job

As `pc_audit_ro` (RLS applies, so set the org first):

```sql
BEGIN;
SELECT set_config('app.org_id', '<org id>', true);
SELECT last_attempt_at, last_run_at, last_error, removed FROM pc.retention_status;
SELECT category, revision, days, effective_from, set_by FROM pc.retention_policies ORDER BY category, revision;
COMMIT;
```

| `last_error` | Meaning | What to do |
|---|---|---|
| (empty) | The last run succeeded. | Nothing. |
| `ROLE_UNAVAILABLE` | The worker has no retention password, or cannot connect as `pc_retention`. Nothing was removed. | Set `database.retention_password_file`, check the role exists (`db bootstrap`) and its password matches; the next hourly dispatch retries. |
| `REMOVAL_FAILED` | A batch failed; earlier batches of the run committed. The log has `evidence.retention_failed` with the org. | Check the database logs for the statement; the next dispatch retries. |

## Periods (Records Manager)

A person holding `evidence.retention.manage` (the **Records Manager** role, org scope, human only) sets the periods:

```bash
pclaw retention get
pclaw retention set receipts --days 730
```

- **Lengthening** (or setting the period in effect) applies at once, and cancels a shortening that has not taken effect yet.
- **Shortening** is a weakening change: it is recorded at once and audited (`audit.evidence.retention_changed`), the org's admins and auditors are notified (`evidence.retention_shortened`), and it **takes effect 7 days later**, so a hold can still be placed. `pclaw retention get` shows it as `pending` until then. The database refuses a shorter revision that takes effect sooner.

Every change is a new, immutable revision; removals name the revision they ran under.

## Legal holds (Records Manager)

A hold applies at once: the job takes the same per-org lock as hold creation, so a batch running at that moment finishes first and the next one sees the hold.

```bash
pclaw hold create --scope transaction --id <transaction id> --reason "dispute 2026-117"
pclaw hold create --scope agent --id <agent id> --reason "incident 42"
pclaw hold create --scope time_range --start 2026-09-01T00:00:00Z --end 2026-10-01T00:00:00Z --reason "audit FY26"
pclaw hold create --scope org --reason "litigation hold"
pclaw hold list --state active
pclaw hold release <hold id> --reason "matter closed"
```

A hold covers an item through its transaction, the transaction's run and agent, its approval request, or the object an audit event names; a time range covers items recorded in `[start, end)`. Ids of another org are not found. Releasing is audited (`audit.evidence.legal_hold_released`) and notified to the org's admins and auditors; retention then applies again at the next daily run. The reasons people write stay in the hold; they are never logged or put in notifications.

## What removal does not do

- It never shortens a period by itself, and never removes anything inside an active hold.
- It never touches a chain link, a tile or a checkpoint: an attempt to delete or rewrite them is refused by the database, and the checkpoint job and the daily verification would report it (see [evidence-verification.md](evidence-verification.md)).
- A removed body is not rebuilt, and a request repeated after its evidence was removed is decided like any new request (F520).
- A replay of an evaluation whose inputs were removed is incomplete (`INPUTS_MISSING`).
