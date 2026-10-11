-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Retention and legal holds (G0 M7 design decision 9, HR-198). The policy
-- and hold queries run as pc_app; the Remove* queries run only as
-- pc_retention, in the retention job's transactions.

-- Serializes the retention job's batches with hold creation and policy
-- changes of one org, so a hold or a longer period that committed is seen
-- by the next batch, and a batch never races one.
-- name: LockRetention :exec
SELECT pg_advisory_xact_lock(hashtextextended('pc.retention|' || sqlc.arg(org_id)::uuid::text, 0));

-- name: ListRetentionRevisions :many
SELECT id, category, revision, days, set_by, effective_from, created_at
FROM pc.retention_policies
WHERE org_id = sqlc.arg(org_id)
ORDER BY category, revision;

-- Revision 1 of a category: its default, recorded by the system.
-- name: InsertRetentionDefault :exec
INSERT INTO pc.retention_policies (org_id, id, category, revision, days, effective_from)
SELECT sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(category), 1, sqlc.arg(days), now()
WHERE NOT EXISTS (SELECT 1 FROM pc.retention_policies p
                  WHERE p.org_id = sqlc.arg(org_id) AND p.category = sqlc.arg(category))
ON CONFLICT DO NOTHING;

-- A person's revision: at once, or 7 days later when it shortens.
-- name: InsertRetentionRevision :one
INSERT INTO pc.retention_policies (org_id, id, category, revision, days, set_by, effective_from)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(category), sqlc.arg(revision), sqlc.arg(days), sqlc.arg(set_by),
        CASE WHEN sqlc.arg(shorten)::boolean THEN now() + interval '7 days' ELSE now() END)
RETURNING effective_from, created_at;

-- name: RetentionPolicyLabels :many
SELECT id, category, revision FROM pc.retention_policies
WHERE org_id = sqlc.arg(org_id) AND id = ANY (sqlc.arg(policy_ids)::uuid[]);

-- Whether the agent, run or transaction a hold names exists in the org.
-- name: RetentionScopeExists :one
SELECT (CASE sqlc.arg(scope)::text
    WHEN 'agent' THEN EXISTS (SELECT 1 FROM pc.agents a WHERE a.org_id = sqlc.arg(org_id) AND a.id = sqlc.arg(id))
    WHEN 'run' THEN EXISTS (SELECT 1 FROM pc.runs r WHERE r.org_id = sqlc.arg(org_id) AND r.id = sqlc.arg(id))
    WHEN 'transaction' THEN EXISTS (SELECT 1 FROM pc.transactions t WHERE t.org_id = sqlc.arg(org_id) AND t.id = sqlc.arg(id))
    ELSE false END)::boolean AS found;

-- name: InsertLegalHold :one
INSERT INTO pc.legal_holds (org_id, id, scope, scope_id, range_start, range_end, reason, created_by)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(scope), sqlc.narg(scope_id), sqlc.narg(range_start),
        sqlc.narg(range_end), sqlc.arg(reason), sqlc.arg(created_by))
RETURNING *;

-- name: GetLegalHold :one
SELECT * FROM pc.legal_holds WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: ReleaseLegalHold :one
UPDATE pc.legal_holds
SET state = 'RELEASED', released_by = sqlc.arg(released_by), released_at = now(), release_reason = sqlc.arg(reason)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'ACTIVE'
RETURNING *;

-- Newest first; before is the id to continue below (nil for the first page).
-- name: ListLegalHoldsPage :many
SELECT * FROM pc.legal_holds
WHERE org_id = sqlc.arg(org_id)
  AND (sqlc.narg(state)::text IS NULL OR state = sqlc.narg(state)::text)
  AND (sqlc.narg(before)::uuid IS NULL OR id < sqlc.narg(before)::uuid)
ORDER BY id DESC
LIMIT sqlc.arg(max_rows);

-- name: RecordRetentionRun :exec
INSERT INTO pc.retention_status (org_id, last_attempt_at, last_run_at, last_error, removed)
VALUES (sqlc.arg(org_id), now(), CASE WHEN sqlc.narg(error_code)::text IS NULL THEN now() END,
        sqlc.narg(error_code), sqlc.arg(removed))
ON CONFLICT (org_id) DO UPDATE
SET last_attempt_at = excluded.last_attempt_at,
    last_run_at = coalesce(excluded.last_run_at, pc.retention_status.last_run_at),
    last_error = excluded.last_error,
    removed = pc.retention_status.removed + excluded.removed;

-- name: GetRetentionStatus :one
SELECT last_attempt_at, last_run_at, last_error, removed FROM pc.retention_status WHERE org_id = sqlc.arg(org_id);

-- The retention job, as pc_retention. Entries lose their body only once
-- chained and covered by a checkpoint (up to sealed_seq).
-- name: RetentionSealedSeq :one
SELECT coalesce(max(tree_size), 0)::bigint AS seq FROM pc.checkpoints WHERE org_id = sqlc.arg(org_id);

-- name: RemoveLedgerBodies :many
WITH due AS (
    SELECT e.org_id, e.id
    FROM pc.ledger_entries e
    JOIN pc.ledger_chain l ON l.org_id = e.org_id AND l.entry_id = e.id
    WHERE e.org_id = sqlc.arg(org_id) AND e.body_removed_at IS NULL AND e.occurred_at < sqlc.arg(cutoff)
      AND e.kind LIKE sqlc.arg(kind_like)::text AND e.kind NOT LIKE sqlc.arg(kind_not_like)::text
      AND l.seq <= sqlc.arg(sealed_seq)
      AND NOT pc.retention_held(e.occurred_at, coalesce(
          (SELECT d.transaction_id FROM pc.decision_receipts d WHERE d.org_id = e.org_id AND d.ledger_entry_id = e.id LIMIT 1),
          (SELECT x.transaction_id FROM pc.execution_receipts x WHERE x.org_id = e.org_id AND x.ledger_entry_id = e.id LIMIT 1),
          (SELECT f.transaction_id FROM pc.effect_receipts f WHERE f.org_id = e.org_id AND f.ledger_entry_id = e.id LIMIT 1),
          pc.ledger_object(e.body)))
    ORDER BY e.occurred_at, e.id
    LIMIT sqlc.arg(max_rows)
)
UPDATE pc.ledger_entries u
SET body = NULL, body_removed_at = now(), removed_by_policy = sqlc.arg(policy_id)
FROM due
WHERE u.org_id = due.org_id AND u.id = due.id
RETURNING u.occurred_at;

-- name: RemoveDecisionReceiptBodies :many
WITH due AS (
    SELECT r.org_id, r.transaction_id, r.evaluation
    FROM pc.decision_receipts r
    WHERE r.org_id = sqlc.arg(org_id) AND r.body_removed_at IS NULL AND r.created_at < sqlc.arg(cutoff)
      AND NOT pc.retention_held(r.created_at, r.transaction_id)
    ORDER BY r.created_at
    LIMIT sqlc.arg(max_rows)
)
UPDATE pc.decision_receipts u
SET receipt_jws = NULL, body_removed_at = now(), removed_by_policy = sqlc.arg(policy_id)
FROM due
WHERE u.org_id = due.org_id AND u.transaction_id = due.transaction_id AND u.evaluation = due.evaluation
RETURNING u.created_at;

-- name: RemoveExecutionReceiptBodies :many
WITH due AS (
    SELECT r.org_id, r.attempt_id
    FROM pc.execution_receipts r
    WHERE r.org_id = sqlc.arg(org_id) AND r.body_removed_at IS NULL AND r.created_at < sqlc.arg(cutoff)
      AND NOT pc.retention_held(r.created_at, r.transaction_id)
    ORDER BY r.created_at
    LIMIT sqlc.arg(max_rows)
)
UPDATE pc.execution_receipts u
SET receipt_jws = NULL, body_removed_at = now(), removed_by_policy = sqlc.arg(policy_id)
FROM due
WHERE u.org_id = due.org_id AND u.attempt_id = due.attempt_id
RETURNING u.created_at;

-- name: RemoveEffectReceiptBodies :many
WITH due AS (
    SELECT r.org_id, r.transaction_id, r.seq
    FROM pc.effect_receipts r
    WHERE r.org_id = sqlc.arg(org_id) AND r.body_removed_at IS NULL AND r.created_at < sqlc.arg(cutoff)
      AND NOT pc.retention_held(r.created_at, r.transaction_id)
    ORDER BY r.created_at
    LIMIT sqlc.arg(max_rows)
)
UPDATE pc.effect_receipts u
SET receipt_jws = NULL, body_removed_at = now(), removed_by_policy = sqlc.arg(policy_id)
FROM due
WHERE u.org_id = due.org_id AND u.transaction_id = due.transaction_id AND u.seq = due.seq
RETURNING u.created_at;

-- name: RemoveObservedValues :many
WITH due AS (
    SELECT o.org_id, o.id
    FROM pc.observations o
    WHERE o.org_id = sqlc.arg(org_id) AND o.body_removed_at IS NULL AND o.observed_at < sqlc.arg(cutoff)
      AND NOT pc.retention_held(o.observed_at, o.transaction_id)
    ORDER BY o.observed_at
    LIMIT sqlc.arg(max_rows)
)
UPDATE pc.observations u
SET fields = NULL, body_removed_at = now(), removed_by_policy = sqlc.arg(policy_id)
FROM due
WHERE u.org_id = due.org_id AND u.id = due.id
RETURNING u.observed_at;

-- name: RemoveApprovalNotes :many
WITH due AS (
    SELECT n.org_id, n.id
    FROM pc.approval_evidence n
    WHERE n.org_id = sqlc.arg(org_id) AND n.body_removed_at IS NULL AND n.created_at < sqlc.arg(cutoff)
      AND NOT pc.retention_held(n.created_at, n.request_id)
    ORDER BY n.created_at
    LIMIT sqlc.arg(max_rows)
)
UPDATE pc.approval_evidence u
SET note = NULL, body_removed_at = now(), removed_by_policy = sqlc.arg(policy_id)
FROM due
WHERE u.org_id = due.org_id AND u.id = due.id
RETURNING u.created_at;

-- Replay inputs are deleted whole: a replay of them is then incomplete
-- (F507).
-- name: DeleteEvaluationInputs :many
WITH due AS (
    SELECT i.org_id, i.transaction_id, i.evaluation
    FROM pc.evaluation_inputs i
    WHERE i.org_id = sqlc.arg(org_id) AND i.created_at < sqlc.arg(cutoff)
      AND NOT pc.retention_held(i.created_at, i.transaction_id)
    ORDER BY i.created_at
    LIMIT sqlc.arg(max_rows)
)
DELETE FROM pc.evaluation_inputs u
USING due
WHERE u.org_id = due.org_id AND u.transaction_id = due.transaction_id AND u.evaluation = due.evaluation
RETURNING u.created_at;
