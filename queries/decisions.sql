-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Decisions of the M4 pipeline: idempotency (HR-005, HR-006), receipts per
-- evaluation, dedupe claims (HR-007), and permits whose reservations are
-- rows of their own. Every state change is conditional (HR-004).

-- name: GetDecision :one
SELECT t.id, t.action_hash, t.decision, t.reason_code, t.state, t.evaluations,
       (SELECT r.receipt_jws FROM pc.decision_receipts r
        WHERE r.org_id = t.org_id AND r.transaction_id = t.id ORDER BY r.evaluation DESC LIMIT 1)::text AS receipt
FROM pc.transactions t
WHERE t.org_id = sqlc.arg(org_id) AND t.run_id = sqlc.arg(run_id) AND t.action_id = sqlc.arg(action_id);

-- name: InsertDecision :exec
INSERT INTO pc.transactions (org_id, id, run_id, action_id, action_hash, operation, decision, reason_code, gateway_id,
                             state, evaluations, grant_id, grant_revision, basis_digest, effective_hash, dedupe_key, mode,
                             connection_id, channel, target_type, target_id)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(run_id), sqlc.arg(action_id), sqlc.arg(action_hash), sqlc.arg(operation),
        sqlc.arg(decision), sqlc.arg(reason_code), sqlc.arg(gateway_id), sqlc.arg(state), 1, sqlc.narg(grant_id),
        sqlc.narg(grant_revision), sqlc.narg(basis_digest), sqlc.narg(effective_hash), sqlc.narg(dedupe_key), sqlc.arg(mode),
        sqlc.narg(connection_id), sqlc.narg(channel), sqlc.narg(target_type), sqlc.narg(target_id));

-- name: UpdateDecision :execresult
UPDATE pc.transactions
SET decision = sqlc.arg(decision), reason_code = sqlc.arg(reason_code), state = sqlc.arg(state),
    evaluations = sqlc.arg(evaluations), grant_id = sqlc.narg(grant_id), grant_revision = sqlc.narg(grant_revision),
    basis_digest = sqlc.narg(basis_digest), effective_hash = sqlc.narg(effective_hash), mode = sqlc.arg(mode)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'OPEN' AND evaluations = sqlc.arg(prev_evaluations);

-- name: InsertEvaluationReceipt :exec
INSERT INTO pc.decision_receipts (org_id, transaction_id, evaluation, receipt_jws, ledger_entry_id)
VALUES (sqlc.arg(org_id), sqlc.arg(transaction_id), sqlc.arg(evaluation), sqlc.arg(receipt_jws), sqlc.arg(ledger_entry_id));

-- name: InsertDedupeClaim :exec
INSERT INTO pc.dedupe_claims (org_id, dedupe_key, transaction_id, state)
VALUES (sqlc.arg(org_id), sqlc.arg(dedupe_key), sqlc.arg(transaction_id), 'HELD')
ON CONFLICT (org_id, dedupe_key) DO NOTHING;

-- name: LockDedupeClaim :one
SELECT transaction_id, state, changed_at
FROM pc.dedupe_claims
WHERE org_id = sqlc.arg(org_id) AND dedupe_key = sqlc.arg(dedupe_key)
FOR UPDATE;

-- name: GetDedupeClaim :one
SELECT transaction_id, state, changed_at
FROM pc.dedupe_claims
WHERE org_id = sqlc.arg(org_id) AND dedupe_key = sqlc.arg(dedupe_key);

-- name: TakeDedupeClaim :execresult
UPDATE pc.dedupe_claims SET transaction_id = sqlc.arg(transaction_id), state = 'HELD', changed_at = now()
WHERE org_id = sqlc.arg(org_id) AND dedupe_key = sqlc.arg(dedupe_key);

-- SettleDedupeClaim records the outcome on the claim, if the transaction
-- still holds it.
-- name: SettleDedupeClaim :exec
UPDATE pc.dedupe_claims c SET state = sqlc.arg(state), changed_at = now()
FROM pc.transactions t
WHERE c.org_id = sqlc.arg(org_id) AND t.org_id = c.org_id AND t.id = sqlc.arg(transaction_id)
  AND c.dedupe_key = t.dedupe_key AND c.transaction_id = t.id;

-- name: InsertPermitForTransaction :exec
INSERT INTO pc.permits (org_id, id, transaction_id, gateway_id, epoch, expires_at, mode, connection_id, definition_digest,
                        verify_expect)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(transaction_id), sqlc.arg(gateway_id), sqlc.arg(epoch), sqlc.arg(expires_at),
        sqlc.arg(mode), sqlc.narg(connection_id), sqlc.narg(definition_digest), sqlc.narg(verify_expect));

-- name: FinishPermitForTransaction :one
UPDATE pc.permits
SET state = sqlc.arg(to_state), finished_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND gateway_id = sqlc.arg(gateway_id) AND state = 'DISPATCHING'
  AND budget_id IS NULL
RETURNING transaction_id;

-- name: ReleaseExpiredIssued :many
UPDATE pc.permits
SET state = 'RELEASED', finished_at = now()
WHERE org_id = sqlc.arg(org_id) AND state = 'ISSUED' AND expires_at < now() AND budget_id IS NULL
RETURNING id, transaction_id;

-- name: MarkStaleDispatching :many
UPDATE pc.permits
SET state = 'UNKNOWN', finished_at = now()
WHERE org_id = sqlc.arg(org_id) AND state = 'DISPATCHING'
  AND dispatching_at < now() - make_interval(secs => sqlc.arg(stale_seconds)::float8) AND budget_id IS NULL
RETURNING id, transaction_id, gateway_id;

-- name: GetContainmentNow :one
SELECT epoch, kill_switch, now()::timestamptz AS now
FROM pc.org_containment
WHERE org_id = sqlc.arg(org_id);
