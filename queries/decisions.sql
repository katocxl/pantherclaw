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
                             connection_id, channel, target_type, target_id, read_class, simulated)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(run_id), sqlc.arg(action_id), sqlc.arg(action_hash), sqlc.arg(operation),
        sqlc.arg(decision), sqlc.arg(reason_code), sqlc.arg(gateway_id), sqlc.arg(state), 1, sqlc.narg(grant_id),
        sqlc.narg(grant_revision), sqlc.narg(basis_digest), sqlc.narg(effective_hash), sqlc.narg(dedupe_key), sqlc.arg(mode),
        sqlc.narg(connection_id), sqlc.narg(channel), sqlc.narg(target_type), sqlc.narg(target_id),
        sqlc.narg(read_class),
        -- HR-220: a transaction is simulated exactly when its run is.
        coalesce((SELECT r.simulated FROM pc.runs r WHERE r.org_id = sqlc.arg(org_id) AND r.id = sqlc.arg(run_id)), false));

-- name: UpdateDecision :execresult
UPDATE pc.transactions
SET decision = sqlc.arg(decision), reason_code = sqlc.arg(reason_code), state = sqlc.arg(state),
    evaluations = sqlc.arg(evaluations), grant_id = sqlc.narg(grant_id), grant_revision = sqlc.narg(grant_revision),
    basis_digest = sqlc.narg(basis_digest), effective_hash = sqlc.narg(effective_hash), mode = sqlc.arg(mode),
    read_class = sqlc.narg(read_class)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'OPEN' AND evaluations = sqlc.arg(prev_evaluations);

-- The sensitive reads of a run tree (G0 M16 D73, D97, HR-431): the pii and
-- secret reads of every run sharing the run's root (runs nest at most 8
-- deep), the 20 most recent plus the most recent of each class, so every
-- class read is there. Classes and ids only, never content (HR-434).
-- name: SensitiveReads :many
WITH RECURSIVE up (id, parent_run_id, hop) AS (
    SELECT r.id, r.parent_run_id, 0 FROM pc.runs r WHERE r.org_id = sqlc.arg(org_id) AND r.id = sqlc.arg(run_id)
    UNION ALL
    SELECT p.id, p.parent_run_id, up.hop + 1 FROM up JOIN pc.runs p ON p.org_id = sqlc.arg(org_id) AND p.id = up.parent_run_id
    WHERE up.hop < 8
), root AS (
    SELECT up.id FROM up ORDER BY up.hop DESC LIMIT 1
), tree (id, hop) AS (
    SELECT root.id, 0 FROM root
    UNION ALL
    SELECT c.id, tree.hop + 1 FROM tree JOIN pc.runs c ON c.org_id = sqlc.arg(org_id) AND c.parent_run_id = tree.id
    WHERE tree.hop < 8
), reads AS (
    SELECT t.id, t.run_id, t.operation, coalesce(t.read_class, '')::text AS read_class, t.created_at
    FROM pc.transactions t
    WHERE t.org_id = sqlc.arg(org_id) AND t.run_id IN (SELECT tree.id FROM tree) AND t.read_class IN ('pii', 'secret')
)
SELECT n.id, n.run_id, n.operation, n.read_class, n.created_at FROM (
    (SELECT * FROM reads ORDER BY reads.created_at DESC, reads.id DESC LIMIT 20)
    UNION
    (SELECT DISTINCT ON (reads.read_class) * FROM reads ORDER BY reads.read_class, reads.created_at DESC, reads.id DESC)
) n
ORDER BY n.created_at DESC, n.id DESC;

-- name: InsertEvaluationReceipt :exec
INSERT INTO pc.decision_receipts (org_id, transaction_id, evaluation, receipt_jws, ledger_entry_id, coverage_snapshot_id)
VALUES (sqlc.arg(org_id), sqlc.arg(transaction_id), sqlc.arg(evaluation), sqlc.arg(receipt_jws)::text, sqlc.arg(ledger_entry_id),
    sqlc.narg(coverage_snapshot_id));

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

-- name: InsertDecisionConsequence :exec
-- What one consequence rule said in an evaluation (G0 M8, HR-206), and
-- where it sits in a chain (G0 M17 D109).
INSERT INTO pc.decision_consequences (org_id, transaction_id, evaluation, position, rule_id, operation, target_type, target_id,
    environments, state, unknown, facts_digest, depth, parent_position, source)
VALUES (sqlc.arg(org_id), sqlc.arg(transaction_id), sqlc.arg(evaluation), sqlc.arg(position), sqlc.arg(rule_id), sqlc.arg(operation),
    sqlc.arg(target_type), sqlc.arg(target_id), sqlc.arg(environments)::text[], sqlc.arg(state), sqlc.arg(unknown), sqlc.arg(facts_digest),
    sqlc.arg(depth), sqlc.narg(parent_position), sqlc.arg(source));

-- name: ListDecisionConsequences :many
-- The consequences of an evaluation, in rule order: a consequence of a
-- consequence comes after the one it follows from (parent_position).
SELECT position, rule_id, operation, target_type, target_id, environments, state, unknown, facts_digest, depth, parent_position,
    source
FROM pc.decision_consequences
WHERE org_id = sqlc.arg(org_id) AND transaction_id = sqlc.arg(transaction_id) AND evaluation = sqlc.arg(evaluation)
ORDER BY position;
