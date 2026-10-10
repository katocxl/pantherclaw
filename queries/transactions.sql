-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- The evidence explorer (G0 M7 track A, F466–F479). Every read runs in the
-- org's tenant transaction; the caller's scope is checked per agent.

-- ListTransactions lists transactions newest first. execution_state
-- mirrors transactions/domain.Execution (a test keeps them equal) so the
-- filter applies before the page is cut.
-- name: ListTransactions :many
WITH x AS (
    SELECT t.id, t.run_id, r.agent_id, t.operation, t.connection_id, t.decision, t.reason_code, t.effect_state,
           t.effect_level_required, t.effect_level_achieved, t.mode, t.evaluations, t.created_at,
           p.state AS permit_state, a.outcome,
           CASE
               WHEN t.decision IN ('REQUIRE_APPROVAL', 'REQUIRE_STEP_UP') THEN 'WAITING'
               WHEN t.decision = 'DENY' AND t.reason_code IN ('APPROVAL_DECLINED', 'APPROVAL_EXPIRED', 'NARROWER_PROPOSED')
                   THEN 'CANCELLED'
               WHEN t.decision IN ('DENY', 'CANNOT_AUTHORIZE') THEN 'BLOCKED'
               WHEN p.state IS NULL OR p.state = 'ISSUED' THEN 'AUTHORIZED'
               WHEN p.state = 'RELEASED' THEN 'CANCELLED'
               WHEN p.state IN ('DISPATCHING', 'UNKNOWN') THEN 'DISPATCHED'
               WHEN a.outcome = 'accepted' THEN 'ACCEPTED'
               WHEN a.outcome = 'failed' THEN 'FAILED'
               ELSE 'DISPATCHED'
           END::text AS execution_state
    FROM pc.transactions t
    JOIN pc.runs r ON r.org_id = t.org_id AND r.id = t.run_id
    LEFT JOIN pc.permits p ON p.org_id = t.org_id AND p.transaction_id = t.id
    LEFT JOIN pc.execution_attempts a ON a.org_id = p.org_id AND a.permit_id = p.id
    WHERE t.org_id = sqlc.arg(org_id)
      AND (coalesce(sqlc.arg(before)::uuid, '00000000-0000-0000-0000-000000000000') = '00000000-0000-0000-0000-000000000000'
           OR t.id < sqlc.arg(before)::uuid)
      AND (sqlc.narg(run_id)::uuid IS NULL OR t.run_id = sqlc.narg(run_id)::uuid)
      AND (sqlc.narg(agent_id)::uuid IS NULL OR r.agent_id = sqlc.narg(agent_id)::uuid)
      AND (sqlc.narg(connection_id)::uuid IS NULL OR t.connection_id = sqlc.narg(connection_id)::uuid)
      AND (cardinality(sqlc.arg(decisions)::text[]) = 0 OR t.decision = ANY (sqlc.arg(decisions)::text[]))
      AND (cardinality(sqlc.arg(effect_states)::text[]) = 0 OR t.effect_state = ANY (sqlc.arg(effect_states)::text[]))
      AND (sqlc.narg(start_time)::timestamptz IS NULL OR t.created_at >= sqlc.narg(start_time)::timestamptz)
      AND (sqlc.narg(end_time)::timestamptz IS NULL OR t.created_at < sqlc.narg(end_time)::timestamptz)
)
SELECT * FROM x
WHERE cardinality(sqlc.arg(execution_states)::text[]) = 0 OR x.execution_state = ANY (sqlc.arg(execution_states)::text[])
ORDER BY x.id DESC
LIMIT sqlc.arg(page_limit);

-- name: TransactionSummary :one
SELECT t.id, t.run_id, r.agent_id, t.operation, t.connection_id, t.decision, t.reason_code, t.effect_state,
       t.effect_level_required, t.effect_level_achieved, t.mode, t.evaluations, t.created_at,
       p.state AS permit_state, a.outcome
FROM pc.transactions t
JOIN pc.runs r ON r.org_id = t.org_id AND r.id = t.run_id
LEFT JOIN pc.permits p ON p.org_id = t.org_id AND p.transaction_id = t.id
LEFT JOIN pc.execution_attempts a ON a.org_id = p.org_id AND a.permit_id = p.id
WHERE t.org_id = sqlc.arg(org_id) AND t.id = sqlc.arg(id);

-- name: DecisionReceiptsOf :many
SELECT d.evaluation, d.receipt_jws, d.ledger_entry_id, d.created_at, c.seq AS chain_seq
FROM pc.decision_receipts d
LEFT JOIN pc.ledger_chain c ON c.org_id = d.org_id AND c.entry_id = d.ledger_entry_id
WHERE d.org_id = sqlc.arg(org_id) AND d.transaction_id = sqlc.arg(transaction_id)
ORDER BY d.evaluation;

-- name: ExecutionOf :one
SELECT a.id AS attempt_id, a.permit_id, a.outcome, a.target_status, a.recorded_by, a.target_ref, a.dispatch_ms,
       a.recorded_at, p.dispatching_at, e.receipt_jws, e.ledger_entry_id, c.seq AS chain_seq
FROM pc.execution_attempts a
JOIN pc.permits p ON p.org_id = a.org_id AND p.id = a.permit_id
JOIN pc.execution_receipts e ON e.org_id = a.org_id AND e.attempt_id = a.id
LEFT JOIN pc.ledger_chain c ON c.org_id = e.org_id AND c.entry_id = e.ledger_entry_id
WHERE a.org_id = sqlc.arg(org_id) AND a.transaction_id = sqlc.arg(transaction_id);

-- ObservationsOf returns the transaction's observations and the ones its
-- effect receipts and reconciliations name (a target-log listing covers
-- many transactions).
-- name: ObservationsOf :many
SELECT o.id, o.source, o.verification_id, o.gateway_id, o.http_status, o.outcome, o.found, o.complete, o.fields,
       o.response_digest, o.observed_at
FROM pc.observations o
WHERE o.org_id = sqlc.arg(org_id)
  AND (o.transaction_id = sqlc.arg(transaction_id) OR o.id = ANY (sqlc.arg(named)::uuid[])
       OR o.id IN (SELECT k.observation_id FROM pc.reconciliation_tasks k
                   WHERE k.org_id = sqlc.arg(org_id) AND k.transaction_id = sqlc.arg(transaction_id)))
ORDER BY o.observed_at, o.id
LIMIT 1000;

-- name: EffectReceiptsOf :many
SELECT f.seq, f.state, f.level_required, f.level_achieved, f.basis, f.receipt_jws, f.ledger_entry_id, f.created_at,
       c.seq AS chain_seq
FROM pc.effect_receipts f
LEFT JOIN pc.ledger_chain c ON c.org_id = f.org_id AND c.entry_id = f.ledger_entry_id
WHERE f.org_id = sqlc.arg(org_id) AND f.transaction_id = sqlc.arg(transaction_id)
ORDER BY f.seq;

-- name: ReconciliationsOf :many
SELECT id, transaction_id, kind, state, resolved_via, observation_id, user_id, basis, evidence, waitlist_entry_id,
       opened_at, resolved_at
FROM pc.reconciliation_tasks
WHERE org_id = sqlc.arg(org_id) AND transaction_id = sqlc.arg(transaction_id)
ORDER BY opened_at, id;

-- name: LinksOf :many
SELECT from_transaction_id, to_transaction_id, kind, created_by, created_at
FROM pc.transaction_links
WHERE org_id = sqlc.arg(org_id)
  AND (from_transaction_id = sqlc.arg(transaction_id) OR to_transaction_id = sqlc.arg(transaction_id))
ORDER BY created_at;

-- Reconciliation (G0 M7 design decisions 3 and 4, HR-192, HR-193).

-- name: ListReconciliations :many
SELECT k.id, k.transaction_id, k.kind, k.state, k.resolved_via, k.observation_id, k.user_id, k.basis, k.evidence,
       k.waitlist_entry_id, k.opened_at, k.resolved_at, r.agent_id
FROM pc.reconciliation_tasks k
JOIN pc.transactions t ON t.org_id = k.org_id AND t.id = k.transaction_id
JOIN pc.runs r ON r.org_id = t.org_id AND r.id = t.run_id
WHERE k.org_id = sqlc.arg(org_id)
  AND (coalesce(sqlc.arg(before)::uuid, '00000000-0000-0000-0000-000000000000') = '00000000-0000-0000-0000-000000000000'
       OR k.id < sqlc.arg(before)::uuid)
  AND (cardinality(sqlc.arg(states)::text[]) = 0 OR k.state = ANY (sqlc.arg(states)::text[]))
  AND (cardinality(sqlc.arg(kinds)::text[]) = 0 OR k.kind = ANY (sqlc.arg(kinds)::text[]))
  AND (sqlc.narg(transaction_id)::uuid IS NULL OR k.transaction_id = sqlc.narg(transaction_id)::uuid)
ORDER BY k.id DESC
LIMIT sqlc.arg(page_limit);

-- name: ReconciliationByID :one
SELECT k.id, k.transaction_id, k.kind, k.state, k.resolved_via, k.observation_id, k.user_id, k.basis, k.evidence,
       k.waitlist_entry_id, k.opened_at, k.resolved_at, r.agent_id, p.id AS permit_id
FROM pc.reconciliation_tasks k
JOIN pc.transactions t ON t.org_id = k.org_id AND t.id = k.transaction_id
JOIN pc.runs r ON r.org_id = t.org_id AND r.id = t.run_id
LEFT JOIN pc.permits p ON p.org_id = t.org_id AND p.transaction_id = t.id
WHERE k.org_id = sqlc.arg(org_id) AND k.id = sqlc.arg(id)
FOR UPDATE OF k;

-- ResolveReconciliationByPerson records a person's "occurred" with their
-- basis; only an open task changes.
-- name: ResolveReconciliationByPerson :execrows
UPDATE pc.reconciliation_tasks
SET state = 'OCCURRED', resolved_via = 'person', user_id = sqlc.arg(user_id), basis = sqlc.arg(basis),
    evidence = sqlc.arg(evidence)::uuid[], observation_id = sqlc.narg(observation_id), resolved_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'OPEN';

-- LatestVerification is the transaction's newest verification task: what
-- a requested verification reads again.
-- name: LatestVerification :one
SELECT id, purpose, state, connection_id, operation, request,
       extract(epoch FROM deadline_at - created_at)::float8 AS window_seconds
FROM pc.verifications
WHERE org_id = sqlc.arg(org_id) AND transaction_id = sqlc.arg(transaction_id)
ORDER BY created_at DESC, id DESC
LIMIT 1;

-- name: VerifyNow :many
UPDATE pc.verifications SET next_at = now()
WHERE org_id = sqlc.arg(org_id) AND transaction_id = sqlc.arg(transaction_id) AND state = 'PENDING'
RETURNING id;

-- name: OpenVerifications :many
SELECT id FROM pc.verifications
WHERE org_id = sqlc.arg(org_id) AND transaction_id = sqlc.arg(transaction_id) AND state IN ('PENDING', 'LEASED');

-- LinkEnd is one end of a link, locked.
-- name: LinkEnd :one
SELECT t.created_at, t.effect_state, t.effect_level_required, t.effect_level_achieved, r.agent_id, p.dispatching_at,
       p.definition_digest
FROM pc.transactions t
JOIN pc.runs r ON r.org_id = t.org_id AND r.id = t.run_id
LEFT JOIN pc.permits p ON p.org_id = t.org_id AND p.transaction_id = t.id
WHERE t.org_id = sqlc.arg(org_id) AND t.id = sqlc.arg(id)
FOR UPDATE OF t;

-- name: InsertTransactionLink :execrows
INSERT INTO pc.transaction_links (org_id, from_transaction_id, to_transaction_id, kind, created_by)
VALUES (sqlc.arg(org_id), sqlc.arg(from_transaction_id), sqlc.arg(to_transaction_id), sqlc.arg(kind), sqlc.arg(created_by))
ON CONFLICT DO NOTHING;

-- Compensated are the earlier transactions a transaction compensates.
-- name: Compensated :many
SELECT to_transaction_id FROM pc.transaction_links
WHERE org_id = sqlc.arg(org_id) AND from_transaction_id = sqlc.arg(from_transaction_id) AND kind = 'compensates';

-- CompensatedBy are the confirmed transactions that compensate a
-- transaction: an original confirmed after its compensation.
-- name: CompensatedBy :many
SELECT l.from_transaction_id FROM pc.transaction_links l
JOIN pc.transactions f ON f.org_id = l.org_id AND f.id = l.from_transaction_id
WHERE l.org_id = sqlc.arg(org_id) AND l.to_transaction_id = sqlc.arg(to_transaction_id) AND l.kind = 'compensates'
  AND f.effect_state = 'CONFIRMED';

-- name: ReconciliationOf :one
SELECT id, transaction_id, kind, state, resolved_via, observation_id, user_id, basis, evidence, waitlist_entry_id,
       opened_at, resolved_at
FROM pc.reconciliation_tasks
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);
