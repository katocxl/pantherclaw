-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Effects and reconciliation (G0 M7 track A, HR-190..193).

-- name: InsertExecutionReceipt :exec
INSERT INTO pc.execution_receipts (org_id, attempt_id, transaction_id, permit_id, receipt_jws, ledger_entry_id)
VALUES (sqlc.arg(org_id), sqlc.arg(attempt_id), sqlc.arg(transaction_id), sqlc.arg(permit_id), sqlc.arg(receipt_jws),
        sqlc.arg(ledger_entry_id));

-- RecordedExecution is the attempt a permit already has, for a gateway
-- that reports after the sweeper did (PAP-1 §7.4).
-- name: RecordedExecution :one
SELECT p.state, p.transaction_id, a.recorded_by, a.outcome, r.receipt_jws
FROM pc.permits p
JOIN pc.execution_attempts a ON a.org_id = p.org_id AND a.permit_id = p.id
JOIN pc.execution_receipts r ON r.org_id = a.org_id AND r.attempt_id = a.id
WHERE p.org_id = sqlc.arg(org_id) AND p.id = sqlc.arg(id) AND p.gateway_id = sqlc.arg(gateway_id);

-- OpenReconciliation opens the transaction's task of a kind, unless one is
-- open (HR-192).
-- name: OpenReconciliation :exec
INSERT INTO pc.reconciliation_tasks (org_id, id, transaction_id, kind)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(transaction_id), sqlc.arg(kind))
ON CONFLICT (org_id, transaction_id, kind) WHERE state = 'OPEN' DO NOTHING;

-- ResolveReconciliationOccurred resolves the transaction's open
-- unknown-outcome task from evidence: only ever towards OCCURRED (HR-192).
-- name: ResolveReconciliationOccurred :execrows
UPDATE pc.reconciliation_tasks
SET state = 'OCCURRED', resolved_via = sqlc.arg(via), observation_id = sqlc.arg(observation_id), resolved_at = now()
WHERE org_id = sqlc.arg(org_id) AND transaction_id = sqlc.arg(transaction_id) AND kind = 'unknown_outcome'
  AND state = 'OPEN';

-- ScheduleVerification creates a verification task unless one of the same
-- purpose is open for the transaction. The deadline is the verifier's
-- window from dispatch, and at least a minute away.
-- name: ScheduleVerification :exec
INSERT INTO pc.verifications (org_id, id, purpose, transaction_id, connection_id, operation, request, next_at, deadline_at)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(purpose), sqlc.arg(transaction_id), sqlc.arg(connection_id),
        sqlc.arg(operation), sqlc.arg(request), now() + make_interval(secs => sqlc.arg(delay_seconds)::float8),
        greatest(sqlc.arg(deadline_at)::timestamptz, now() + interval '1 minute'))
ON CONFLICT (org_id, transaction_id, purpose) WHERE state IN ('PENDING', 'LEASED') AND transaction_id IS NOT NULL
DO NOTHING;

-- name: InsertObservation :exec
INSERT INTO pc.observations (org_id, id, source, transaction_id, verification_id, gateway_id, attempt, http_status, outcome,
                             found, complete, fields, response_digest)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(source), sqlc.narg(transaction_id), sqlc.narg(verification_id),
        sqlc.arg(gateway_id), sqlc.narg(attempt), sqlc.narg(http_status), sqlc.narg(outcome), sqlc.narg(found),
        sqlc.narg(complete), sqlc.narg(fields), sqlc.narg(response_digest));

-- SiblingDefinition returns operation's definition from the newest
-- imported version that holds the definition with digest: the verifier's
-- reads of a write, reviewed in the same package version.
-- name: SiblingDefinition :one
SELECT s.canonical
FROM pc.action_definitions d
JOIN pc.action_definitions s ON s.org_id = d.org_id AND s.version_id = d.version_id
WHERE d.org_id = sqlc.arg(org_id) AND d.digest = sqlc.arg(digest) AND s.operation = sqlc.arg(operation)
ORDER BY d.version_id DESC
LIMIT 1;

-- name: DefinitionCanonical :one
SELECT canonical FROM pc.action_definitions
WHERE org_id = sqlc.arg(org_id) AND digest = sqlc.arg(digest)
ORDER BY version_id DESC
LIMIT 1;

-- name: SetEffectRequired :exec
UPDATE pc.transactions SET effect_level_required = sqlc.arg(level)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);
