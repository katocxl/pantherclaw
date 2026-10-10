-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Verification leases, observations and effect receipts (G0 M7 design
-- decisions 1-3, HR-190..192).

-- DueVerifications are the due tasks of the connections a gateway serves.
-- Reads stop when the kill switch is on or the connection is quarantined
-- or retired, as dispatches do (HR-190).
-- name: DueVerifications :many
SELECT v.id, v.purpose, v.transaction_id, v.connection_id, v.operation, v.request, v.attempts, v.deadline_at
FROM pc.verifications v
JOIN pc.connections c ON c.org_id = v.org_id AND c.id = v.connection_id
JOIN pc.org_containment o ON o.org_id = v.org_id
WHERE v.org_id = sqlc.arg(org_id) AND v.state = 'PENDING' AND v.next_at <= now() AND v.deadline_at > now()
  AND c.gateway_id = sqlc.arg(gateway_id) AND c.state = 'ACTIVE' AND NOT o.kill_switch
ORDER BY v.next_at
LIMIT sqlc.arg(max_tasks)
FOR UPDATE OF v SKIP LOCKED;

-- name: LeaseVerification :execrows
UPDATE pc.verifications
SET state = 'LEASED', lease_hash = sqlc.arg(lease_hash), leased_by = sqlc.arg(gateway_id), leased_at = now(),
    lease_expires_at = now() + make_interval(secs => sqlc.arg(lease_seconds)::float8), attempts = attempts + 1
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'PENDING';

-- LeasedVerification is a task under a live lease of this gateway, with
-- what its permit fixed (HR-190, HR-191): nothing else accepts a report.
-- name: LeasedVerification :one
SELECT v.id, v.purpose, v.transaction_id, v.connection_id, v.attempts, v.deadline_at,
       p.id AS permit_id, p.dispatching_at, p.definition_digest, p.verify_expect,
       t.effect_state, t.effect_level_required, t.effect_level_achieved
FROM pc.verifications v
JOIN pc.permits p ON p.org_id = v.org_id AND p.transaction_id = v.transaction_id
JOIN pc.transactions t ON t.org_id = v.org_id AND t.id = v.transaction_id
WHERE v.org_id = sqlc.arg(org_id) AND v.id = sqlc.arg(id) AND v.state = 'LEASED' AND v.leased_by = sqlc.arg(gateway_id)
  AND v.lease_hash = sqlc.arg(lease_hash) AND v.lease_expires_at >= now()
FOR UPDATE OF v;

-- name: FinishVerification :exec
UPDATE pc.verifications
SET state = sqlc.arg(state), finished_at = now(), lease_hash = NULL, leased_by = NULL, leased_at = NULL, lease_expires_at = NULL
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state IN ('PENDING', 'LEASED');

-- name: RetryVerification :exec
UPDATE pc.verifications
SET state = 'PENDING', next_at = now() + make_interval(secs => sqlc.arg(delay_seconds)::float8), lease_hash = NULL,
    leased_by = NULL, leased_at = NULL, lease_expires_at = NULL
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'LEASED';

-- ReleaseExpiredLeases returns leases nobody reported in time to PENDING,
-- or ends them when the task's deadline passed too.
-- name: ReleaseExpiredLeases :many
UPDATE pc.verifications
SET state = CASE WHEN deadline_at <= now() THEN 'EXPIRED' ELSE 'PENDING' END,
    finished_at = CASE WHEN deadline_at <= now() THEN now() END,
    lease_hash = NULL, leased_by = NULL, leased_at = NULL, lease_expires_at = NULL
WHERE org_id = sqlc.arg(org_id) AND state = 'LEASED' AND lease_expires_at < now()
RETURNING id, state, transaction_id;

-- name: ExpirePastDeadline :many
UPDATE pc.verifications
SET state = 'EXPIRED', finished_at = now()
WHERE org_id = sqlc.arg(org_id) AND state = 'PENDING' AND deadline_at <= now()
RETURNING id, transaction_id;

-- name: TransactionEffect :one
SELECT t.effect_state, t.effect_level_required, t.effect_level_achieved, p.definition_digest
FROM pc.transactions t
JOIN pc.permits p ON p.org_id = t.org_id AND p.transaction_id = t.id
WHERE t.org_id = sqlc.arg(org_id) AND t.id = sqlc.arg(id)
FOR UPDATE OF t;

-- name: NextEffectSeq :one
SELECT (coalesce(max(seq), 0) + 1)::integer FROM pc.effect_receipts
WHERE org_id = sqlc.arg(org_id) AND transaction_id = sqlc.arg(transaction_id);

-- name: InsertEffectReceipt :exec
INSERT INTO pc.effect_receipts (org_id, transaction_id, seq, state, level_required, level_achieved, basis, receipt_jws,
                                ledger_entry_id)
VALUES (sqlc.arg(org_id), sqlc.arg(transaction_id), sqlc.arg(seq), sqlc.arg(state), sqlc.arg(level_required),
        sqlc.narg(level_achieved), sqlc.arg(basis), sqlc.arg(receipt_jws), sqlc.arg(ledger_entry_id));

-- name: SetEffectState :exec
UPDATE pc.transactions SET effect_state = sqlc.arg(state), effect_level_achieved = sqlc.narg(achieved)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- Target logs (HR-112, G0 M7 design decision 6).

-- TargetLogConnections are the org's active HTTP connections with the raw
-- file of their pinned package version, the end of their last complete
-- target-log window, and whether a target-log task is open.
-- name: TargetLogConnections :many
SELECT c.id, v.raw,
       coalesce((SELECT max(r.window_end) FROM pc.target_log_runs r
        WHERE r.org_id = c.org_id AND r.connection_id = c.id AND r.complete), 'epoch'::timestamptz)::timestamptz AS last_end,
       EXISTS (SELECT 1 FROM pc.verifications o
               WHERE o.org_id = c.org_id AND o.connection_id = c.id AND o.purpose = 'target_log'
                 AND o.state IN ('PENDING', 'LEASED')) AS open,
       now()::timestamptz AS now
FROM pc.connections c
JOIN pc.tool_packages t ON t.org_id = c.org_id AND t.name = c.package
JOIN pc.package_pins p ON p.org_id = t.org_id AND p.package_id = t.id
JOIN pc.package_versions v ON v.org_id = p.org_id AND v.id = p.version_id
WHERE c.org_id = sqlc.arg(org_id) AND c.state = 'ACTIVE' AND c.kind = 'http';

-- name: ScheduleTargetLog :exec
INSERT INTO pc.verifications (org_id, id, purpose, connection_id, operation, request, next_at, deadline_at, window_start,
                              window_end)
VALUES (sqlc.arg(org_id), sqlc.arg(id), 'target_log', sqlc.arg(connection_id), sqlc.arg(operation), sqlc.arg(request), now(),
        now() + interval '15 minutes', sqlc.arg(window_start), sqlc.arg(window_end));

-- LeasedTargetLog is a target-log task under a live lease of this gateway.
-- name: LeasedTargetLog :one
SELECT v.id, v.connection_id, v.operation, v.request, v.window_start, v.window_end
FROM pc.verifications v
WHERE v.org_id = sqlc.arg(org_id) AND v.id = sqlc.arg(id) AND v.purpose = 'target_log' AND v.state = 'LEASED'
  AND v.leased_by = sqlc.arg(gateway_id) AND v.lease_hash = sqlc.arg(lease_hash) AND v.lease_expires_at >= now()
FOR UPDATE OF v;

-- ReceiptOfCorrelation is the transaction a listed object names by its
-- idempotency key, when that transaction was dispatched through the
-- connection: its permit, the recorded outcome and its effect.
-- name: ReceiptOfCorrelation :one
SELECT p.id AS permit_id, p.state AS permit_state, a.outcome, t.effect_state, t.effect_level_required,
       t.effect_level_achieved, p.definition_digest
FROM pc.transactions t
JOIN pc.permits p ON p.org_id = t.org_id AND p.transaction_id = t.id
LEFT JOIN pc.execution_attempts a ON a.org_id = p.org_id AND a.permit_id = p.id
WHERE t.org_id = sqlc.arg(org_id) AND t.id = sqlc.arg(transaction_id) AND p.connection_id = sqlc.arg(connection_id)
  AND p.state IN ('DISPATCHING', 'DISPATCHED', 'UNKNOWN')
FOR UPDATE OF t;

-- name: InsertTargetLogRun :exec
INSERT INTO pc.target_log_runs (org_id, verification_id, connection_id, window_start, window_end, items_seen, matched, unmatched,
                                complete)
VALUES (sqlc.arg(org_id), sqlc.arg(verification_id), sqlc.arg(connection_id), sqlc.arg(window_start), sqlc.arg(window_end),
        sqlc.arg(items_seen), sqlc.arg(matched), sqlc.arg(unmatched), sqlc.arg(complete));

-- InsertUnreceiptedEffect records an object no receipt accounts for, once.
-- name: InsertUnreceiptedEffect :execrows
INSERT INTO pc.unreceipted_effects (org_id, id, connection_id, operation, object_ref, correlation, target_created_at,
                                    verification_id)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(connection_id), sqlc.arg(operation), sqlc.arg(object_ref),
        sqlc.narg(correlation), sqlc.narg(target_created_at), sqlc.arg(verification_id))
ON CONFLICT (org_id, connection_id, object_ref) DO NOTHING;
