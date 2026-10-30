-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Verification leases, observations and effect receipts (G0 M7 design
-- decisions 1-3, HR-190..192).

-- DueVerifications are the due tasks of the connections a gateway serves.
-- Reads stop when the kill switch is on or the connection is quarantined
-- or retired, as dispatches do (HR-190). A connection test is leased at
-- most max_test_attempts times, so a target_verifier test's tokens are
-- minted at most that often (HR-188).
-- name: DueVerifications :many
SELECT v.id, v.purpose, v.transaction_id, v.connection_id, v.operation, v.request, v.attempts, v.deadline_at
FROM pc.verifications v
JOIN pc.connections c ON c.org_id = v.org_id AND c.id = v.connection_id
JOIN pc.org_containment o ON o.org_id = v.org_id
WHERE v.org_id = sqlc.arg(org_id) AND v.state = 'PENDING' AND v.next_at <= now() AND v.deadline_at > now()
  AND c.gateway_id = sqlc.arg(gateway_id) AND c.state = 'ACTIVE' AND NOT o.kill_switch
  AND (v.purpose <> 'connection_test' OR v.attempts < sqlc.arg(max_test_attempts)::integer)
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
-- A consequence's task has no permit and carries its basis itself (G0 M8
-- W1c).
-- name: LeasedVerification :one
SELECT v.id, v.purpose, v.transaction_id, v.connection_id, v.attempts, v.deadline_at,
       p.id AS permit_id, p.dispatching_at, p.definition_digest, p.verify_expect,
       v.basis_at, v.definition_digest AS task_definition_digest,
       t.effect_state, t.effect_level_required, t.effect_level_achieved
FROM pc.verifications v
LEFT JOIN pc.permits p ON p.org_id = v.org_id AND p.transaction_id = v.transaction_id AND NOT p.replaced
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
-- or ends them when the task's deadline passed too, when it is a
-- connection test leased max_test_attempts times (HR-188), or when it is an
-- organization scan leased three times, each a whole scan's worth of the
-- installation's API quota (HR-209), or a rotation test or confirmation
-- leased three times (G0 M20 S20c).
-- name: ReleaseExpiredLeases :many
UPDATE pc.verifications
SET state = CASE WHEN deadline_at <= now() OR (purpose = 'connection_test' AND attempts >= sqlc.arg(max_test_attempts)::integer)
                      OR (purpose = 'org_scan' AND attempts >= 3)
                      OR (purpose IN ('credential_rotation_test', 'credential_rotation_confirm') AND attempts >= 3)
                 THEN 'EXPIRED' ELSE 'PENDING' END,
    finished_at = CASE WHEN deadline_at <= now() OR (purpose = 'connection_test' AND attempts >= sqlc.arg(max_test_attempts)::integer)
                            OR (purpose = 'org_scan' AND attempts >= 3)
                            OR (purpose IN ('credential_rotation_test', 'credential_rotation_confirm') AND attempts >= 3)
                       THEN now() END,
    lease_hash = NULL, leased_by = NULL, leased_at = NULL, lease_expires_at = NULL
WHERE org_id = sqlc.arg(org_id) AND state = 'LEASED' AND lease_expires_at < now()
RETURNING id, state, transaction_id;

-- name: ExpirePastDeadline :many
UPDATE pc.verifications
SET state = 'EXPIRED', finished_at = now()
WHERE org_id = sqlc.arg(org_id) AND state = 'PENDING' AND deadline_at <= now()
RETURNING id, transaction_id;

-- TransactionEffect is a transaction's effect and the definition its
-- permit fixed, or, for a consequence, its verification task (G0 M8 W1c).
-- name: TransactionEffect :one
SELECT t.effect_state, t.effect_level_required, t.effect_level_achieved,
       coalesce(p.definition_digest, (SELECT v.definition_digest FROM pc.verifications v
                                      WHERE v.org_id = t.org_id AND v.transaction_id = t.id AND v.purpose = 'consequence'
                                      ORDER BY v.created_at DESC LIMIT 1)) AS definition_digest
FROM pc.transactions t
LEFT JOIN pc.permits p ON p.org_id = t.org_id AND p.transaction_id = t.id AND NOT p.replaced
WHERE t.org_id = sqlc.arg(org_id) AND t.id = sqlc.arg(id)
FOR UPDATE OF t;

-- Consequences (G0 M8 W1c): when an action's effect is confirmed, the
-- server opens a transaction for each consequence its decision predicted,
-- never dispatched, and verifies it.

-- PredictedConsequences are what the transaction's latest evaluation
-- predicted, with the environments each deploys to.
-- name: PredictedConsequences :many
SELECT c.position, c.operation, c.target_type, c.target_id, c.environments
FROM pc.decision_consequences c
WHERE c.org_id = sqlc.arg(org_id) AND c.transaction_id = sqlc.arg(transaction_id) AND c.state = 'PREDICTED'
  AND c.evaluation = (SELECT max(d.evaluation) FROM pc.decision_consequences d
                      WHERE d.org_id = c.org_id AND d.transaction_id = c.transaction_id)
ORDER BY c.position;

-- UnknownConsequences are the consequences the transaction's latest
-- evaluation could not rule out (UNKNOWN). They name no environment, so
-- none is looked up; each is audited as not verified (G0 M8, W1c).
-- name: UnknownConsequences :many
SELECT c.position, c.operation, c.target_type, c.target_id
FROM pc.decision_consequences c
WHERE c.org_id = sqlc.arg(org_id) AND c.transaction_id = sqlc.arg(transaction_id) AND c.state = 'UNKNOWN'
  AND c.evaluation = (SELECT max(d.evaluation) FROM pc.decision_consequences d
                      WHERE d.org_id = c.org_id AND d.transaction_id = c.transaction_id)
ORDER BY c.position;

-- InsertConsequenceTransaction records a consequence of parent as its own
-- transaction: the parent's run, gateway, connection, grant and mode,
-- decided with it (ALLOW), never dispatched.
-- name: InsertConsequenceTransaction :execrows
INSERT INTO pc.transactions (org_id, id, run_id, action_id, action_hash, operation, decision, reason_code, gateway_id, state,
                             grant_id, grant_revision, connection_id, mode, target_type, target_id, effect_level_required, simulated)
SELECT t.org_id, sqlc.arg(id), t.run_id, sqlc.arg(action_id), sqlc.arg(action_hash), sqlc.arg(operation), 'ALLOW',
       'CONSEQUENCE', t.gateway_id, 'FINAL', t.grant_id, t.grant_revision, t.connection_id, t.mode, sqlc.arg(target_type),
       sqlc.arg(target_id), sqlc.arg(level_required), t.simulated
FROM pc.transactions t
WHERE t.org_id = sqlc.arg(org_id) AND t.id = sqlc.arg(parent);

-- ScheduleConsequenceVerification creates a consequence's verification
-- task, with the definition it verifies and the start of its window.
-- name: ScheduleConsequenceVerification :exec
INSERT INTO pc.verifications (org_id, id, purpose, transaction_id, connection_id, operation, request, next_at, deadline_at,
                              definition_digest, basis_at)
VALUES (sqlc.arg(org_id), sqlc.arg(id), 'consequence', sqlc.arg(transaction_id),
        (SELECT t.connection_id FROM pc.transactions t WHERE t.org_id = sqlc.arg(org_id) AND t.id = sqlc.arg(transaction_id)), sqlc.arg(operation),
        sqlc.arg(request), now() + make_interval(secs => sqlc.arg(delay_seconds)::float8),
        now() + make_interval(secs => sqlc.arg(within_seconds)::float8), sqlc.arg(definition_digest), now());

-- SiblingDefinitionWithDigest is SiblingDefinition with the sibling's
-- digest.
-- name: SiblingDefinitionWithDigest :one
SELECT s.digest, s.canonical
FROM pc.action_definitions d
JOIN pc.action_definitions s ON s.org_id = d.org_id AND s.version_id = d.version_id
WHERE d.org_id = sqlc.arg(org_id) AND d.digest = sqlc.arg(digest) AND s.operation = sqlc.arg(operation)
ORDER BY d.version_id DESC
LIMIT 1;

-- IsConsequence reports whether a transaction is a consequence the
-- server opened for another.
-- name: IsConsequence :one
SELECT EXISTS (SELECT 1 FROM pc.transaction_links
               WHERE org_id = sqlc.arg(org_id) AND to_transaction_id = sqlc.arg(id) AND kind = 'consequence');

-- name: NextEffectSeq :one
SELECT (coalesce(max(seq), 0) + 1)::integer FROM pc.effect_receipts
WHERE org_id = sqlc.arg(org_id) AND transaction_id = sqlc.arg(transaction_id);

-- TransactionChannel is the channel a transaction came through: the
-- effect receipts of a cooperative one (hook, sdk) are labeled PARTIAL
-- coverage (HR-024, HR-186, G0 M7 design decision 2).
-- name: TransactionChannel :one
SELECT channel FROM pc.transactions WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: InsertEffectReceipt :exec
INSERT INTO pc.effect_receipts (org_id, transaction_id, seq, state, level_required, level_achieved, basis, receipt_jws,
                                ledger_entry_id)
VALUES (sqlc.arg(org_id), sqlc.arg(transaction_id), sqlc.arg(seq), sqlc.arg(state), sqlc.arg(level_required),
        sqlc.narg(level_achieved), sqlc.arg(basis), sqlc.arg(receipt_jws)::text, sqlc.arg(ledger_entry_id));

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
JOIN pc.permits p ON p.org_id = t.org_id AND p.transaction_id = t.id AND NOT p.replaced
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

-- name: StartConnectionTest :exec
-- A leased connection test is RUNNING on the gateway that holds the lease.
UPDATE pc.connection_tests SET state = 'RUNNING', gateway_id = sqlc.arg(gateway_id)
WHERE org_id = sqlc.arg(org_id) AND verification_id = sqlc.arg(verification_id) AND state IN ('PENDING', 'RUNNING');

-- LeasedConnectionTest is a connection test's task under a live lease of
-- this gateway (HR-190), with its test and when the lease ends.
-- name: LeasedConnectionTest :one
SELECT v.id, v.connection_id, v.operation, v.attempts, v.lease_expires_at, t.id AS test_id, t.kind AS test_kind
FROM pc.verifications v
JOIN pc.connection_tests t ON t.org_id = v.org_id AND t.verification_id = v.id
WHERE v.org_id = sqlc.arg(org_id) AND v.id = sqlc.arg(id) AND v.purpose = 'connection_test' AND v.state = 'LEASED'
  AND v.leased_by = sqlc.arg(gateway_id) AND v.lease_hash = sqlc.arg(lease_hash) AND v.lease_expires_at >= now()
FOR UPDATE OF v, t;

-- VerifierTestBasis is what a target_verifier test's token mint checks
-- again on the server (HR-188's exception): its connection's state, access
-- mode and package, and whether the kill switch is engaged. Without the
-- org's containment row there is no row, and no mint.
-- name: VerifierTestBasis :one
SELECT c.state AS connection_state, c.access_mode, c.package, k.kill_switch
FROM pc.connection_tests t
JOIN pc.connections c ON c.org_id = t.org_id AND c.id = t.connection_id
JOIN pc.org_containment k ON k.org_id = t.org_id
WHERE t.org_id = sqlc.arg(org_id) AND t.id = sqlc.arg(id);

-- RecordTestTokenMint records a running target_verifier test's token mint
-- for its lease attempt: at most one mint per attempt (HR-188's exception).
-- name: RecordTestTokenMint :execrows
UPDATE pc.connection_tests
SET tokens_attempt = sqlc.arg(attempt)::integer
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND kind = 'target_verifier' AND state = 'RUNNING'
  AND coalesce(tokens_attempt, 0) < sqlc.arg(attempt)::integer;

-- name: FinishConnectionTest :exec
UPDATE pc.connection_tests
SET state = sqlc.arg(state), result = sqlc.narg(result), checks = sqlc.arg(checks), gateway_id = sqlc.arg(gateway_id),
    detail_sha256 = sqlc.narg(detail_sha256), finished_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state IN ('PENDING', 'RUNNING');

-- FailExpiredConnectionTests ends the tests whose task expired before a
-- gateway reported, by its deadline or after max_test_attempts leases:
-- they could not run.
-- name: FailExpiredConnectionTests :execrows
UPDATE pc.connection_tests t
SET state = 'FAILED', finished_at = now(),
    checks = jsonb_build_array(jsonb_build_object('check', 'TEST_READ', 'passed', false, 'detail',
        CASE WHEN v.attempts >= sqlc.arg(max_test_attempts)::integer
             THEN format('No gateway reported the test read in %s attempts.', v.attempts)
             ELSE 'No gateway reported the test read before its deadline.' END))
FROM pc.verifications v
WHERE t.org_id = sqlc.arg(org_id) AND v.org_id = t.org_id AND v.id = t.verification_id AND v.state = 'EXPIRED'
  AND t.state IN ('PENDING', 'RUNNING');
