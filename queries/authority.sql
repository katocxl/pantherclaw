-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Walking-skeleton authority queries (M1.5). All state transitions are
-- conditional (HR-004); security deadlines use the database clock.

-- name: DBNow :one
SELECT now()::timestamptz AS now;

-- name: ShareContainment :one
SELECT epoch, kill_switch
FROM pc.org_containment
WHERE org_id = sqlc.arg(org_id)
FOR SHARE;

-- BeginDispatch is the commit point (HR-001): ISSUED -> DISPATCHING only if
-- unexpired by the database clock and the epoch is still the org's current,
-- non-killed containment epoch.
-- name: BeginDispatch :one
UPDATE pc.permits p
SET state = 'DISPATCHING', dispatching_at = clock_timestamp()
WHERE p.org_id = sqlc.arg(org_id) AND p.id = sqlc.arg(id) AND p.gateway_id = sqlc.arg(gateway_id)
  AND p.state = 'ISSUED' AND p.epoch = sqlc.arg(epoch) AND p.expires_at > clock_timestamp()
  AND p.epoch = (SELECT c.epoch FROM pc.org_containment c WHERE c.org_id = p.org_id AND NOT c.kill_switch)
RETURNING p.transaction_id;

-- name: GetPermit :one
SELECT p.state, p.epoch, p.expires_at, p.gateway_id, p.transaction_id, (p.expires_at <= clock_timestamp())::boolean AS expired,
       c.epoch AS current_epoch, c.kill_switch
FROM pc.permits p
JOIN pc.org_containment c ON c.org_id = p.org_id
WHERE p.org_id = sqlc.arg(org_id) AND p.id = sqlc.arg(id);

-- name: InsertExecutionAttempt :exec
INSERT INTO pc.execution_attempts (org_id, id, permit_id, transaction_id, outcome, target_status, response_digest, dispatch_ms,
                                   access_mode, recorded_by, target_ref)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(permit_id), sqlc.arg(transaction_id), sqlc.arg(outcome),
        sqlc.narg(target_status), sqlc.narg(response_digest), sqlc.narg(dispatch_ms), sqlc.narg(access_mode),
        sqlc.arg(recorded_by), sqlc.narg(target_ref));

-- DispatchingPermit is what a permit bound, read at BeginDispatch for the
-- action token (G0 M6 decision 17, HR-188).
-- name: DispatchingPermit :one
SELECT t.id AS transaction_id, p.connection_id, c.access_mode, p.mode, t.operation, t.target_type, t.target_id,
       t.action_hash, t.effective_hash, clock_timestamp()::timestamptz AS now
FROM pc.permits p
JOIN pc.transactions t ON t.org_id = p.org_id AND t.id = p.transaction_id
LEFT JOIN pc.connections c ON c.org_id = p.org_id AND c.id = p.connection_id
WHERE p.org_id = sqlc.arg(org_id) AND p.id = sqlc.arg(id);

-- name: RecordOutbound :exec
UPDATE pc.permits
SET outbound_method = sqlc.narg(outbound_method), outbound_url = sqlc.narg(outbound_url),
    outbound_body_sha256 = sqlc.narg(outbound_body_sha256), action_token_jti = sqlc.narg(action_token_jti)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- ExecutionContext is what an execution receipt states about a permit:
-- its mode, connection, channel and the connection's access mode (F416).
-- name: ExecutionContext :one
SELECT p.mode, p.connection_id, t.channel, c.access_mode, t.id AS transaction_id, t.action_hash, t.effective_hash,
       p.dispatching_at, p.definition_digest, p.verify_expect, t.target_type, t.target_id
FROM pc.permits p
JOIN pc.transactions t ON t.org_id = p.org_id AND t.id = p.transaction_id
LEFT JOIN pc.connections c ON c.org_id = p.org_id AND c.id = p.connection_id
WHERE p.org_id = sqlc.arg(org_id) AND p.id = sqlc.arg(id) AND p.gateway_id = sqlc.arg(gateway_id);

-- name: InsertContainment :exec
INSERT INTO pc.org_containment (org_id) VALUES (sqlc.arg(org_id)) ON CONFLICT (org_id) DO NOTHING;

-- name: BumpEpoch :one
UPDATE pc.org_containment SET epoch = epoch + 1, updated_at = now()
WHERE org_id = sqlc.arg(org_id)
RETURNING epoch;

-- EngageKillSwitch sets the kill switch and raises the epoch in one
-- statement (HR-002, HR-113); it changes nothing while already engaged.
-- name: EngageKillSwitch :one
UPDATE pc.org_containment
SET kill_switch = true, epoch = epoch + 1, engaged_by = sqlc.arg(engaged_by)::text, engaged_at = now(),
    engage_reason = sqlc.arg(reason)::text, updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND NOT kill_switch
RETURNING epoch, engaged_at;

-- ClearKillSwitch lifts the kill switch and raises the epoch; it changes
-- nothing while not engaged.
-- name: ClearKillSwitch :one
UPDATE pc.org_containment
SET kill_switch = false, epoch = epoch + 1, engaged_by = NULL, engaged_at = NULL, engage_reason = NULL, updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND kill_switch
RETURNING epoch;
