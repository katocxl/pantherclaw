-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- The containment stream and the kill switch (G0 M6, HR-002, HR-010,
-- HR-113). The stream's epoch and kill switch come from GetContainmentNow
-- (decisions.sql); engaging and clearing the kill switch are
-- EngageKillSwitch and ClearKillSwitch (authority.sql).

-- name: WatchedGateways :many
SELECT id, state, config_version FROM pc.gateways WHERE org_id = sqlc.arg(org_id);

-- WatchedConnections also says whether an active connection has a
-- verification task due, as DueVerifications would lease it (G0 M7 design
-- decision 1): one probe of verifications_due per connection.
-- name: WatchedConnections :many
SELECT c.id, c.gateway_id, c.state,
       (c.state = 'ACTIVE' AND EXISTS (
           SELECT 1 FROM pc.verifications v
           WHERE v.org_id = c.org_id AND v.connection_id = c.id AND v.state = 'PENDING' AND v.next_at <= now()
             AND v.deadline_at > now()))::boolean AS verifications_due
FROM pc.connections c
WHERE c.org_id = sqlc.arg(org_id) AND c.state <> 'RETIRED';

-- name: GetKillSwitch :one
SELECT epoch, kill_switch, engaged_by, engaged_at, engage_reason, now()::timestamptz AS now
FROM pc.org_containment WHERE org_id = sqlc.arg(org_id);

-- name: CountLiveConnections :one
SELECT count(*) FROM pc.connections WHERE org_id = sqlc.arg(org_id) AND state <> 'RETIRED';

-- name: PendingRestore :one
SELECT id, proposed_by, reason, created_at, expires_at FROM pc.kill_switch_requests
WHERE org_id = sqlc.arg(org_id) AND state = 'PENDING' AND expires_at > now();

-- ExpireRestores marks proposals past their window EXPIRED. Expiry is
-- enforced where a proposal is used; this only frees the one pending slot.
-- name: ExpireRestores :exec
UPDATE pc.kill_switch_requests SET state = 'EXPIRED', decided_at = now()
WHERE org_id = sqlc.arg(org_id) AND state = 'PENDING' AND expires_at <= now();

-- name: InsertRestore :one
INSERT INTO pc.kill_switch_requests (org_id, id, epoch, proposed_by, proposer_cred, reason, expires_at)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(epoch), sqlc.arg(proposed_by), sqlc.arg(proposer_cred), sqlc.arg(reason),
        now() + make_interval(mins => sqlc.arg(window_minutes)::integer))
RETURNING id, proposed_by, reason, created_at, expires_at;

-- name: LockRestore :one
SELECT id, epoch, proposed_by, proposer_cred, state, (expires_at > now())::boolean AS live
FROM pc.kill_switch_requests
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id)
FOR UPDATE;

-- name: ConfirmRestore :execrows
UPDATE pc.kill_switch_requests
SET state = 'CONFIRMED', decided_by = sqlc.arg(decided_by), decider_cred = sqlc.arg(decider_cred), decided_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'PENDING' AND expires_at > now();

-- name: CancelRestore :execrows
UPDATE pc.kill_switch_requests SET state = 'CANCELLED', decided_by = sqlc.arg(decided_by), decided_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'PENDING';
