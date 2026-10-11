-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Restricted payload capture (G0 M7 design decision 10, HR-199). Profiles
-- and the audited read run as pc_app; DeletePayloadCaptures runs only as
-- pc_retention, in the retention job.

-- name: InsertCaptureProfile :one
INSERT INTO pc.capture_profiles (org_id, id, purpose, connections, operations, capture_request, capture_response,
    byte_cap, retention_days, expires_at, created_by)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(purpose), sqlc.arg(connections)::uuid[], sqlc.arg(operations)::text[],
    sqlc.arg(capture_request), sqlc.arg(capture_response), sqlc.arg(byte_cap), sqlc.arg(retention_days),
    now() + make_interval(days => sqlc.arg(expires_in_days)::int), sqlc.arg(created_by))
RETURNING *;

-- name: GetCaptureProfile :one
SELECT * FROM pc.capture_profiles WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: DisableCaptureProfile :one
UPDATE pc.capture_profiles SET state = 'DISABLED', disabled_by = sqlc.arg(disabled_by), disabled_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'ACTIVE'
RETURNING *;

-- Newest first; an ACTIVE profile past its expiry reads as EXPIRED.
-- name: ListCaptureProfilesPage :many
SELECT p.*, (CASE WHEN p.state = 'ACTIVE' AND p.expires_at <= now() THEN 'EXPIRED' ELSE p.state END)::text AS effective_state
FROM pc.capture_profiles p
WHERE p.org_id = sqlc.arg(org_id)
  AND (sqlc.narg(state)::text IS NULL OR (CASE WHEN p.state = 'ACTIVE' AND p.expires_at <= now() THEN 'EXPIRED' ELSE p.state END) = sqlc.narg(state)::text)
  AND (sqlc.narg(before)::uuid IS NULL OR p.id < sqlc.narg(before)::uuid)
ORDER BY p.id DESC
LIMIT sqlc.arg(max_rows);

-- name: ExpireCaptureProfiles :execrows
UPDATE pc.capture_profiles SET state = 'EXPIRED'
WHERE org_id = sqlc.arg(org_id) AND state = 'ACTIVE' AND expires_at <= now();

-- How many of ids are connections of the org that are not retired.
-- name: CountCaptureConnections :one
SELECT count(*)::integer FROM pc.connections
WHERE org_id = sqlc.arg(org_id) AND id = ANY (sqlc.arg(connection_ids)::uuid[]) AND state <> 'RETIRED';

-- The gateways serving these connections get a new configuration.
-- name: BumpGatewaysOfConnections :exec
UPDATE pc.gateways g SET config_version = g.config_version + 1
WHERE g.org_id = sqlc.arg(org_id)
  AND g.id IN (SELECT c.gateway_id FROM pc.connections c WHERE c.org_id = sqlc.arg(org_id) AND c.id = ANY (sqlc.arg(connections)::uuid[]));

-- The active, unexpired profiles covering a connection the gateway serves.
-- name: GatewayCaptureProfiles :many
SELECT p.id, p.connections, p.operations, p.capture_request, p.capture_response, p.byte_cap, p.expires_at
FROM pc.capture_profiles p
WHERE p.org_id = sqlc.arg(org_id) AND p.state = 'ACTIVE' AND p.expires_at > now()
  AND p.connections && ARRAY(SELECT c.id FROM pc.connections c
                             WHERE c.org_id = sqlc.arg(org_id) AND c.gateway_id = sqlc.arg(gateway_id) AND c.state <> 'RETIRED')
ORDER BY p.id;

-- What a recorded execution captured into: its attempt, transaction,
-- connection, operation and mode, and the gateway its permit names.
-- name: CaptureTarget :one
SELECT a.id AS attempt_id, a.transaction_id, a.outcome, a.recorded_by, t.connection_id, t.operation, t.mode, p.gateway_id
FROM pc.execution_attempts a
JOIN pc.permits p ON p.org_id = a.org_id AND p.id = a.permit_id
JOIN pc.transactions t ON t.org_id = a.org_id AND t.id = a.transaction_id
WHERE a.org_id = sqlc.arg(org_id) AND a.permit_id = sqlc.arg(permit_id);

-- name: ActiveCaptureProfile :one
SELECT id, connections, operations, capture_request, capture_response, byte_cap, retention_days
FROM pc.capture_profiles
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'ACTIVE' AND expires_at > now();

-- A repeated report of one attempt keeps the first capture.
-- name: InsertPayloadCapture :execrows
INSERT INTO pc.payload_captures (org_id, id, attempt_id, transaction_id, profile_id, direction, content, size, truncated,
    remove_at)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(attempt_id), sqlc.arg(transaction_id), sqlc.arg(profile_id),
    sqlc.arg(direction), sqlc.arg(content), sqlc.arg(size), sqlc.arg(truncated),
    now() + make_interval(days => sqlc.arg(retention_days)::int))
ON CONFLICT (org_id, attempt_id, direction) DO NOTHING;

-- name: GetPayloadCapture :one
SELECT c.id, c.attempt_id, c.transaction_id, c.profile_id, c.direction, c.content, c.size, c.truncated, c.created_at,
       c.remove_at, r.agent_id
FROM pc.payload_captures c
JOIN pc.transactions t ON t.org_id = c.org_id AND t.id = c.transaction_id
JOIN pc.runs r ON r.org_id = t.org_id AND r.id = t.run_id
WHERE c.org_id = sqlc.arg(org_id) AND c.transaction_id = sqlc.arg(transaction_id) AND c.direction = sqlc.arg(direction);

-- The retention job, as pc_retention: captures past their profile's
-- retention or the payloads period, outside legal holds.
-- name: DeletePayloadCaptures :many
WITH due AS (
    SELECT c.org_id, c.id
    FROM pc.payload_captures c
    WHERE c.org_id = sqlc.arg(org_id) AND (c.remove_at <= sqlc.arg(now) OR c.created_at < sqlc.arg(cutoff))
      AND NOT pc.retention_held(c.created_at, c.transaction_id)
    ORDER BY c.created_at
    LIMIT sqlc.arg(max_rows)
)
DELETE FROM pc.payload_captures u
USING due
WHERE u.org_id = due.org_id AND u.id = due.id
RETURNING u.created_at;
