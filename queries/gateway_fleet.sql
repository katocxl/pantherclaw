-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Gateway fleet policy (00216), G0 M18 D151.

-- name: GetGatewayFleetPolicy :one
SELECT * FROM pc.gateway_fleet_policy WHERE org_id = sqlc.arg(org_id);

-- name: UpsertGatewayFleetPolicy :one
INSERT INTO pc.gateway_fleet_policy (org_id, minimum_version, silence_after_seconds, updated_by, updated_at)
VALUES (sqlc.arg(org_id), sqlc.narg(minimum_version), sqlc.arg(silence_after_seconds), sqlc.arg(updated_by), sqlc.arg(updated_at))
ON CONFLICT (org_id) DO UPDATE
SET minimum_version = EXCLUDED.minimum_version, silence_after_seconds = EXCLUDED.silence_after_seconds,
    updated_by = EXCLUDED.updated_by, updated_at = EXCLUDED.updated_at
RETURNING *;

-- Gateway alert state (00217).

-- name: ListGatewayAlertStates :many
SELECT * FROM pc.gateway_alert_state
WHERE org_id = sqlc.arg(org_id) AND gateway_id = ANY(sqlc.arg(gateway_ids)::uuid[]);

-- name: ListActiveGatewayIDs :many
SELECT id FROM pc.gateways
WHERE org_id = sqlc.arg(org_id) AND state = 'ACTIVE'
  AND id > coalesce(sqlc.arg(after_id)::uuid, '00000000-0000-0000-0000-000000000000')
ORDER BY id
LIMIT sqlc.arg(max_rows);

-- name: UpsertGatewayAlertState :exec
INSERT INTO pc.gateway_alert_state (org_id, gateway_id, silent_since, silent_notified_at, below_minimum_version, below_minimum_notified_at)
VALUES (sqlc.arg(org_id), sqlc.arg(gateway_id), sqlc.narg(silent_since), sqlc.narg(silent_notified_at),
        sqlc.narg(below_minimum_version), sqlc.narg(below_minimum_notified_at))
ON CONFLICT (org_id, gateway_id) DO UPDATE
SET silent_since = EXCLUDED.silent_since, silent_notified_at = EXCLUDED.silent_notified_at,
    below_minimum_version = EXCLUDED.below_minimum_version, below_minimum_notified_at = EXCLUDED.below_minimum_notified_at;

-- name: LockGatewayAlertState :exec
SELECT pg_advisory_xact_lock(hashtextextended('pc.gateway_alert_state:' || sqlc.arg(org_id)::uuid::text, 0));

-- name: RecordGatewayReport :exec
INSERT INTO pc.gateway_alert_state (org_id, gateway_id, last_report_at)
VALUES (sqlc.arg(org_id), sqlc.arg(gateway_id), sqlc.arg(last_report_at))
ON CONFLICT (org_id, gateway_id) DO UPDATE
SET last_report_at = GREATEST(pc.gateway_alert_state.last_report_at, EXCLUDED.last_report_at);
