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
