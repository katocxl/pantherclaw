-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Threat map queries (G0 M28 D716, D719). Every query runs inside
-- db.InTenantTx and also filters by org_id explicitly. The evaluator's
-- input reads join these in phase 2.

-- name: UpsertThreatMapSnapshot :exec
-- Today's evaluation for one scope and framework; a later run the same day
-- replaces it.
INSERT INTO pc.threat_map_snapshots (org_id, scope_key, framework, day, evaluated_at,
    catalog_version, catalog_digest, mapping_digest, states, counts)
VALUES (sqlc.arg(org_id), sqlc.arg(scope_key), sqlc.arg(framework), sqlc.arg(day), sqlc.arg(evaluated_at),
    sqlc.arg(catalog_version), sqlc.arg(catalog_digest), sqlc.arg(mapping_digest), sqlc.arg(states), sqlc.arg(counts))
ON CONFLICT (org_id, scope_key, framework, day) DO UPDATE SET
    evaluated_at = EXCLUDED.evaluated_at, catalog_version = EXCLUDED.catalog_version,
    catalog_digest = EXCLUDED.catalog_digest, mapping_digest = EXCLUDED.mapping_digest,
    states = EXCLUDED.states, counts = EXCLUDED.counts;

-- name: LatestThreatMapSnapshot :one
-- The newest stored evaluation for one scope and framework, the one a new
-- evaluation is compared with to find dropped lanes.
SELECT day, evaluated_at, catalog_version, catalog_digest, mapping_digest, states, counts
FROM pc.threat_map_snapshots
WHERE org_id = sqlc.arg(org_id) AND scope_key = sqlc.arg(scope_key) AND framework = sqlc.arg(framework)
ORDER BY day DESC
LIMIT 1;

-- name: ThreatMapSnapshotsSince :many
-- One scope and framework's days from since on, oldest first (history).
SELECT day, evaluated_at, catalog_version, mapping_digest, states, counts
FROM pc.threat_map_snapshots
WHERE org_id = sqlc.arg(org_id) AND scope_key = sqlc.arg(scope_key) AND framework = sqlc.arg(framework)
    AND day >= sqlc.arg(since)
ORDER BY day;

-- name: DeleteOldThreatMapSnapshots :execrows
-- Rows older than the history keeps (400 days, D719).
DELETE FROM pc.threat_map_snapshots WHERE org_id = sqlc.arg(org_id) AND day < sqlc.arg(before);
