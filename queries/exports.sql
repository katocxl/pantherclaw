-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Export destinations (G0 M20 D252; F517, HR-513..516). Every state change
-- is a conditional update.

-- name: InsertExportDestination :exec
INSERT INTO pc.export_destinations (org_id, id, name, kind, url, bucket, region, key_prefix, path_style, internal,
                                    data_classes, secret, created_by)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(name), sqlc.arg(kind), sqlc.arg(url), sqlc.narg(bucket), sqlc.narg(region),
        sqlc.arg(key_prefix), sqlc.arg(path_style), sqlc.arg(internal), sqlc.arg(data_classes), sqlc.arg(secret),
        sqlc.arg(created_by));

-- name: GetExportDestination :one
SELECT id, name, kind, url, bucket, region, key_prefix, path_style, internal, data_classes, state, secret_replaced_at,
       created_by, created_at, activated_by, activated_at, confirmed_at, last_delivered_at, consecutive_failures,
       failing_since, last_failure_at, last_failure_code, delivered_pushes, failed_pushes
FROM pc.export_destinations
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: ListExportDestinations :many
SELECT id, name, kind, url, bucket, region, key_prefix, path_style, internal, data_classes, state, secret_replaced_at,
       created_by, created_at, activated_by, activated_at, confirmed_at, last_delivered_at, consecutive_failures,
       failing_since, last_failure_at, last_failure_code, delivered_pushes, failed_pushes
FROM pc.export_destinations
WHERE org_id = sqlc.arg(org_id) AND state <> 'DISABLED'
  AND (sqlc.narg(after_id)::uuid IS NULL OR id > sqlc.narg(after_id)::uuid)
ORDER BY id
LIMIT sqlc.arg(max_rows)::int;

-- name: ActivateExportDestination :execrows
-- A person with a fresh step-up activates a PENDING destination (HR-513);
-- the database clock sets activated_at.
UPDATE pc.export_destinations
SET state = 'ACTIVE', activated_by = sqlc.arg(activated_by), activated_credential = sqlc.arg(activated_credential),
    updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'PENDING';

-- name: SetExportDestinationState :execrows
UPDATE pc.export_destinations SET state = sqlc.arg(state), updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = sqlc.arg(expected);

-- name: ReplaceExportSecret :execrows
UPDATE pc.export_destinations SET secret = sqlc.arg(secret), secret_replaced_at = now(), updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state <> 'DISABLED';
