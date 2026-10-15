-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

-- Saved queries (G0 M10 D34, F317, HR-257). Only specifications are stored;
-- running one always re-runs it under the viewer's permissions.

-- name: InsertSavedQuery :one
INSERT INTO pc.saved_queries (org_id, id, owner, name, description, visibility, team_id, spec)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
RETURNING *;

-- name: GetSavedQuery :one
SELECT * FROM pc.saved_queries WHERE org_id = $1 AND id = $2;

-- name: ListSavedQueries :many
-- The caller's own queries, the org's and those shared with the given
-- teams, newest first.
SELECT * FROM pc.saved_queries
WHERE org_id = sqlc.arg(org_id)
  AND (owner = sqlc.arg(owner)::text OR visibility = 'ORG'
       OR (visibility = 'TEAM' AND team_id = ANY (sqlc.arg(teams)::uuid[])))
  AND (sqlc.narg(before)::uuid IS NULL OR id < sqlc.narg(before)::uuid)
ORDER BY id DESC
LIMIT sqlc.arg(page_limit);

-- name: UpdateSavedQuery :one
UPDATE pc.saved_queries
SET name = $4, description = $5, visibility = $6, team_id = $7, spec = $8
WHERE org_id = $1 AND id = $2 AND owner = $3
RETURNING *;

-- name: DeleteSavedQuery :execrows
DELETE FROM pc.saved_queries WHERE org_id = $1 AND id = $2 AND owner = $3;

-- name: SavedQueryTeams :many
-- Every team of the org with its business unit: the places a TEAM query
-- may be shared with.
SELECT id, business_unit_id FROM pc.teams WHERE org_id = $1 ORDER BY id;
