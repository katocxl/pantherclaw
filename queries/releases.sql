-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

-- Change windows (G0 M8 track P, HR-207).

-- name: ActiveChangeWindow :one
-- The ACTIVE window of an environment and repository ('' for every
-- repository), locked so that a replacement takes the next revision.
SELECT * FROM pc.change_windows
WHERE org_id = sqlc.arg(org_id) AND environment = sqlc.arg(environment) AND coalesce(repository, '') = sqlc.arg(repository)::text
  AND state = 'ACTIVE'
FOR UPDATE;

-- name: LastChangeWindowRevision :one
SELECT coalesce(max(revision), 0)::integer FROM pc.change_windows
WHERE org_id = sqlc.arg(org_id) AND environment = sqlc.arg(environment) AND coalesce(repository, '') = sqlc.arg(repository)::text;

-- name: InsertChangeWindow :one
INSERT INTO pc.change_windows (org_id, id, environment, repository, time_zone, weekly, one_off, freezes, revision, created_by)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(environment), sqlc.narg(repository), sqlc.arg(time_zone), sqlc.arg(weekly),
    sqlc.arg(one_off), sqlc.arg(freezes), sqlc.arg(revision), sqlc.arg(created_by))
RETURNING *;

-- name: RetireChangeWindow :one
UPDATE pc.change_windows SET state = 'RETIRED', retired_by = sqlc.arg(retired_by), retired_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'ACTIVE'
RETURNING *;

-- name: GetChangeWindow :one
SELECT * FROM pc.change_windows WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: ListChangeWindows :many
SELECT * FROM pc.change_windows
WHERE org_id = sqlc.arg(org_id) AND (sqlc.arg(environment)::text = '' OR environment = sqlc.arg(environment))
  AND (sqlc.arg(include_retired)::boolean OR state = 'ACTIVE')
ORDER BY environment, coalesce(repository, ''), revision DESC
LIMIT 500;

-- name: ApplicableChangeWindows :many
-- The ACTIVE windows that apply to a release to an environment and
-- repository (its own and the environment's), with the database clock
-- that decides them (HR-171).
SELECT w.*, now()::timestamptz AS decided_at FROM pc.change_windows w
WHERE w.org_id = sqlc.arg(org_id) AND w.environment = sqlc.arg(environment) AND w.state = 'ACTIVE'
  AND (w.repository IS NULL OR w.repository = sqlc.arg(repository)::text);
