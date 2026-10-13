-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- GitHub identities (G0 M8, HR-207): a person of the org linked to a
-- GitHub user id, which independence compares.

-- name: InsertGitHubIdentity :one
-- A link the person proved by signing in to GitHub (P2f): verified now.
INSERT INTO pc.github_identities (org_id, id, user_id, github_login, github_user_id, linked_by, verified_at)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(user_id), sqlc.arg(github_login), sqlc.arg(github_user_id), sqlc.arg(linked_by), now())
RETURNING *;

-- name: InsertGitHubIdentityHistory :exec
-- Every link a person proved, kept for good (P2f): see 00083.
INSERT INTO pc.github_identity_history (org_id, github_user_id, user_id)
VALUES (sqlc.arg(org_id), sqlc.arg(github_user_id), sqlc.arg(user_id))
ON CONFLICT DO NOTHING;

-- name: GitHubIdentityByGitHubUser :one
SELECT * FROM pc.github_identities WHERE org_id = sqlc.arg(org_id) AND github_user_id = sqlc.arg(github_user_id);

-- name: GitHubIdentity :one
SELECT * FROM pc.github_identities WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: DeleteGitHubIdentity :one
DELETE FROM pc.github_identities WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id)
RETURNING *;

-- name: ListGitHubIdentities :many
SELECT * FROM pc.github_identities
WHERE org_id = sqlc.arg(org_id) AND (sqlc.narg(user_id)::uuid IS NULL OR user_id = sqlc.narg(user_id)::uuid)
  AND id > coalesce(sqlc.arg(after_id)::uuid, '00000000-0000-0000-0000-000000000000')
ORDER BY id
LIMIT sqlc.arg(max_rows);
