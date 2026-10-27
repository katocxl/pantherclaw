-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Break-glass access (G0 M13 D33; HR-389), in the org's tenant
-- transaction.

-- name: ListBreakGlassHolders :many
SELECT * FROM pc.breakglass_holders WHERE org_id = sqlc.arg(org_id) ORDER BY designated_at, user_id;

-- name: GetBreakGlassHolder :one
SELECT * FROM pc.breakglass_holders WHERE org_id = sqlc.arg(org_id) AND user_id = sqlc.arg(user_id);

-- name: DeleteBreakGlassHolder :execrows
DELETE FROM pc.breakglass_holders WHERE org_id = sqlc.arg(org_id) AND user_id = sqlc.arg(user_id);

-- name: PutBreakGlassHolder :exec
INSERT INTO pc.breakglass_holders (org_id, user_id, role, designated_by)
VALUES (sqlc.arg(org_id), sqlc.arg(user_id), sqlc.arg(role), sqlc.arg(designated_by))
ON CONFLICT (org_id, user_id) DO UPDATE
SET role = EXCLUDED.role, designated_by = EXCLUDED.designated_by, designated_at = now()
WHERE pc.breakglass_holders.role IS DISTINCT FROM EXCLUDED.role;

-- name: EndExpiredBreakGlass :many
-- Closes a holder's activation that ran out, so a new one can start.
UPDATE pc.breakglass_activations
SET ended_at = expires_at, end_reason = 'EXPIRED'
WHERE org_id = sqlc.arg(org_id) AND ended_at IS NULL AND now() >= expires_at
RETURNING id;

-- name: InsertBreakGlassActivation :one
INSERT INTO pc.breakglass_activations (org_id, id, user_id, role, reason, credential, expires_at)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(user_id), sqlc.arg(role), sqlc.arg(reason), sqlc.arg(credential),
        now() + make_interval(mins => sqlc.arg(minutes)::int))
RETURNING *;

-- name: LiveBreakGlassOfUser :one
-- The holder's activation in force, while they are still designated with
-- its role.
SELECT a.* FROM pc.breakglass_activations a
JOIN pc.breakglass_holders h ON h.org_id = a.org_id AND h.user_id = a.user_id AND h.role = a.role
JOIN pc.users u ON u.org_id = a.org_id AND u.id = a.user_id AND u.state = 'ACTIVE'
JOIN pc.webauthn_credentials k ON k.org_id = a.org_id AND k.id = a.credential AND k.user_id = a.user_id AND k.state = 'ACTIVE'
WHERE a.org_id = sqlc.arg(org_id) AND a.user_id = sqlc.arg(user_id) AND a.ended_at IS NULL AND now() < a.expires_at;

-- name: GetBreakGlassActivation :one
SELECT a.*, (a.ended_at IS NULL AND now() < a.expires_at)::bool AS active
FROM pc.breakglass_activations a WHERE a.org_id = sqlc.arg(org_id) AND a.id = sqlc.arg(id);

-- name: EndBreakGlassActivation :execrows
UPDATE pc.breakglass_activations
SET ended_at = now(), end_reason = sqlc.arg(end_reason), ended_by_type = sqlc.narg(ended_by_type), ended_by_id = sqlc.narg(ended_by_id)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND ended_at IS NULL;

-- name: EndBreakGlassOfUser :many
UPDATE pc.breakglass_activations
SET ended_at = now(), end_reason = sqlc.arg(end_reason), ended_by_type = sqlc.narg(ended_by_type), ended_by_id = sqlc.narg(ended_by_id)
WHERE org_id = sqlc.arg(org_id) AND user_id = sqlc.arg(user_id) AND ended_at IS NULL
RETURNING id;

-- name: ListBreakGlassActivations :many
SELECT a.*, (a.ended_at IS NULL AND now() < a.expires_at)::bool AS active
FROM pc.breakglass_activations a
WHERE a.org_id = sqlc.arg(org_id) AND (sqlc.narg(before)::uuid IS NULL OR a.id < sqlc.narg(before)::uuid)
ORDER BY a.id DESC
LIMIT sqlc.arg(max_rows);

-- name: UserActiveInOrg :one
SELECT (state = 'ACTIVE')::bool FROM pc.users WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);
