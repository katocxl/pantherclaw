-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Access (M2): users, invitations and role bindings. Tenant-scoped like
-- every query; a zero page cursor arrives as NULL. Changes that can remove
-- the last Org Admin first take LockOrgAdmins (FOR NO KEY UPDATE on the org
-- row: it serializes those changes without blocking foreign-key checks).

-- name: LockOrgAdmins :exec
SELECT id FROM pc.orgs WHERE id = sqlc.arg(org_id) FOR NO KEY UPDATE;

-- name: CountActiveOrgAdmins :one
SELECT count(DISTINCT rb.user_id)
FROM pc.role_bindings rb
JOIN pc.users u ON u.org_id = rb.org_id AND u.id = rb.user_id
WHERE rb.org_id = sqlc.arg(org_id) AND rb.role = 'org_admin' AND rb.scope_type = 'ORG' AND u.state = 'ACTIVE'
  AND NOT EXISTS (SELECT FROM pc.account_deletion_steps ds WHERE ds.org_id=u.org_id AND ds.user_id=u.id);

-- name: GetUser :one
SELECT * FROM pc.users WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: ListUsers :many
SELECT * FROM pc.users
WHERE org_id = sqlc.arg(org_id) AND id > coalesce(sqlc.arg(after)::uuid, '00000000-0000-0000-0000-000000000000')
ORDER BY id
LIMIT sqlc.arg(page_limit);

-- name: SetUserState :one
UPDATE pc.users SET state = sqlc.arg(state), updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id)
RETURNING *;

-- name: RevokeUserSessions :execrows
UPDATE pc.cli_sessions SET state = 'REVOKED', revoke_reason = sqlc.arg(reason), revoked_at = now()
WHERE org_id = sqlc.arg(org_id) AND user_id = sqlc.arg(user_id) AND state = 'ACTIVE';

-- name: ShareServiceAccount :one
SELECT * FROM pc.service_accounts WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) FOR SHARE;

-- name: ShareEnvironment :one
SELECT state FROM pc.environments WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) FOR SHARE;

-- name: InsertInvitation :one
INSERT INTO pc.invitations (org_id, id, kind, email, roles, token_hash, created_by, expires_at)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(kind), sqlc.arg(email), sqlc.arg(roles)::text[], sqlc.arg(token_hash),
        sqlc.arg(created_by), now() + make_interval(hours => sqlc.arg(ttl_hours)::int))
RETURNING *, CASE WHEN state = 'PENDING' AND expires_at <= now() THEN 'EXPIRED' ELSE state END::text AS effective_state;

-- name: ListInvitations :many
SELECT *, CASE WHEN state = 'PENDING' AND expires_at <= now() THEN 'EXPIRED' ELSE state END::text AS effective_state
FROM pc.invitations
WHERE org_id = sqlc.arg(org_id) AND id > coalesce(sqlc.arg(after)::uuid, '00000000-0000-0000-0000-000000000000')
  AND (sqlc.arg(include_closed)::bool OR (state = 'PENDING' AND expires_at > now()))
ORDER BY id
LIMIT sqlc.arg(page_limit);

-- name: RevokeInvitation :one
UPDATE pc.invitations SET state = 'REVOKED', revoked_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'PENDING'
RETURNING *, 'REVOKED'::text AS effective_state;

-- name: InvitationExists :one
SELECT EXISTS (SELECT 1 FROM pc.invitations WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id));

-- name: InsertRoleBinding :one
INSERT INTO pc.role_bindings (org_id, id, role, user_id, service_account_id, scope_type, business_unit_id, team_id,
                              environment_id, created_by)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(role), sqlc.narg(user_id), sqlc.narg(service_account_id),
        sqlc.arg(scope_type), sqlc.narg(business_unit_id), sqlc.narg(team_id), sqlc.narg(environment_id), sqlc.arg(created_by))
RETURNING *;

-- name: GetRoleBinding :one
SELECT * FROM pc.role_bindings WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: DeleteRoleBinding :execrows
DELETE FROM pc.role_bindings WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: ListRoleBindings :many
SELECT * FROM pc.role_bindings
WHERE org_id = sqlc.arg(org_id) AND id > coalesce(sqlc.arg(after)::uuid, '00000000-0000-0000-0000-000000000000')
  AND (sqlc.narg(user_id)::uuid IS NULL OR user_id = sqlc.narg(user_id))
  AND (sqlc.narg(service_account_id)::uuid IS NULL OR service_account_id = sqlc.narg(service_account_id))
ORDER BY id
LIMIT sqlc.arg(page_limit);

-- name: BindingsOfUser :many
SELECT * FROM pc.role_bindings WHERE org_id = sqlc.arg(org_id) AND user_id = sqlc.arg(user_id) ORDER BY id LIMIT 500;

-- name: BindingsOfServiceAccount :many
SELECT * FROM pc.role_bindings
WHERE org_id = sqlc.arg(org_id) AND service_account_id = sqlc.arg(service_account_id) ORDER BY id LIMIT 500;

-- name: RevokeBootstrapInvitations :execrows
UPDATE pc.invitations SET state = 'REVOKED', revoked_at = now()
WHERE org_id = sqlc.arg(org_id) AND kind = 'BOOTSTRAP' AND state = 'PENDING';

-- name: InsertOrg :exec
INSERT INTO pc.orgs (id, name) VALUES (sqlc.arg(org_id), sqlc.arg(name));
