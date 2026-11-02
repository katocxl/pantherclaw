-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Provisioning (G0 M26 D405, D406, D409): the SCIM directory, group role
-- mappings and SAML connections. Directory queries always name the issuer,
-- which is all a SCIM token can see.

-- name: InsertSCIMToken :one
INSERT INTO pc.scim_tokens (org_id, id, name, issuer, subject_attribute, secret_hash, hint, created_by, expires_at)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(name), sqlc.arg(issuer), sqlc.arg(subject_attribute), sqlc.arg(secret_hash),
        sqlc.arg(hint), sqlc.arg(created_by), now() + make_interval(days => sqlc.arg(ttl_days)::int))
RETURNING *;

-- name: SCIMTokenByHash :one
-- Only a token that can act: ACTIVE, unexpired, of an active org.
SELECT t.id, t.issuer, t.subject_attribute
FROM pc.scim_tokens t
JOIN pc.orgs o ON o.id = t.org_id
WHERE t.org_id = sqlc.arg(org_id) AND t.secret_hash = sqlc.arg(secret_hash) AND t.state = 'ACTIVE'
  AND t.expires_at > now() AND o.state = 'ACTIVE';

-- name: TouchSCIMToken :exec
UPDATE pc.scim_tokens SET last_used_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND (last_used_at IS NULL OR last_used_at < now() - interval '1 minute');

-- name: LockSCIMToken :one
SELECT * FROM pc.scim_tokens WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) FOR UPDATE;

-- name: ListSCIMTokens :many
SELECT * FROM pc.scim_tokens WHERE org_id = sqlc.arg(org_id) ORDER BY name LIMIT 200;

-- name: ActivateSCIMToken :execrows
UPDATE pc.scim_tokens SET state = 'ACTIVE', activated_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'PENDING' AND expires_at > now();

-- name: RevokeSCIMToken :execrows
UPDATE pc.scim_tokens SET state = 'REVOKED', revoked_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state IN ('PENDING', 'ACTIVE');

-- name: LapseSCIMToken :execrows
UPDATE pc.scim_tokens SET state = 'LAPSED' WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'PENDING';

-- name: IssuerInUse :one
-- Whether issuer belongs to one of the org's providers, in any state but
-- turned off. The deployment's providers are checked in code.
SELECT (EXISTS (SELECT FROM pc.org_identity_providers p
                WHERE p.org_id = sqlc.arg(org_id) AND p.issuer = sqlc.arg(issuer) AND p.state <> 'DISABLED')
     OR EXISTS (SELECT FROM pc.saml_connections c
                WHERE c.org_id = sqlc.arg(org_id) AND c.issuer = sqlc.arg(issuer) AND c.state IN ('PENDING', 'ACTIVE')))::bool AS in_use;

-- name: CountDirectoryUsers :one
-- userName is not case-exact (RFC 7643 4.1.1): subject_ci and user_name
-- match without case; subject and external_id match exactly.
SELECT count(*)
FROM pc.users u
LEFT JOIN pc.scim_users s ON s.org_id = u.org_id AND s.user_id = u.id
WHERE u.org_id = sqlc.arg(org_id) AND u.issuer = sqlc.arg(issuer) AND s.deleted_at IS NULL
  AND (sqlc.narg(subject)::text IS NULL OR u.subject = sqlc.narg(subject))
  AND (sqlc.narg(subject_ci)::text IS NULL OR lower(u.subject) = lower(sqlc.narg(subject_ci)))
  AND (sqlc.narg(user_name)::text IS NULL OR lower(s.user_name) = lower(sqlc.narg(user_name)))
  AND (sqlc.narg(external_id)::text IS NULL OR s.external_id = sqlc.narg(external_id));

-- name: ListDirectoryUsers :many
SELECT u.id, u.subject, u.email, u.display_name, u.state, u.created_at, u.updated_at, s.user_name, s.external_id
FROM pc.users u
LEFT JOIN pc.scim_users s ON s.org_id = u.org_id AND s.user_id = u.id
WHERE u.org_id = sqlc.arg(org_id) AND u.issuer = sqlc.arg(issuer) AND s.deleted_at IS NULL
  AND (sqlc.narg(subject)::text IS NULL OR u.subject = sqlc.narg(subject))
  AND (sqlc.narg(subject_ci)::text IS NULL OR lower(u.subject) = lower(sqlc.narg(subject_ci)))
  AND (sqlc.narg(user_name)::text IS NULL OR lower(s.user_name) = lower(sqlc.narg(user_name)))
  AND (sqlc.narg(external_id)::text IS NULL OR s.external_id = sqlc.narg(external_id))
ORDER BY u.id
LIMIT sqlc.arg(page_limit) OFFSET sqlc.arg(page_offset);

-- name: LockDirectoryUser :one
-- A user of this issuer not hidden from SCIM, locked for the change.
SELECT u.id, u.subject, u.email, u.display_name, u.state, u.created_at, u.updated_at,
       s.user_name, s.external_id, coalesce(s.disabled_by_scim, false)::bool AS disabled_by_scim, s.deleted_at
FROM pc.users u
LEFT JOIN pc.scim_users s ON s.org_id = u.org_id AND s.user_id = u.id
WHERE u.org_id = sqlc.arg(org_id) AND u.issuer = sqlc.arg(issuer) AND u.id = sqlc.arg(id)
FOR UPDATE OF u;

-- name: DirectoryUserBySubject :one
SELECT u.id, u.state, s.deleted_at
FROM pc.users u
LEFT JOIN pc.scim_users s ON s.org_id = u.org_id AND s.user_id = u.id
WHERE u.org_id = sqlc.arg(org_id) AND u.issuer = sqlc.arg(issuer) AND u.subject = sqlc.arg(subject)
FOR UPDATE OF u;

-- name: InsertProvisionedUser :one
INSERT INTO pc.users (org_id, id, issuer, subject, email, display_name, state)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(issuer), sqlc.arg(subject), sqlc.arg(email), sqlc.arg(display_name), sqlc.arg(state))
RETURNING *;

-- name: SetProvisionedProfile :exec
UPDATE pc.users SET email = sqlc.arg(email), display_name = sqlc.arg(display_name), updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: PutSCIMUser :exec
INSERT INTO pc.scim_users (org_id, user_id, user_name, external_id, disabled_by_scim, deleted_at)
VALUES (sqlc.arg(org_id), sqlc.arg(user_id), sqlc.narg(user_name), sqlc.narg(external_id), sqlc.arg(disabled_by_scim), sqlc.narg(deleted_at))
ON CONFLICT (org_id, user_id) DO UPDATE
SET user_name = EXCLUDED.user_name, external_id = EXCLUDED.external_id, disabled_by_scim = EXCLUDED.disabled_by_scim,
    deleted_at = EXCLUDED.deleted_at, updated_at = now();

-- name: ClearSCIMDisabled :exec
-- A person disabled this user: from now on only a person enables them.
UPDATE pc.scim_users SET disabled_by_scim = false, updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND user_id = sqlc.arg(user_id) AND disabled_by_scim;

-- name: ClearSCIMExternalID :exec
-- Account deletion: the userName and external id may name the person.
UPDATE pc.scim_users SET user_name = NULL, external_id = NULL, updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND user_id = sqlc.arg(user_id);

-- name: MarkSCIMDeprovisioned :exec
INSERT INTO pc.scim_users (org_id, user_id, deprovisioned_at) VALUES (sqlc.arg(org_id), sqlc.arg(user_id), now())
ON CONFLICT (org_id, user_id) DO UPDATE SET deprovisioned_at = now(), updated_at = now();

-- name: ActiveKeysOfDeprovisioned :many
-- API keys a person made before SCIM deprovisioned them: they stay active
-- until a person rotates or revokes them (D409), so the posture queue lists
-- them while they are active, whatever later happens to the person (D528).
SELECT k.id, k.name, k.hint, k.service_account_id, k.expires_at, u.id AS user_id,
       coalesce(s.deprovisioned_at, s.updated_at)::timestamptz AS deprovisioned_at
FROM pc.scim_users s
JOIN pc.users u ON u.org_id = s.org_id AND u.id = s.user_id
JOIN pc.api_keys k ON k.org_id = s.org_id AND k.created_by = 'user:' || u.id::text
WHERE s.org_id = sqlc.arg(org_id) AND s.deprovisioned_at IS NOT NULL AND k.created_at <= s.deprovisioned_at
  AND k.state = 'ACTIVE' AND k.expires_at > now()
ORDER BY u.id, k.name
LIMIT sqlc.arg(page_limit);

-- name: CountActiveKeysOfUser :one
SELECT count(*) FROM pc.api_keys
WHERE org_id = sqlc.arg(org_id) AND created_by = sqlc.arg(created_by) AND state = 'ACTIVE' AND expires_at > now();

-- name: InsertGroup :one
INSERT INTO pc.groups (org_id, id, issuer, display_name, external_id)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(issuer), sqlc.arg(display_name), sqlc.narg(external_id))
RETURNING *;

-- name: LockGroup :one
SELECT * FROM pc.groups
WHERE org_id = sqlc.arg(org_id) AND issuer = sqlc.arg(issuer) AND id = sqlc.arg(id) FOR UPDATE;

-- name: GroupByID :one
SELECT * FROM pc.groups WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: SetGroup :one
UPDATE pc.groups SET display_name = sqlc.arg(display_name), external_id = sqlc.narg(external_id), updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id)
RETURNING *;

-- name: DeleteGroup :exec
DELETE FROM pc.groups WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: CountDirectoryGroups :one
SELECT count(*) FROM pc.groups g
WHERE g.org_id = sqlc.arg(org_id) AND g.issuer = sqlc.arg(issuer)
  AND (sqlc.narg(display_name)::text IS NULL OR g.display_name = sqlc.narg(display_name))
  AND (sqlc.narg(external_id)::text IS NULL OR g.external_id = sqlc.narg(external_id));

-- name: ListDirectoryGroups :many
SELECT * FROM pc.groups g
WHERE g.org_id = sqlc.arg(org_id) AND g.issuer = sqlc.arg(issuer)
  AND (sqlc.narg(display_name)::text IS NULL OR g.display_name = sqlc.narg(display_name))
  AND (sqlc.narg(external_id)::text IS NULL OR g.external_id = sqlc.narg(external_id))
ORDER BY g.id
LIMIT sqlc.arg(page_limit) OFFSET sqlc.arg(page_offset);

-- name: ListAllGroups :many
SELECT g.*, (SELECT count(*) FROM pc.group_members m WHERE m.org_id = g.org_id AND m.group_id = g.id)::bigint AS member_count
FROM pc.groups g
WHERE g.org_id = sqlc.arg(org_id) AND g.id > coalesce(sqlc.arg(after)::uuid, '00000000-0000-0000-0000-000000000000')
ORDER BY g.id
LIMIT sqlc.arg(page_limit);

-- name: GroupMemberIDs :many
SELECT user_id FROM pc.group_members WHERE org_id = sqlc.arg(org_id) AND group_id = sqlc.arg(group_id) ORDER BY user_id;

-- name: AddGroupMember :exec
INSERT INTO pc.group_members (org_id, group_id, user_id) VALUES (sqlc.arg(org_id), sqlc.arg(group_id), sqlc.arg(user_id))
ON CONFLICT DO NOTHING;

-- name: RemoveGroupMember :exec
DELETE FROM pc.group_members WHERE org_id = sqlc.arg(org_id) AND group_id = sqlc.arg(group_id) AND user_id = sqlc.arg(user_id);

-- name: GroupsOfUser :many
SELECT group_id FROM pc.group_members WHERE org_id = sqlc.arg(org_id) AND user_id = sqlc.arg(user_id);

-- name: DesiredBindings :many
-- What a user's groups give them. One row per binding.
SELECT DISTINCT r.role, r.scope_type, r.business_unit_id, r.team_id, r.environment_id
FROM pc.group_members m
JOIN pc.group_role_mappings r ON r.org_id = m.org_id AND r.group_id = m.group_id
WHERE m.org_id = sqlc.arg(org_id) AND m.user_id = sqlc.arg(user_id);

-- name: ProvisionedBindings :many
SELECT * FROM pc.role_bindings WHERE org_id = sqlc.arg(org_id) AND user_id = sqlc.arg(user_id) AND provisioned;

-- name: InsertProvisionedBinding :execrows
-- A person's identical binding is another row (the source is in the key,
-- D528): each one's removal leaves the other.
INSERT INTO pc.role_bindings (org_id, id, role, user_id, scope_type, business_unit_id, team_id, environment_id, created_by, provisioned)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(role), sqlc.arg(user_id), sqlc.arg(scope_type), sqlc.narg(business_unit_id),
        sqlc.narg(team_id), sqlc.narg(environment_id), 'scim:group', true)
ON CONFLICT DO NOTHING;

-- name: DeleteProvisionedBinding :exec
DELETE FROM pc.role_bindings WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND provisioned;

-- name: InsertGroupRoleMapping :one
INSERT INTO pc.group_role_mappings (org_id, id, group_id, role, scope_type, business_unit_id, team_id, environment_id, created_by)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(group_id), sqlc.arg(role), sqlc.arg(scope_type), sqlc.narg(business_unit_id),
        sqlc.narg(team_id), sqlc.narg(environment_id), sqlc.arg(created_by))
RETURNING *;

-- name: GetGroupRoleMapping :one
SELECT * FROM pc.group_role_mappings WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: DeleteGroupRoleMapping :execrows
DELETE FROM pc.group_role_mappings WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: ListGroupRoleMappings :many
SELECT * FROM pc.group_role_mappings WHERE org_id = sqlc.arg(org_id) ORDER BY id LIMIT 1000;

-- name: InsertSAMLConnection :one
INSERT INTO pc.saml_connections (org_id, id, name, idp_entity_id, sso_url, certificates, created_by)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(name), sqlc.arg(idp_entity_id), sqlc.arg(sso_url), sqlc.arg(certificates)::text[], sqlc.arg(created_by))
RETURNING *;

-- name: LockSAMLConnection :one
SELECT * FROM pc.saml_connections WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) FOR UPDATE;

-- name: GetSAMLConnection :one
SELECT * FROM pc.saml_connections WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: ListSAMLConnections :many
SELECT * FROM pc.saml_connections WHERE org_id = sqlc.arg(org_id) ORDER BY name LIMIT 32;

-- name: CountSAMLConnections :one
SELECT count(*) FROM pc.saml_connections WHERE org_id = sqlc.arg(org_id) AND state IN ('PENDING', 'ACTIVE');

-- name: ActiveSAMLIssuers :many
SELECT id, issuer FROM pc.saml_connections WHERE org_id = sqlc.arg(org_id) AND state = 'ACTIVE';

-- name: PutSAMLConnection :execrows
UPDATE pc.saml_connections
SET sso_url = sqlc.arg(sso_url), certificates = sqlc.arg(certificates)::text[], state = 'ACTIVE',
    activated_at = coalesce(activated_at, now()), disabled_at = NULL, updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: DisableSAMLConnection :execrows
UPDATE pc.saml_connections SET state = 'DISABLED', disabled_at = now(), updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state <> 'DISABLED';

-- name: LapseSAMLConnection :execrows
UPDATE pc.saml_connections SET state = 'LAPSED', updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'PENDING';
