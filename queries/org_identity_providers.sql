-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Organization identity providers (G0 M18 D155, HR-481..484). State
-- changes are conditional updates (HR-004). The sealed client secret is
-- read only by the resolver, never by a listing (HR-482).

-- name: InsertOrgIdentityProvider :one
INSERT INTO pc.org_identity_providers (org_id, id, name, issuer, client_id, client_secret, trust_email, created_by, updated_by)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(name), sqlc.arg(issuer), sqlc.arg(client_id), sqlc.arg(client_secret),
        sqlc.arg(trust_email), sqlc.arg(created_by), sqlc.arg(created_by))
RETURNING id, name, issuer, client_id, trust_email, state, created_by, created_at, updated_by, updated_at, activated_at,
    disabled_by, disabled_at;

-- name: GetOrgIdentityProvider :one
SELECT id, name, issuer, client_id, trust_email, state, created_by, created_at, updated_by, updated_at, activated_at,
    disabled_by, disabled_at
FROM pc.org_identity_providers WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: LockOrgIdentityProvider :one
SELECT id, name, issuer, client_id, sha256(client_secret)::bytea AS secret_digest, trust_email, state, updated_at, activated_at
FROM pc.org_identity_providers WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) FOR UPDATE;

-- name: ListOrgIdentityProviders :many
SELECT id, name, issuer, client_id, trust_email, state, created_by, created_at, updated_by, updated_at, activated_at,
    disabled_by, disabled_at
FROM pc.org_identity_providers WHERE org_id = sqlc.arg(org_id)
ORDER BY name
LIMIT 100;

-- The providers that count toward the org's limit (D169): ACTIVE ones and
-- the others whose activation is filed (PENDING, or DISABLED being
-- activated again), other than except_id.
-- name: CountOrgIdentityProviders :one
SELECT count(*) FROM pc.org_identity_providers p
WHERE p.org_id = sqlc.arg(org_id) AND p.id IS DISTINCT FROM sqlc.narg(except_id)::uuid
  AND (p.state = 'ACTIVE' OR EXISTS (
      SELECT 1 FROM pc.protected_changes c
      WHERE c.org_id = p.org_id AND c.surface = 'identity_provider.put' AND c.subject_id = p.id AND c.state = 'PENDING'));

-- A provider never activated whose activation was declined or expired
-- stops counting (D169).
-- name: LapseOrgIdentityProvider :execrows
UPDATE pc.org_identity_providers
SET state = 'DISABLED', disabled_by = sqlc.arg(disabled_by), disabled_at = now(), updated_by = sqlc.arg(disabled_by), updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'PENDING' AND activated_at IS NULL;

-- The ACTIVE providers with their sealed secrets, for the per-request
-- resolver.
-- name: ActiveOrgIdentityProviders :many
SELECT id, name, issuer, client_id, client_secret, trust_email, updated_at
FROM pc.org_identity_providers WHERE org_id = sqlc.arg(org_id) AND state = 'ACTIVE'
ORDER BY name
LIMIT 100;

-- name: PutOrgIdentityProvider :execrows
UPDATE pc.org_identity_providers
SET name = sqlc.arg(name), issuer = sqlc.arg(issuer), client_id = sqlc.arg(client_id),
    client_secret = coalesce(sqlc.narg(client_secret)::bytea, client_secret), trust_email = sqlc.arg(trust_email),
    state = 'ACTIVE', activated_at = coalesce(activated_at, now()), disabled_by = NULL, disabled_at = NULL,
    updated_by = sqlc.arg(updated_by), updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: DisableOrgIdentityProvider :execrows
UPDATE pc.org_identity_providers
SET state = 'DISABLED', disabled_by = sqlc.arg(disabled_by), disabled_at = now(), updated_by = sqlc.arg(disabled_by),
    updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state <> 'DISABLED';

-- name: OrgIdentityProviderSettings :one
SELECT own_providers_only, updated_at FROM pc.org_identity_provider_settings WHERE org_id = sqlc.arg(org_id);

-- name: LockOrgIdentityProviderSettings :exec
SELECT pg_advisory_xact_lock(hashtextextended('pc.org_identity_providers:' || sqlc.arg(org_id)::uuid::text, 0));

-- name: SetOwnProvidersOnly :exec
INSERT INTO pc.org_identity_provider_settings (org_id, own_providers_only, updated_by)
VALUES (sqlc.arg(org_id), sqlc.arg(own_providers_only), sqlc.arg(updated_by))
ON CONFLICT (org_id) DO UPDATE
SET own_providers_only = EXCLUDED.own_providers_only, updated_by = EXCLUDED.updated_by, updated_at = now();

-- The org's active admins (enabled people holding org_admin at the org)
-- with their identity issuers, for the lock-out guard (HR-484, D162).
-- name: OrgAdminIdentities :many
SELECT DISTINCT u.id, u.issuer
FROM pc.role_bindings b
JOIN pc.users u ON u.org_id = b.org_id AND u.id = b.user_id
WHERE b.org_id = sqlc.arg(org_id) AND b.role = 'org_admin' AND b.scope_type = 'ORG' AND u.state = 'ACTIVE'
ORDER BY u.id
LIMIT 1000;
