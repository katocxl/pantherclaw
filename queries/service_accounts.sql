-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Service accounts, their public keys and API keys (M2, ADR-0016).
-- Tenant-scoped; a zero page cursor arrives as NULL; state changes are
-- conditional (HR-004); expiry uses the database clock.

-- name: InsertServiceAccount :one
INSERT INTO pc.service_accounts (org_id, id, name, description, created_by)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(name), sqlc.arg(description), sqlc.arg(created_by))
RETURNING *;

-- name: GetServiceAccount :one
SELECT * FROM pc.service_accounts WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: ListServiceAccounts :many
SELECT * FROM pc.service_accounts
WHERE org_id = sqlc.arg(org_id) AND id > coalesce(sqlc.arg(after)::uuid, '00000000-0000-0000-0000-000000000000')
ORDER BY id
LIMIT sqlc.arg(page_limit);

-- name: UpdateServiceAccount :one
UPDATE pc.service_accounts SET description = coalesce(sqlc.narg(description), description), updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id)
RETURNING *;

-- name: SetServiceAccountState :one
UPDATE pc.service_accounts SET state = sqlc.arg(state), updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id)
RETURNING *;

-- name: InsertServiceAccountKey :one
INSERT INTO pc.service_account_keys (org_id, id, service_account_id, kid, alg, public_jwk, created_by, expires_at)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(service_account_id), sqlc.arg(kid), sqlc.arg(alg), sqlc.arg(public_jwk),
        sqlc.arg(created_by), now() + make_interval(days => sqlc.arg(ttl_days)::int))
RETURNING *, CASE WHEN state = 'ACTIVE' AND expires_at <= now() THEN 'EXPIRED' ELSE state END::text AS effective_state;

-- name: ListServiceAccountKeys :many
SELECT *, CASE WHEN state = 'ACTIVE' AND expires_at <= now() THEN 'EXPIRED' ELSE state END::text AS effective_state
FROM pc.service_account_keys
WHERE org_id = sqlc.arg(org_id) AND service_account_id = sqlc.arg(service_account_id)
  AND id > coalesce(sqlc.arg(after)::uuid, '00000000-0000-0000-0000-000000000000')
ORDER BY id
LIMIT sqlc.arg(page_limit);

-- name: RevokeServiceAccountKey :one
UPDATE pc.service_account_keys SET state = 'REVOKED', revoked_at = now()
WHERE org_id = sqlc.arg(org_id) AND service_account_id = sqlc.arg(service_account_id) AND id = sqlc.arg(id) AND state = 'ACTIVE'
RETURNING *, 'REVOKED'::text AS effective_state;

-- name: ServiceAccountKeyExists :one
SELECT EXISTS (SELECT 1 FROM pc.service_account_keys
               WHERE org_id = sqlc.arg(org_id) AND service_account_id = sqlc.arg(service_account_id) AND id = sqlc.arg(id));

-- name: AssertionKey :one
SELECT k.id, k.alg, k.public_jwk, k.state AS key_state, (k.expires_at > now())::bool AS live, sa.state AS account_state
FROM pc.service_account_keys k
JOIN pc.service_accounts sa ON sa.org_id = k.org_id AND sa.id = k.service_account_id
WHERE k.org_id = sqlc.arg(org_id) AND k.service_account_id = sqlc.arg(service_account_id) AND k.kid = sqlc.arg(kid);

-- name: InsertAuthReplay :execrows
INSERT INTO pc.auth_replay (org_id, issuer, jti, expires_at)
VALUES (sqlc.arg(org_id), sqlc.arg(issuer), sqlc.arg(jti), sqlc.arg(expires_at))
ON CONFLICT DO NOTHING;

-- name: InsertAPIKey :one
INSERT INTO pc.api_keys (org_id, id, service_account_id, name, secret_hash, hint, scopes, created_by, expires_at, allowed_cidrs)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(service_account_id), sqlc.arg(name), sqlc.arg(secret_hash), sqlc.arg(hint),
        sqlc.arg(scopes)::text[], sqlc.arg(created_by), now() + make_interval(days => sqlc.arg(ttl_days)::int),
        sqlc.narg(allowed_cidrs)::cidr[])
RETURNING *, CASE WHEN state = 'ACTIVE' AND expires_at <= now() THEN 'EXPIRED' ELSE state END::text AS effective_state;

-- name: ListAPIKeys :many
SELECT *, CASE WHEN state = 'ACTIVE' AND expires_at <= now() THEN 'EXPIRED' ELSE state END::text AS effective_state
FROM pc.api_keys
WHERE org_id = sqlc.arg(org_id) AND id > coalesce(sqlc.arg(after)::uuid, '00000000-0000-0000-0000-000000000000')
  AND (sqlc.narg(service_account_id)::uuid IS NULL OR service_account_id = sqlc.narg(service_account_id))
ORDER BY id
LIMIT sqlc.arg(page_limit);

-- name: RevokeAPIKey :one
UPDATE pc.api_keys SET state = 'REVOKED', revoked_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'ACTIVE'
RETURNING *, 'REVOKED'::text AS effective_state;

-- name: APIKeyExists :one
SELECT EXISTS (SELECT 1 FROM pc.api_keys WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id));
