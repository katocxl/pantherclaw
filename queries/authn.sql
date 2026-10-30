-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Per-request authentication checks (ADR-0016). They run in a tenant
-- transaction for the org named by the credential, so a credential routed
-- to the wrong org simply matches nothing. Expiry uses the database clock.

-- name: OrgState :one
SELECT state FROM pc.orgs WHERE id = sqlc.arg(org_id);

-- name: AuthAPIKey :one
SELECT k.id, k.service_account_id, k.scopes, k.allowed_cidrs, k.state AS key_state, (k.expires_at > now())::bool AS live,
       (k.last_used_at IS NULL OR k.last_used_at < now() - interval '1 minute')::bool AS touch,
       sa.state AS account_state
FROM pc.api_keys k
JOIN pc.service_accounts sa ON sa.org_id = k.org_id AND sa.id = k.service_account_id
WHERE k.org_id = sqlc.arg(org_id) AND k.secret_hash = sqlc.arg(secret_hash);

-- name: TouchAPIKey :exec
UPDATE pc.api_keys SET last_used_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id)
  AND (last_used_at IS NULL OR last_used_at < now() - interval '1 minute');

-- name: AuthUserSession :one
SELECT u.state AS user_state, s.state AS session_state, (s.expires_at > now())::bool AS live
FROM pc.users u
JOIN pc.cli_sessions s ON s.org_id = u.org_id AND s.user_id = u.id
WHERE u.org_id = sqlc.arg(org_id) AND u.id = sqlc.arg(user_id) AND s.id = sqlc.arg(session_id) AND pc.identity_available(u.issuer,u.subject,false);

-- name: AuthServiceAccountKey :one
SELECT sa.state AS account_state, k.state AS key_state, (k.expires_at > now())::bool AS live
FROM pc.service_accounts sa
JOIN pc.service_account_keys k ON k.org_id = sa.org_id AND k.service_account_id = sa.id
WHERE sa.org_id = sqlc.arg(org_id) AND sa.id = sqlc.arg(service_account_id) AND k.id = sqlc.arg(key_id);
