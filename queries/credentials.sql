-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Sealed credentials (G0 M6 design decision 8, HR-060, HR-061, HR-182).
-- The server stores only sealed bytes. No query here returns them; only
-- the gateway configuration (slice 12) does, to the gateway that owns the
-- broker key.

-- name: NextCredentialVersion :one
SELECT (coalesce(max(version), 0) + 1)::integer FROM pc.credentials
WHERE org_id = sqlc.arg(org_id) AND connection_id = sqlc.arg(connection_id);

-- name: SupersedeCredentials :execrows
UPDATE pc.credentials SET state = 'SUPERSEDED', superseded_at = now()
WHERE org_id = sqlc.arg(org_id) AND connection_id = sqlc.arg(connection_id) AND state = 'ACTIVE';

-- name: InsertSealedCredential :one
INSERT INTO pc.credentials (org_id, id, connection_id, version, broker_key_id, sealed, allowed_hosts, header, scheme, created_by, kind)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(connection_id), sqlc.arg(version), sqlc.arg(broker_key_id), sqlc.arg(sealed),
        sqlc.arg(allowed_hosts)::text[], sqlc.arg(header), sqlc.narg(scheme), sqlc.arg(created_by), sqlc.arg(kind))
RETURNING id, version, state, created_at;

-- name: ListCredentialMetadata :many
SELECT c.id, c.connection_id, c.version, c.broker_key_id, b.fingerprint AS broker_key_fingerprint, c.allowed_hosts, c.header,
       c.scheme, c.state, c.created_by, c.created_at, c.kind
FROM pc.credentials c
JOIN pc.broker_keys b ON b.org_id = c.org_id AND b.id = c.broker_key_id
WHERE c.org_id = sqlc.arg(org_id) AND c.connection_id = sqlc.arg(connection_id)
ORDER BY c.version DESC
LIMIT 50;

-- name: RevokeCredentialVersion :execrows
UPDATE pc.credentials SET state = 'REVOKED', revoked_by = sqlc.arg(revoked_by), revoked_at = now()
WHERE org_id = sqlc.arg(org_id) AND connection_id = sqlc.arg(connection_id) AND version = sqlc.arg(version)
  AND state <> 'REVOKED';

-- UpsertConnectionGitHub records the GitHub App installation a sealed
-- github_app credential is for (connection_github; G0 M8, ADR-0021). What
-- was read from an installation is kept only while it stays the same one.
-- name: UpsertConnectionGitHub :exec
INSERT INTO pc.connection_github AS g (org_id, connection_id, app_client_id, installation_id, account_login, updated_by)
VALUES (sqlc.arg(org_id), sqlc.arg(connection_id), sqlc.arg(app_client_id), sqlc.arg(installation_id), sqlc.arg(account_login),
        sqlc.arg(updated_by))
ON CONFLICT (org_id, connection_id) DO UPDATE SET
    app_client_id = EXCLUDED.app_client_id, installation_id = EXCLUDED.installation_id, account_login = EXCLUDED.account_login,
    account_id = CASE WHEN g.installation_id = EXCLUDED.installation_id THEN g.account_id END,
    permissions = CASE WHEN g.installation_id = EXCLUDED.installation_id THEN g.permissions ELSE '{}'::jsonb END,
    repository_selection = CASE WHEN g.installation_id = EXCLUDED.installation_id THEN g.repository_selection END,
    read_at = CASE WHEN g.installation_id = EXCLUDED.installation_id THEN g.read_at END,
    updated_by = EXCLUDED.updated_by, updated_at = now();
