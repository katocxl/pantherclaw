-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

-- A new connection's first configuration waits for confirmation (D84).
-- name: ProposePostgresConnection :exec
INSERT INTO pc.postgres_connections (org_id, connection_id, proposed, proposed_digest, proposed_at)
VALUES (@org_id, @connection_id, @proposed, @proposed_digest, now());

-- name: LockPostgresConnection :one
SELECT config, digest, proposed, proposed_digest FROM pc.postgres_connections
WHERE org_id = @org_id AND connection_id = @connection_id
FOR UPDATE;

-- name: GetPostgresConnection :one
SELECT config, digest, proposed, proposed_digest, proposed_at, confirmed_by, confirmed_at
FROM pc.postgres_connections WHERE org_id = @org_id AND connection_id = @connection_id;

-- A narrowing change applies at once and voids a pending proposal.
-- name: ApplyPostgresConnection :exec
UPDATE pc.postgres_connections
SET config = @config, digest = @digest, proposed = NULL, proposed_digest = NULL, proposed_at = NULL, updated_at = now()
WHERE org_id = @org_id AND connection_id = @connection_id;

-- A widening change is proposed; the current configuration keeps serving.
-- name: ProposePostgresChange :exec
UPDATE pc.postgres_connections
SET proposed = @proposed, proposed_digest = @proposed_digest, proposed_at = now(), updated_at = now()
WHERE org_id = @org_id AND connection_id = @connection_id;

-- name: ConfirmPostgresConnection :execrows
UPDATE pc.postgres_connections
SET config = proposed, digest = proposed_digest, proposed = NULL, proposed_digest = NULL, proposed_at = NULL,
    confirmed_by = @confirmed_by, confirmed_credential = @confirmed_credential, confirmed_at = now(), updated_at = now()
WHERE org_id = @org_id AND connection_id = @connection_id AND proposed_digest = @proposed_digest;
