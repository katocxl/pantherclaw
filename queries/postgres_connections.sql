-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

-- name: UpsertPostgresConnection :exec
INSERT INTO pc.postgres_connections (org_id, connection_id, config, digest)
VALUES (@org_id, @connection_id, @config, @digest)
ON CONFLICT (org_id, connection_id) DO UPDATE SET config = EXCLUDED.config, digest = EXCLUDED.digest, updated_at = now();

-- name: GetPostgresConnection :one
SELECT config, digest FROM pc.postgres_connections WHERE org_id = @org_id AND connection_id = @connection_id;
