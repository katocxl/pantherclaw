-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

-- A snowflake connection's endpoint and first manifest, which waits for
-- confirmation (G0 M31 D962, as D84).
-- name: ProposeSnowflakeConnection :exec
INSERT INTO pc.snowflake_connections (org_id, connection_id, account, warehouse, database_name, schema_name,
    proposed, proposed_digest, proposed_at)
VALUES (@org_id, @connection_id, @account, @warehouse, @database_name, @schema_name, @proposed, @proposed_digest, now());

-- name: LockSnowflakeConnection :one
SELECT account, warehouse, database_name, schema_name, config, digest, proposed, proposed_digest
FROM pc.snowflake_connections
WHERE org_id = @org_id AND connection_id = @connection_id
FOR UPDATE;

-- name: GetSnowflakeConnection :one
SELECT account, warehouse, database_name, schema_name, config, digest, proposed, proposed_digest, proposed_at,
    confirmed_by, confirmed_at
FROM pc.snowflake_connections WHERE org_id = @org_id AND connection_id = @connection_id;

-- A narrowing change applies at once and voids a pending proposal.
-- name: ApplySnowflakeConnection :exec
UPDATE pc.snowflake_connections
SET config = @config, digest = @digest, proposed = NULL, proposed_digest = NULL, proposed_at = NULL, updated_at = now()
WHERE org_id = @org_id AND connection_id = @connection_id;

-- A widening change is proposed; the current manifest keeps serving.
-- name: ProposeSnowflakeChange :exec
UPDATE pc.snowflake_connections
SET proposed = @proposed, proposed_digest = @proposed_digest, proposed_at = now(), updated_at = now()
WHERE org_id = @org_id AND connection_id = @connection_id;

-- name: ConfirmSnowflakeConnection :execrows
UPDATE pc.snowflake_connections
SET config = proposed, digest = proposed_digest, proposed = NULL, proposed_digest = NULL, proposed_at = NULL,
    confirmed_by = @confirmed_by, confirmed_credential = @confirmed_credential, confirmed_at = now(), updated_at = now()
WHERE org_id = @org_id AND connection_id = @connection_id AND proposed_digest = @proposed_digest;
