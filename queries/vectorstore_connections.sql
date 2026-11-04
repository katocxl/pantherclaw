-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

-- A vectorstore connection's settings (G0 M30 D922-D925a), written in the
-- transaction that creates or changes the connection. A change never
-- touches the endpoint: the service refuses one first, and pc_app may not
-- update those columns.
-- name: PutVectorstoreConnection :exec
INSERT INTO pc.vectorstore_connections (org_id, connection_id, host, port, database, db_user, sslmode, ca_pem, internal,
    schema_name, table_name, dimensions, distance, writer_agent_ids)
VALUES (@org_id, @connection_id, @host, @port, @database, @db_user, @sslmode, sqlc.narg('ca_pem'), @internal,
    @schema_name, @table_name, @dimensions, @distance, @writer_agent_ids)
ON CONFLICT (org_id, connection_id) DO UPDATE
SET schema_name = EXCLUDED.schema_name, table_name = EXCLUDED.table_name, dimensions = EXCLUDED.dimensions,
    distance = EXCLUDED.distance, writer_agent_ids = EXCLUDED.writer_agent_ids, updated_at = now();

-- name: GetVectorstoreConnection :one
SELECT host, port, database, db_user, sslmode, ca_pem, internal, schema_name, table_name, dimensions, distance,
    writer_agent_ids
FROM pc.vectorstore_connections WHERE org_id = @org_id AND connection_id = @connection_id;
