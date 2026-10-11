-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Connector specs (G0 M9 track C, 00093): every version of a connector
-- connection's spec, keyed by the connection revision it was set at.

-- name: InsertConnectorSpec :one
INSERT INTO pc.connector_specs (org_id, connection_id, revision, image, command, environment, credential_placeholders,
                                egress_connection_id, memory_mib, milli_cpus, pids, created_by)
VALUES (sqlc.arg(org_id), sqlc.arg(connection_id), sqlc.arg(revision), sqlc.arg(image), sqlc.arg(command)::text[],
        sqlc.arg(environment), sqlc.arg(credential_placeholders)::text[], sqlc.narg(egress_connection_id),
        sqlc.arg(memory_mib), sqlc.arg(milli_cpus), sqlc.arg(pids), sqlc.arg(created_by))
RETURNING *;

-- The connection's current spec: the latest.
-- name: CurrentConnectorSpec :one
SELECT * FROM pc.connector_specs
WHERE org_id = sqlc.arg(org_id) AND connection_id = sqlc.arg(connection_id)
ORDER BY revision DESC
LIMIT 1;

-- The current spec of each connector a gateway serves.
-- name: GatewayConnectorSpecs :many
SELECT DISTINCT ON (s.connection_id) s.* FROM pc.connector_specs s
JOIN pc.connections c ON c.org_id = s.org_id AND c.id = s.connection_id
WHERE s.org_id = sqlc.arg(org_id) AND c.gateway_id = sqlc.arg(gateway_id) AND c.state <> 'RETIRED'
ORDER BY s.connection_id, s.revision DESC;
