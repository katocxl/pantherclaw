-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Connections and their route modes (G0 M6, HR-183, HR-184). A connection
-- is one target served by one gateway through one tool package; each route
-- of the package has a mode on it. Every change bumps the revision, and
-- the gateway's configuration version so it refetches (decision 19).

-- name: InsertConnection :one
INSERT INTO pc.connections (org_id, id, name, kind, gateway_id, package, base_url, allowed_hosts, destination_class,
                            access_mode, credential_header, credential_scheme, default_mode, max_response_bytes,
                            timeout_ms, created_by, updated_by)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(name), sqlc.arg(kind), sqlc.arg(gateway_id), sqlc.arg(package),
        sqlc.narg(base_url), sqlc.arg(allowed_hosts)::text[], sqlc.arg(destination_class), sqlc.arg(access_mode),
        sqlc.narg(credential_header), sqlc.narg(credential_scheme), sqlc.arg(default_mode),
        sqlc.arg(max_response_bytes), sqlc.arg(timeout_ms), sqlc.arg(created_by), sqlc.arg(created_by))
RETURNING *;

-- name: GetConnection :one
SELECT * FROM pc.connections WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: LockConnection :one
SELECT * FROM pc.connections WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) FOR UPDATE;

-- name: ListConnections :many
SELECT * FROM pc.connections
WHERE org_id = sqlc.arg(org_id) AND (sqlc.arg(include_retired)::boolean OR state <> 'RETIRED')
  AND (sqlc.narg(gateway_id)::uuid IS NULL OR gateway_id = sqlc.narg(gateway_id)::uuid)
  AND id > coalesce(sqlc.arg(after_id)::uuid, '00000000-0000-0000-0000-000000000000')
ORDER BY id
LIMIT sqlc.arg(max_rows);

-- UpdateConnection writes every mutable field; the caller passes the
-- current values for fields it does not change. The revision guards
-- against a concurrent change.
-- name: UpdateConnection :one
UPDATE pc.connections
SET gateway_id = sqlc.arg(gateway_id), base_url = sqlc.narg(base_url), allowed_hosts = sqlc.arg(allowed_hosts)::text[],
    destination_class = sqlc.arg(destination_class), access_mode = sqlc.arg(access_mode),
    default_mode = sqlc.arg(default_mode), max_response_bytes = sqlc.arg(max_response_bytes),
    timeout_ms = sqlc.arg(timeout_ms), state = sqlc.arg(state), quarantine_reason = sqlc.narg(quarantine_reason),
    revision = revision + 1, updated_by = sqlc.arg(updated_by), updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND revision = sqlc.arg(revision)
RETURNING *;

-- name: InsertConnectionRoute :exec
INSERT INTO pc.connection_routes (org_id, connection_id, route, mode, changed_by)
VALUES (sqlc.arg(org_id), sqlc.arg(connection_id), sqlc.arg(route), sqlc.arg(mode), sqlc.arg(changed_by))
ON CONFLICT (org_id, connection_id, route) DO NOTHING;

-- name: ListConnectionRoutes :many
SELECT * FROM pc.connection_routes
WHERE org_id = sqlc.arg(org_id) AND connection_id = sqlc.arg(connection_id)
ORDER BY route;

-- name: SetConnectionRouteMode :one
UPDATE pc.connection_routes
SET mode = sqlc.arg(mode), changed_by = sqlc.arg(changed_by), changed_at = now()
WHERE org_id = sqlc.arg(org_id) AND connection_id = sqlc.arg(connection_id) AND route = sqlc.arg(route)
RETURNING *;

-- name: TouchConnection :exec
UPDATE pc.connections SET revision = revision + 1, updated_by = sqlc.arg(updated_by), updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: RevokeConnectionCredentials :execrows
UPDATE pc.credentials SET state = 'REVOKED', revoked_by = sqlc.arg(revoked_by), revoked_at = now()
WHERE org_id = sqlc.arg(org_id) AND connection_id = sqlc.arg(connection_id) AND state = 'ACTIVE';

-- PinnedPackageRaw returns the org's pinned version of a package and its
-- file, from which a connection takes its routes.
-- name: PinnedPackageRaw :one
SELECT p.version, v.state, v.raw
FROM pc.package_pins p
JOIN pc.tool_packages t ON t.org_id = p.org_id AND t.id = p.package_id
JOIN pc.package_versions v ON v.org_id = p.org_id AND v.id = p.version_id
WHERE p.org_id = sqlc.arg(org_id) AND t.name = sqlc.arg(name);

-- name: OpenCircuit :exec
-- A gateway reported its breaker for a connection open (HR-078).
INSERT INTO pc.circuit_states (org_id, connection_id, gateway_id, state, unknown_count, total_count, opened_at, closed_at, reported_at)
VALUES (sqlc.arg(org_id), sqlc.arg(connection_id), sqlc.arg(gateway_id), 'OPEN', sqlc.arg(unknown_count), sqlc.arg(total_count), now(), NULL, now())
ON CONFLICT (org_id, connection_id, gateway_id) DO UPDATE
SET state = 'OPEN', unknown_count = EXCLUDED.unknown_count, total_count = EXCLUDED.total_count,
    opened_at = CASE WHEN pc.circuit_states.state = 'OPEN' THEN pc.circuit_states.opened_at ELSE now() END,
    closed_at = NULL, reported_at = now();

-- name: CloseCircuits :execrows
-- Restoring a connection closes its open circuits.
UPDATE pc.circuit_states SET state = 'CLOSED', closed_at = now()
WHERE org_id = sqlc.arg(org_id) AND connection_id = sqlc.arg(connection_id) AND state = 'OPEN';

-- name: ListConnectionGitHub :many
-- The GitHub App installations behind connections (connection_github).
SELECT * FROM pc.connection_github
WHERE org_id = sqlc.arg(org_id) AND connection_id = ANY(sqlc.arg(connection_ids)::uuid[]);
