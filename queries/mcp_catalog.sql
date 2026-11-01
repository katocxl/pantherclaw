-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- The org's MCP server catalogue (G0 M24 D220-D226).

-- name: InsertMcpServer :one
INSERT INTO pc.mcp_servers (org_id, id, name, title, transport, package_ref, url_host, url_path_prefix, image_digest, notes)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(name), sqlc.arg(title), sqlc.arg(transport), sqlc.narg(package_ref),
    sqlc.narg(url_host), sqlc.narg(url_path_prefix), sqlc.narg(image_digest), sqlc.arg(notes))
RETURNING *;

-- name: GetMcpServer :one
SELECT * FROM pc.mcp_servers WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: LockMcpServer :one
SELECT * FROM pc.mcp_servers WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) FOR UPDATE;

-- name: ListMcpServers :many
SELECT * FROM pc.mcp_servers
WHERE org_id = sqlc.arg(org_id)
  AND (cardinality(sqlc.arg(statuses)::text[]) = 0 OR status = ANY (sqlc.arg(statuses)::text[]))
  AND id > coalesce(sqlc.arg(after_id)::uuid, '00000000-0000-0000-0000-000000000000')
ORDER BY id
LIMIT sqlc.arg(max_rows);

-- McpServersIn reads every server of some statuses, for matching.
-- name: McpServersIn :many
SELECT * FROM pc.mcp_servers WHERE org_id = sqlc.arg(org_id) AND status = ANY (sqlc.arg(statuses)::text[]) ORDER BY id;

-- DecideMcpServer moves a server, conditional on its status (HR-004).
-- name: DecideMcpServer :one
UPDATE pc.mcp_servers SET status = sqlc.arg(to_status), decided_by = sqlc.arg(decided_by), decided_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND status = sqlc.arg(from_status)
RETURNING *;

-- EnsureMcpCatalogSettings creates the org's row at the default mode.
-- name: EnsureMcpCatalogSettings :exec
INSERT INTO pc.mcp_catalog_settings (org_id) VALUES (sqlc.arg(org_id)) ON CONFLICT (org_id) DO NOTHING;

-- GetMcpCatalogSettings reads the org's row.
-- name: GetMcpCatalogSettings :one
SELECT * FROM pc.mcp_catalog_settings WHERE org_id = sqlc.arg(org_id);

-- ShareMcpCatalogMode reads the mode and keeps it from changing until the
-- transaction ends: a connection write and a switch to ENFORCE take turns.
-- name: ShareMcpCatalogMode :one
SELECT mode FROM pc.mcp_catalog_settings WHERE org_id = sqlc.arg(org_id) FOR SHARE;

-- LockMcpCatalogSettings takes the row a mode change writes.
-- name: LockMcpCatalogSettings :one
SELECT * FROM pc.mcp_catalog_settings WHERE org_id = sqlc.arg(org_id) FOR UPDATE;

-- name: SetMcpCatalogMode :one
UPDATE pc.mcp_catalog_settings SET mode = sqlc.arg(mode), updated_by = sqlc.arg(updated_by), updated_at = now()
WHERE org_id = sqlc.arg(org_id)
RETURNING *;

-- McpConnections reads the org's connections that reach an MCP server, with
-- a connector's current image.
-- name: McpConnections :many
SELECT c.id, c.name, c.kind, c.state, c.gateway_id, c.package, c.base_url, c.created_at,
    coalesce((SELECT s.image FROM pc.connector_specs s WHERE s.org_id = c.org_id AND s.connection_id = c.id
              ORDER BY s.revision DESC LIMIT 1), '')::text AS image
FROM pc.connections c
WHERE c.org_id = sqlc.arg(org_id) AND c.kind IN ('mcp', 'mcp_container') AND c.state <> 'RETIRED'
ORDER BY c.id;

-- McpPackageVersions reads the versions of a tool package a revoke quarantines:
-- all that are or could be activated (G0 M24 D267).
-- name: McpPackageVersions :many
SELECT t.name AS package, v.version, v.state
FROM pc.package_versions v
JOIN pc.tool_packages t ON t.org_id = v.org_id AND t.id = v.package_id
WHERE v.org_id = sqlc.arg(org_id) AND t.name = sqlc.arg(name) AND v.state IN ('ACTIVE', 'STALE', 'REVIEWED')
ORDER BY v.version;

-- McpRevocationLive reports whether a control of a server's revocation is
-- still live.
-- name: McpRevocationLive :one
SELECT EXISTS (
    SELECT 1 FROM pc.response_actions a
    JOIN pc.containment_controls c ON c.org_id = a.org_id AND c.action_id = a.id
    WHERE a.org_id = sqlc.arg(org_id) AND a.scope_type = 'mcp_server' AND a.scope_id = sqlc.arg(server)::text
      AND c.lifted_at IS NULL)::boolean AS live;

-- McpScanServers reads the open local MCP servers scans found. The attributes
-- are UNTRUSTED observations, and a name is shown as plain text.
-- name: McpScanServers :many
SELECT id, agent_id, first_seen_at, left(coalesce(observed->>'name', ''), 200)::text AS name,
    coalesce(observed->>'url_host', '')::text AS url_host, coalesce(observed->>'package_ref', '')::text AS package_ref
FROM pc.discoveries
WHERE org_id = sqlc.arg(org_id) AND state = 'OPEN' AND observed->>'kind' = 'mcp_server'
ORDER BY id;

-- McpPackageRevoked reports whether a REVOKED server names a tool package.
-- name: McpPackageRevoked :one
SELECT EXISTS (
    SELECT 1 FROM pc.mcp_servers s
    WHERE s.org_id = sqlc.arg(org_id) AND s.status = 'REVOKED' AND s.package_ref = sqlc.arg(name)::text)::boolean AS revoked;
