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
