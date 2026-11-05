-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Browser site queries (G0 M33 D976). Every query runs inside
-- db.InTenantTx and also filters by org_id explicitly.

-- name: ListBrowserSites :many
SELECT * FROM pc.browser_sites
WHERE org_id = sqlc.arg(org_id)
ORDER BY host, include_subdomains;

-- name: GetBrowserSiteByHost :one
SELECT * FROM pc.browser_sites
WHERE org_id = sqlc.arg(org_id) AND host = sqlc.arg(host) AND include_subdomains = sqlc.arg(include_subdomains);

-- name: CountBrowserSites :one
SELECT count(*) FROM pc.browser_sites
WHERE org_id = sqlc.arg(org_id);

-- name: ListBrowserCompareSites :many
-- The sites marked for the gateway's cloaking compare (D986).
SELECT host, include_subdomains FROM pc.browser_sites
WHERE org_id = sqlc.arg(org_id) AND compare
ORDER BY host, include_subdomains;

-- name: InsertBrowserSite :one
INSERT INTO pc.browser_sites (id, org_id, host, include_subdomains, compare, click_selectors, note, created_by)
VALUES (sqlc.arg(id), sqlc.arg(org_id), sqlc.arg(host), sqlc.arg(include_subdomains), sqlc.arg(compare),
        sqlc.arg(click_selectors)::text[], sqlc.arg(note), sqlc.arg(created_by))
RETURNING *;

-- name: DeleteBrowserSite :one
DELETE FROM pc.browser_sites
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id)
RETURNING *;
