-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Supply-chain flags (G0 M24 D211, D212). Flags are written only by the checks
-- and move only OPEN to CLEARED when what they are on leaves review; nothing
-- here touches the inventory item or its review (HR-582).

-- name: UpsertInventoryFlag :exec
INSERT INTO pc.supplychain_flags (org_id, id, connection_id, inventory_id, tool, digest, check_kind, severity, detail)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(connection_id), sqlc.arg(inventory_id), sqlc.arg(tool), sqlc.arg(digest),
        sqlc.arg(check_kind), sqlc.arg(severity), sqlc.arg(detail))
ON CONFLICT (org_id, inventory_id, check_kind) WHERE inventory_id IS NOT NULL
DO UPDATE SET severity = excluded.severity, detail = excluded.detail, state = 'OPEN', last_seen = now();

-- name: InsertPackageFlag :exec
INSERT INTO pc.supplychain_flags (org_id, id, package_version_id, tool, digest, check_kind, severity, detail)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(package_version_id), sqlc.arg(tool), sqlc.arg(digest), sqlc.arg(check_kind),
        sqlc.arg(severity), sqlc.arg(detail))
ON CONFLICT (org_id, package_version_id, tool, check_kind) WHERE package_version_id IS NOT NULL DO NOTHING;

-- name: ClearInventoryFlags :exec
UPDATE pc.supplychain_flags SET state = 'CLEARED', last_seen = now()
WHERE org_id = sqlc.arg(org_id) AND inventory_id = sqlc.arg(inventory_id) AND state = 'OPEN';

-- name: ClearPackageFlags :exec
UPDATE pc.supplychain_flags SET state = 'CLEARED', last_seen = now()
WHERE org_id = sqlc.arg(org_id) AND package_version_id = sqlc.arg(package_version_id) AND state = 'OPEN';

-- TouchInventoryFlags marks the open flags of items a report listed again.
-- name: TouchInventoryFlags :exec
UPDATE pc.supplychain_flags SET last_seen = now()
WHERE org_id = sqlc.arg(org_id) AND inventory_id = ANY (sqlc.arg(items)::uuid[]) AND state = 'OPEN';

-- ListOpenSupplyChainFlags reads the queue's open flags, worst first, so a
-- capped read keeps those.
-- name: ListOpenSupplyChainFlags :many
SELECT * FROM pc.supplychain_flags
WHERE org_id = sqlc.arg(org_id) AND state = 'OPEN'
  AND ((sqlc.arg(connections)::boolean AND inventory_id IS NOT NULL) OR (sqlc.arg(packages)::boolean AND package_version_id IS NOT NULL))
  AND (sqlc.narg(connection_id)::uuid IS NULL OR connection_id = sqlc.narg(connection_id)::uuid)
ORDER BY CASE severity WHEN 'HIGH' THEN 0 WHEN 'MEDIUM' THEN 1 ELSE 2 END, id
LIMIT sqlc.arg(max_rows);

-- name: ListSupplyChainFlags :many
SELECT * FROM pc.supplychain_flags
WHERE org_id = sqlc.arg(org_id)
  AND (sqlc.narg(connection_id)::uuid IS NULL OR connection_id = sqlc.narg(connection_id)::uuid)
  AND (sqlc.narg(inventory_id)::uuid IS NULL OR inventory_id = sqlc.narg(inventory_id)::uuid)
  AND (sqlc.narg(package_version_id)::uuid IS NULL OR package_version_id = sqlc.narg(package_version_id)::uuid)
  AND (sqlc.arg(packages)::boolean OR package_version_id IS NULL)
  AND (cardinality(sqlc.arg(states)::text[]) = 0 OR state = ANY (sqlc.arg(states)::text[]))
  AND id > coalesce(sqlc.arg(after_id)::uuid, '00000000-0000-0000-0000-000000000000')
ORDER BY id
LIMIT sqlc.arg(max_rows);

-- ApprovedToolDigests lists the digests a tool name is approved under on the
-- org's other connections.
-- name: ApprovedToolDigests :many
SELECT DISTINCT digest FROM pc.connection_inventory
WHERE org_id = sqlc.arg(org_id) AND kind = 'TOOL' AND state = 'COVERED' AND name = sqlc.arg(name)
  AND connection_id <> sqlc.arg(connection_id);

-- ApprovedToolsOutside lists tools approved on connections that do not use
-- the package being imported.
-- name: ApprovedToolsOutside :many
SELECT DISTINCT i.name, i.digest FROM pc.connection_inventory i
JOIN pc.connections c ON c.org_id = i.org_id AND c.id = i.connection_id
WHERE i.org_id = sqlc.arg(org_id) AND i.kind = 'TOOL' AND i.state = 'COVERED' AND i.name = ANY (sqlc.arg(names)::text[])
  AND c.package <> sqlc.arg(package);
