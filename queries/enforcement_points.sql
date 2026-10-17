-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- AuthZEN enforcement points (G0 M14 D26-D29; HR-317). A point is a
-- service account bound to the connections it fronts; only confirmed
-- bindings are in pc.enforcement_point_connections.

-- name: InsertEnforcementPoint :exec
INSERT INTO pc.enforcement_points (org_id, id, name, description, service_account_id, proposed_connections,
                                   rate_per_second, created_by)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(name), sqlc.arg(description), sqlc.arg(service_account_id),
        sqlc.arg(proposed_connections)::uuid[], sqlc.arg(rate_per_second), sqlc.arg(created_by));

-- name: GetEnforcementPoint :one
SELECT p.org_id, p.id, p.name, p.description, p.service_account_id, p.proposed_connections, p.rate_per_second,
       p.state, p.created_by, p.created_at, p.activated_by, p.activated_credential, p.activated_at, p.disabled_by,
       p.disabled_at, p.updated_at,
       coalesce((SELECT array_agg(b.connection_id ORDER BY b.connection_id) FROM pc.enforcement_point_connections b
                 WHERE b.org_id = p.org_id AND b.point_id = p.id), '{}')::uuid[] AS connection_ids
FROM pc.enforcement_points p
WHERE p.org_id = sqlc.arg(org_id) AND p.id = sqlc.arg(id);

-- name: LockEnforcementPoint :one
SELECT p.state, p.proposed_connections,
       coalesce((SELECT array_agg(b.connection_id ORDER BY b.connection_id) FROM pc.enforcement_point_connections b
                 WHERE b.org_id = p.org_id AND b.point_id = p.id), '{}')::uuid[] AS connection_ids
FROM pc.enforcement_points p
WHERE p.org_id = sqlc.arg(org_id) AND p.id = sqlc.arg(id)
FOR UPDATE OF p;

-- name: ListEnforcementPoints :many
SELECT p.org_id, p.id, p.name, p.description, p.service_account_id, p.proposed_connections, p.rate_per_second,
       p.state, p.created_by, p.created_at, p.activated_by, p.activated_credential, p.activated_at, p.disabled_by,
       p.disabled_at, p.updated_at,
       coalesce((SELECT array_agg(b.connection_id ORDER BY b.connection_id) FROM pc.enforcement_point_connections b
                 WHERE b.org_id = p.org_id AND b.point_id = p.id), '{}')::uuid[] AS connection_ids
FROM pc.enforcement_points p
WHERE p.org_id = sqlc.arg(org_id)
ORDER BY p.name, p.id
LIMIT 200;

-- name: CountLiveEnforcementPoints :one
SELECT count(*) FROM pc.enforcement_points WHERE org_id = sqlc.arg(org_id) AND state <> 'DISABLED';

-- name: ProposeEnforcementPointConnections :execrows
UPDATE pc.enforcement_points SET proposed_connections = sqlc.narg(proposed_connections)::uuid[]
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state <> 'DISABLED';

-- name: ActivateEnforcementPoint :execrows
-- Confirms the proposed connections: a PENDING point becomes ACTIVE with
-- this person and key as its activation; an ACTIVE one keeps its first.
UPDATE pc.enforcement_points
SET state = 'ACTIVE', proposed_connections = NULL,
    activated_by = coalesce(activated_by, sqlc.arg(activated_by)),
    activated_credential = coalesce(activated_credential, sqlc.arg(activated_credential)),
    activated_at = coalesce(activated_at, now())
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state IN ('PENDING', 'ACTIVE')
  AND proposed_connections IS NOT NULL;

-- name: DisableEnforcementPoint :execrows
UPDATE pc.enforcement_points SET state = 'DISABLED', proposed_connections = NULL, disabled_by = sqlc.arg(disabled_by),
    disabled_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state <> 'DISABLED';

-- name: UnbindEnforcementPointConnections :execrows
-- Removes every binding not in keep.
DELETE FROM pc.enforcement_point_connections
WHERE org_id = sqlc.arg(org_id) AND point_id = sqlc.arg(point_id)
  AND NOT (connection_id = ANY (sqlc.arg(keep)::uuid[]));

-- name: BindEnforcementPointConnections :exec
INSERT INTO pc.enforcement_point_connections (org_id, point_id, connection_id)
SELECT sqlc.arg(org_id), sqlc.arg(point_id), c FROM unnest(sqlc.arg(connections)::uuid[]) AS c
ON CONFLICT (org_id, point_id, connection_id) DO NOTHING;

-- name: EnforcementPointBindable :many
-- The named connections with what binding checks: a point fronts only
-- agent_held and target_enforced connections that are not retired.
SELECT c.id, c.name, c.kind, c.access_mode, c.state
FROM pc.connections c
WHERE c.org_id = sqlc.arg(org_id) AND c.id = ANY (sqlc.arg(connection_ids)::uuid[]);

-- name: EnforcementPointSubject :one
-- The service account a point names, for its checks at creation.
SELECT s.id, s.state FROM pc.service_accounts s WHERE s.org_id = sqlc.arg(org_id) AND s.id = sqlc.arg(id);

-- name: ActiveEnforcementPointOf :one
-- The ACTIVE point whose subject is this service account (D26).
SELECT p.id, p.name, p.rate_per_second
FROM pc.enforcement_points p
WHERE p.org_id = sqlc.arg(org_id) AND p.service_account_id = sqlc.arg(service_account_id) AND p.state = 'ACTIVE';

-- name: EnforcementPointConnection :one
-- A connection a point is bound to, by name, with its package's pinned
-- version (D26, D27, HR-317).
SELECT c.id, c.name, c.kind, c.access_mode, c.state, c.base_url, c.package, c.gateway_id, v.raw AS package_raw
FROM pc.enforcement_point_connections b
JOIN pc.connections c ON c.org_id = b.org_id AND c.id = b.connection_id
JOIN pc.tool_packages t ON t.org_id = c.org_id AND t.name = c.package
JOIN pc.package_pins p ON p.org_id = t.org_id AND p.package_id = t.id
JOIN pc.package_versions v ON v.org_id = p.org_id AND v.id = p.version_id
WHERE b.org_id = sqlc.arg(org_id) AND b.point_id = sqlc.arg(point_id) AND c.name = sqlc.arg(name)
  AND c.state <> 'RETIRED';

-- name: SetTransactionDecidedVia :execrows
-- Records that an enforcement point asked for the decision (D28): once,
-- and only on a transaction of the authzen channel.
UPDATE pc.transactions SET decided_via = 'authzen', enforcement_point_id = sqlc.arg(enforcement_point_id)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND channel = 'authzen'
  AND (decided_via IS NULL OR enforcement_point_id = sqlc.arg(enforcement_point_id));
