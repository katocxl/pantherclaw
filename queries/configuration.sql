-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- What one gateway serves (G0 M6 design decision 19): its connections and
-- route modes, the pinned packages they use, and their active sealed
-- credentials. Every query is scoped to the calling gateway; sealed bytes
-- leave only here, and only to the gateway whose broker key they were
-- sealed to (HR-182).

-- name: GatewayConnections :many
SELECT * FROM pc.connections
WHERE org_id = sqlc.arg(org_id) AND gateway_id = sqlc.arg(gateway_id) AND state <> 'RETIRED'
ORDER BY name;

-- name: GatewayConnectionRoutes :many
SELECT r.connection_id, r.route, r.mode
FROM pc.connection_routes r
JOIN pc.connections c ON c.org_id = r.org_id AND c.id = r.connection_id
WHERE r.org_id = sqlc.arg(org_id) AND c.gateway_id = sqlc.arg(gateway_id) AND c.state <> 'RETIRED'
ORDER BY r.connection_id, r.route;

-- name: GatewayPackages :many
SELECT DISTINCT t.name, p.version, v.raw
FROM pc.connections c
JOIN pc.tool_packages t ON t.org_id = c.org_id AND t.name = c.package
JOIN pc.package_pins p ON p.org_id = t.org_id AND p.package_id = t.id
JOIN pc.package_versions v ON v.org_id = p.org_id AND v.id = p.version_id
WHERE c.org_id = sqlc.arg(org_id) AND c.gateway_id = sqlc.arg(gateway_id) AND c.state <> 'RETIRED'
ORDER BY t.name;

-- name: GatewaySealedCredentials :many
SELECT cr.id, cr.connection_id, cr.version, cr.broker_key_id, cr.sealed, cr.allowed_hosts, cr.header, cr.scheme, cr.kind
FROM pc.credentials cr
JOIN pc.connections c ON c.org_id = cr.org_id AND c.id = cr.connection_id
JOIN pc.broker_keys b ON b.org_id = cr.org_id AND b.id = cr.broker_key_id
WHERE cr.org_id = sqlc.arg(org_id) AND c.gateway_id = sqlc.arg(gateway_id) AND b.gateway_id = sqlc.arg(gateway_id)
  AND cr.state = 'ACTIVE' AND c.state <> 'RETIRED'
ORDER BY cr.connection_id;
