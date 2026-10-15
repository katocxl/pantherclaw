-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Readers of the publish gate's validator (G0 M11.1 design decision 8):
-- who could answer a rule's holds, and which facts something supplies.

-- PolicyRoleHolders counts the active persons holding a role at the org
-- path (APPROVER_NONE).
-- name: PolicyRoleHolders :one
SELECT count(DISTINCT u.id)::integer AS n
FROM pc.role_bindings b
JOIN pc.users u ON u.org_id = b.org_id AND u.id = b.user_id
WHERE b.org_id = sqlc.arg(org_id) AND b.role = sqlc.arg(role) AND b.scope_type = 'ORG' AND u.state = 'ACTIVE';

-- PolicySuppliedFacts lists the facts an active provider declares, for a
-- connection only while that connection is active (FACT_NO_SOURCE).
-- name: PolicySuppliedFacts :many
SELECT DISTINCT d.name
FROM pc.fact_declarations d
JOIN pc.fact_providers p ON p.org_id = d.org_id AND p.id = d.provider_id
LEFT JOIN pc.connections c ON c.org_id = d.org_id AND c.id = d.connection_id
WHERE d.org_id = sqlc.arg(org_id) AND d.active AND p.state = 'ACTIVE'
  AND (d.connection_id IS NULL OR c.state = 'ACTIVE')
ORDER BY d.name;
