-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

-- Quick find's first pass (G0 M11 part 2 D45, D79 S3, D86 Q4): names that
-- start with the text, as a byte range name_lo..name_hi on lower(name).
-- Each is its own query, with no id or substring arm, so the range is
-- served by the lower(name) text_pattern_ops indexes of migration 00147
-- even under a generic plan. Rows outside the viewer's scope are filtered
-- before the limit and the count, as in search_find.sql.

-- name: FindAgentsByPrefix :many
SELECT a.id, a.name::text AS label, a.state AS state, a.created_at AS at, count(*) OVER () AS total
FROM pc.agents a
WHERE a.org_id = sqlc.arg(org_id)
  AND (sqlc.arg(all_agents)::boolean OR a.id = ANY (sqlc.arg(agents)::uuid[]))
  AND lower(a.name) ~>=~ sqlc.arg(name_lo)::text AND lower(a.name) ~<=~ sqlc.arg(name_hi)::text
ORDER BY lower(a.name) = sqlc.arg(name_lo)::text DESC, a.name, a.id
LIMIT sqlc.arg(page_limit);

-- name: FindConnectionsByPrefix :many
SELECT c.id, c.name::text AS label, c.state AS state, c.created_at AS at, count(*) OVER () AS total
FROM pc.connections c
WHERE c.org_id = sqlc.arg(org_id)
  AND lower(c.name) ~>=~ sqlc.arg(name_lo)::text AND lower(c.name) ~<=~ sqlc.arg(name_hi)::text
ORDER BY lower(c.name) = sqlc.arg(name_lo)::text DESC, c.name, c.id
LIMIT sqlc.arg(page_limit);

-- name: FindCasesByPrefix :many
SELECT c.id, c.title::text AS label, c.state AS state, c.created_at AS at, count(*) OVER () AS total
FROM pc.cases c
WHERE c.org_id = sqlc.arg(org_id)
  AND (sqlc.arg(all_agents)::boolean OR pc.case_within(c.org_id, c.id, sqlc.arg(agents)::uuid[]))
  AND lower(c.title) ~>=~ sqlc.arg(name_lo)::text AND lower(c.title) ~<=~ sqlc.arg(name_hi)::text
ORDER BY lower(c.title) = sqlc.arg(name_lo)::text DESC, c.title, c.id
LIMIT sqlc.arg(page_limit);

-- name: FindIncidentsByPrefix :many
SELECT i.id, i.title::text AS label, i.state AS state, i.created_at AS at, count(*) OVER () AS total
FROM pc.incidents i
WHERE i.org_id = sqlc.arg(org_id)
  AND (sqlc.arg(all_agents)::boolean
       OR (EXISTS (SELECT 1 FROM pc.alerts a, jsonb_array_elements(a.subjects) s
                   WHERE a.org_id = i.org_id AND a.incident_id = i.id AND s ->> 'type' = 'agent')
           AND NOT EXISTS (SELECT 1 FROM pc.alerts a, jsonb_array_elements(a.subjects) s
                           WHERE a.org_id = i.org_id AND a.incident_id = i.id AND s ->> 'type' = 'agent'
                             AND NOT (s ->> 'id') = ANY (sqlc.arg(agents)::uuid[]::text[]))))
  AND lower(i.title) ~>=~ sqlc.arg(name_lo)::text AND lower(i.title) ~<=~ sqlc.arg(name_hi)::text
ORDER BY lower(i.title) = sqlc.arg(name_lo)::text DESC, i.title, i.id
LIMIT sqlc.arg(page_limit);

-- name: FindAlertsByPrefix :many
SELECT a.id, a.title::text AS label, a.state AS state, a.created_at AS at, count(*) OVER () AS total
FROM pc.alerts a
WHERE a.org_id = sqlc.arg(org_id)
  AND (sqlc.arg(all_agents)::boolean
       OR (EXISTS (SELECT 1 FROM jsonb_array_elements(a.subjects) s WHERE s ->> 'type' = 'agent')
           AND NOT EXISTS (SELECT 1 FROM jsonb_array_elements(a.subjects) s
                           WHERE s ->> 'type' = 'agent' AND NOT (s ->> 'id') = ANY (sqlc.arg(agents)::uuid[]::text[]))))
  AND lower(a.title) ~>=~ sqlc.arg(name_lo)::text AND lower(a.title) ~<=~ sqlc.arg(name_hi)::text
ORDER BY lower(a.title) = sqlc.arg(name_lo)::text DESC, a.title, a.id
LIMIT sqlc.arg(page_limit);

-- name: FindPackagesByPrefix :many
SELECT k.id, k.name::text AS label, ''::text AS state, k.created_at AS at, count(*) OVER () AS total
FROM pc.tool_packages k
WHERE k.org_id = sqlc.arg(org_id)
  AND lower(k.name) ~>=~ sqlc.arg(name_lo)::text AND lower(k.name) ~<=~ sqlc.arg(name_hi)::text
ORDER BY lower(k.name) = sqlc.arg(name_lo)::text DESC, k.name, k.id
LIMIT sqlc.arg(page_limit);

-- name: FindGatewaysByPrefix :many
SELECT g.id, g.name::text AS label, g.state AS state, g.created_at AS at, count(*) OVER () AS total
FROM pc.gateways g
WHERE g.org_id = sqlc.arg(org_id)
  AND lower(g.name) ~>=~ sqlc.arg(name_lo)::text AND lower(g.name) ~<=~ sqlc.arg(name_hi)::text
ORDER BY lower(g.name) = sqlc.arg(name_lo)::text DESC, g.name, g.id
LIMIT sqlc.arg(page_limit);

-- name: FindServiceAccountsByPrefix :many
SELECT s.id, s.name::text AS label, s.state AS state, s.created_at AS at, count(*) OVER () AS total
FROM pc.service_accounts s
WHERE s.org_id = sqlc.arg(org_id)
  AND lower(s.name) ~>=~ sqlc.arg(name_lo)::text AND lower(s.name) ~<=~ sqlc.arg(name_hi)::text
ORDER BY lower(s.name) = sqlc.arg(name_lo)::text DESC, s.name, s.id
LIMIT sqlc.arg(page_limit);

-- name: FindAutomationsByPrefix :many
SELECT a.id, a.name::text AS label, a.state AS state, a.created_at AS at, count(*) OVER () AS total
FROM pc.automations a
WHERE a.org_id = sqlc.arg(org_id)
  AND lower(a.name) ~>=~ sqlc.arg(name_lo)::text AND lower(a.name) ~<=~ sqlc.arg(name_hi)::text
ORDER BY lower(a.name) = sqlc.arg(name_lo)::text DESC, a.name, a.id
LIMIT sqlc.arg(page_limit);

-- A person matches by display name or email (two index ranges).
-- name: FindPeopleByPrefix :many
SELECT u.id, (CASE WHEN u.display_name <> '' THEN u.display_name ELSE u.email END)::text AS label, u.state,
       u.created_at AS at, count(*) OVER () AS total
FROM pc.users u
WHERE u.org_id = sqlc.arg(org_id)
  AND ((lower(u.display_name) ~>=~ sqlc.arg(name_lo)::text AND lower(u.display_name) ~<=~ sqlc.arg(name_hi)::text)
       OR (lower(u.email) ~>=~ sqlc.arg(name_lo)::text AND lower(u.email) ~<=~ sqlc.arg(name_hi)::text))
ORDER BY (lower(u.display_name) = sqlc.arg(name_lo)::text OR lower(u.email) = sqlc.arg(name_lo)::text) DESC,
         u.display_name, u.email, u.id
LIMIT sqlc.arg(page_limit);
