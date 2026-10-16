-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

-- Quick find (G0 M11 part 2 coordinator decision D45; F304, F320, HR-295).
-- Each query matches one kind by an id range (an exact id has id_lo =
-- id_hi; an id prefix of at least 8 hex digits spans the ids that start
-- with it) or, for kinds with names, first by a name prefix (name_lo..name_hi,
-- byte-wise, served by the lower(name) text_pattern_ops indexes of migration
-- 00147), then, only to fill the limit, by an escaped case-insensitive LIKE
-- anywhere in the name (contains is '%<escaped text>%'; '' or name_hi ''
-- leaves that match out). Rows outside
-- the viewer's scope are filtered before the limit, and total counts only
-- the rows in scope, so hidden records never show in matches or counts.
-- Every row has the same columns: id, label, state, at, total.

-- name: FindAgents :many
SELECT a.id, a.name::text AS label, a.state, a.created_at AS at, count(*) OVER () AS total
FROM pc.agents a
WHERE a.org_id = sqlc.arg(org_id)
  AND (sqlc.arg(all_agents)::boolean OR a.id = ANY (sqlc.arg(agents)::uuid[]))
  AND ((sqlc.narg(id_lo)::uuid IS NOT NULL AND a.id BETWEEN sqlc.narg(id_lo)::uuid AND sqlc.narg(id_hi)::uuid)
       OR (sqlc.arg(name_hi)::text <> '' AND lower(a.name) ~>=~ sqlc.arg(name_lo)::text AND lower(a.name) ~<=~ sqlc.arg(name_hi)::text)
       OR (sqlc.arg(contains)::text <> '' AND lower(a.name) LIKE sqlc.arg(contains)::text ESCAPE '\'))
ORDER BY lower(a.name) = sqlc.arg(lowered)::text DESC, starts_with(lower(a.name), sqlc.arg(lowered)::text) DESC, a.name, a.id
LIMIT sqlc.arg(page_limit);

-- name: FindConnections :many
SELECT c.id, c.name::text AS label, c.state, c.created_at AS at, count(*) OVER () AS total
FROM pc.connections c
WHERE c.org_id = sqlc.arg(org_id)
  AND ((sqlc.narg(id_lo)::uuid IS NOT NULL AND c.id BETWEEN sqlc.narg(id_lo)::uuid AND sqlc.narg(id_hi)::uuid)
       OR (sqlc.arg(name_hi)::text <> '' AND lower(c.name) ~>=~ sqlc.arg(name_lo)::text AND lower(c.name) ~<=~ sqlc.arg(name_hi)::text)
       OR (sqlc.arg(contains)::text <> '' AND lower(c.name) LIKE sqlc.arg(contains)::text ESCAPE '\'))
ORDER BY lower(c.name) = sqlc.arg(lowered)::text DESC, starts_with(lower(c.name), sqlc.arg(lowered)::text) DESC, c.name, c.id
LIMIT sqlc.arg(page_limit);

-- name: FindCases :many
SELECT c.id, c.title::text AS label, c.state, c.created_at AS at, count(*) OVER () AS total
FROM pc.cases c
WHERE c.org_id = sqlc.arg(org_id)
  AND (sqlc.arg(all_agents)::boolean OR pc.case_within(c.org_id, c.id, sqlc.arg(agents)::uuid[]))
  AND ((sqlc.narg(id_lo)::uuid IS NOT NULL AND c.id BETWEEN sqlc.narg(id_lo)::uuid AND sqlc.narg(id_hi)::uuid)
       OR (sqlc.arg(name_hi)::text <> '' AND lower(c.title) ~>=~ sqlc.arg(name_lo)::text AND lower(c.title) ~<=~ sqlc.arg(name_hi)::text)
       OR (sqlc.arg(contains)::text <> '' AND lower(c.title) LIKE sqlc.arg(contains)::text ESCAPE '\'))
ORDER BY lower(c.title) = sqlc.arg(lowered)::text DESC, starts_with(lower(c.title), sqlc.arg(lowered)::text) DESC, c.title, c.id
LIMIT sqlc.arg(page_limit);

-- name: FindIncidents :many
SELECT i.id, i.title::text AS label, i.state, i.created_at AS at, count(*) OVER () AS total
FROM pc.incidents i
WHERE i.org_id = sqlc.arg(org_id)
  AND (sqlc.arg(all_agents)::boolean
       OR (EXISTS (SELECT 1 FROM pc.alerts a, jsonb_array_elements(a.subjects) s
                   WHERE a.org_id = i.org_id AND a.incident_id = i.id AND s ->> 'type' = 'agent')
           AND NOT EXISTS (SELECT 1 FROM pc.alerts a, jsonb_array_elements(a.subjects) s
                           WHERE a.org_id = i.org_id AND a.incident_id = i.id AND s ->> 'type' = 'agent'
                             AND NOT (s ->> 'id') = ANY (sqlc.arg(agents)::uuid[]::text[]))))
  AND ((sqlc.narg(id_lo)::uuid IS NOT NULL AND i.id BETWEEN sqlc.narg(id_lo)::uuid AND sqlc.narg(id_hi)::uuid)
       OR (sqlc.arg(name_hi)::text <> '' AND lower(i.title) ~>=~ sqlc.arg(name_lo)::text AND lower(i.title) ~<=~ sqlc.arg(name_hi)::text)
       OR (sqlc.arg(contains)::text <> '' AND lower(i.title) LIKE sqlc.arg(contains)::text ESCAPE '\'))
ORDER BY lower(i.title) = sqlc.arg(lowered)::text DESC, starts_with(lower(i.title), sqlc.arg(lowered)::text) DESC, i.title, i.id
LIMIT sqlc.arg(page_limit);

-- name: FindAlerts :many
SELECT a.id, a.title::text AS label, a.state, a.created_at AS at, count(*) OVER () AS total
FROM pc.alerts a
WHERE a.org_id = sqlc.arg(org_id)
  AND (sqlc.arg(all_agents)::boolean
       OR (EXISTS (SELECT 1 FROM jsonb_array_elements(a.subjects) s WHERE s ->> 'type' = 'agent')
           AND NOT EXISTS (SELECT 1 FROM jsonb_array_elements(a.subjects) s
                           WHERE s ->> 'type' = 'agent' AND NOT (s ->> 'id') = ANY (sqlc.arg(agents)::uuid[]::text[]))))
  AND ((sqlc.narg(id_lo)::uuid IS NOT NULL AND a.id BETWEEN sqlc.narg(id_lo)::uuid AND sqlc.narg(id_hi)::uuid)
       OR (sqlc.arg(name_hi)::text <> '' AND lower(a.title) ~>=~ sqlc.arg(name_lo)::text AND lower(a.title) ~<=~ sqlc.arg(name_hi)::text)
       OR (sqlc.arg(contains)::text <> '' AND lower(a.title) LIKE sqlc.arg(contains)::text ESCAPE '\'))
ORDER BY lower(a.title) = sqlc.arg(lowered)::text DESC, starts_with(lower(a.title), sqlc.arg(lowered)::text) DESC, a.title, a.id
LIMIT sqlc.arg(page_limit);

-- name: FindPackages :many
SELECT k.id, k.name::text AS label, ''::text AS state, k.created_at AS at, count(*) OVER () AS total
FROM pc.tool_packages k
WHERE k.org_id = sqlc.arg(org_id)
  AND ((sqlc.narg(id_lo)::uuid IS NOT NULL AND k.id BETWEEN sqlc.narg(id_lo)::uuid AND sqlc.narg(id_hi)::uuid)
       OR (sqlc.arg(name_hi)::text <> '' AND lower(k.name) ~>=~ sqlc.arg(name_lo)::text AND lower(k.name) ~<=~ sqlc.arg(name_hi)::text)
       OR (sqlc.arg(contains)::text <> '' AND lower(k.name) LIKE sqlc.arg(contains)::text ESCAPE '\'))
ORDER BY lower(k.name) = sqlc.arg(lowered)::text DESC, starts_with(lower(k.name), sqlc.arg(lowered)::text) DESC, k.name, k.id
LIMIT sqlc.arg(page_limit);

-- name: FindGateways :many
SELECT g.id, g.name::text AS label, g.state, g.created_at AS at, count(*) OVER () AS total
FROM pc.gateways g
WHERE g.org_id = sqlc.arg(org_id)
  AND ((sqlc.narg(id_lo)::uuid IS NOT NULL AND g.id BETWEEN sqlc.narg(id_lo)::uuid AND sqlc.narg(id_hi)::uuid)
       OR (sqlc.arg(name_hi)::text <> '' AND lower(g.name) ~>=~ sqlc.arg(name_lo)::text AND lower(g.name) ~<=~ sqlc.arg(name_hi)::text)
       OR (sqlc.arg(contains)::text <> '' AND lower(g.name) LIKE sqlc.arg(contains)::text ESCAPE '\'))
ORDER BY lower(g.name) = sqlc.arg(lowered)::text DESC, starts_with(lower(g.name), sqlc.arg(lowered)::text) DESC, g.name, g.id
LIMIT sqlc.arg(page_limit);

-- name: FindServiceAccounts :many
SELECT s.id, s.name::text AS label, s.state, s.created_at AS at, count(*) OVER () AS total
FROM pc.service_accounts s
WHERE s.org_id = sqlc.arg(org_id)
  AND ((sqlc.narg(id_lo)::uuid IS NOT NULL AND s.id BETWEEN sqlc.narg(id_lo)::uuid AND sqlc.narg(id_hi)::uuid)
       OR (sqlc.arg(name_hi)::text <> '' AND lower(s.name) ~>=~ sqlc.arg(name_lo)::text AND lower(s.name) ~<=~ sqlc.arg(name_hi)::text)
       OR (sqlc.arg(contains)::text <> '' AND lower(s.name) LIKE sqlc.arg(contains)::text ESCAPE '\'))
ORDER BY lower(s.name) = sqlc.arg(lowered)::text DESC, starts_with(lower(s.name), sqlc.arg(lowered)::text) DESC, s.name, s.id
LIMIT sqlc.arg(page_limit);

-- A person matches by display name or email; the label is the display
-- name, else the email.
-- name: FindPeople :many
SELECT u.id, (CASE WHEN u.display_name <> '' THEN u.display_name ELSE u.email END)::text AS label, u.state,
       u.created_at AS at, count(*) OVER () AS total
FROM pc.users u
WHERE u.org_id = sqlc.arg(org_id)
  AND ((sqlc.narg(id_lo)::uuid IS NOT NULL AND u.id BETWEEN sqlc.narg(id_lo)::uuid AND sqlc.narg(id_hi)::uuid)
       OR (sqlc.arg(name_hi)::text <> '' AND (lower(u.display_name) ~>=~ sqlc.arg(name_lo)::text AND lower(u.display_name) ~<=~ sqlc.arg(name_hi)::text
                                       OR lower(u.email) ~>=~ sqlc.arg(name_lo)::text AND lower(u.email) ~<=~ sqlc.arg(name_hi)::text))
       OR (sqlc.arg(contains)::text <> '' AND (lower(u.display_name) LIKE sqlc.arg(contains)::text ESCAPE '\'
                                               OR lower(u.email) LIKE sqlc.arg(contains)::text ESCAPE '\')))
ORDER BY (lower(u.display_name) = sqlc.arg(lowered)::text OR lower(u.email) = sqlc.arg(lowered)::text) DESC,
         (starts_with(lower(u.display_name), sqlc.arg(lowered)::text) OR starts_with(lower(u.email), sqlc.arg(lowered)::text)) DESC,
         u.display_name, u.email, u.id
LIMIT sqlc.arg(page_limit);

-- name: FindRuns :many
SELECT r.id, ''::text AS label, r.state, r.created_at AS at, count(*) OVER () AS total
FROM pc.runs r
WHERE r.org_id = sqlc.arg(org_id)
  AND (sqlc.arg(all_agents)::boolean OR r.agent_id = ANY (sqlc.arg(agents)::uuid[]))
  AND r.id BETWEEN sqlc.arg(id_lo)::uuid AND sqlc.arg(id_hi)::uuid
ORDER BY r.id DESC
LIMIT sqlc.arg(page_limit);

-- name: FindTransactions :many
SELECT t.id, t.operation::text AS label, t.decision AS state, t.created_at AS at, count(*) OVER () AS total
FROM pc.transactions t
JOIN pc.runs r ON r.org_id = t.org_id AND r.id = t.run_id
WHERE t.org_id = sqlc.arg(org_id)
  AND (sqlc.arg(all_agents)::boolean OR r.agent_id = ANY (sqlc.arg(agents)::uuid[]))
  AND t.id BETWEEN sqlc.arg(id_lo)::uuid AND sqlc.arg(id_hi)::uuid
ORDER BY t.id DESC
LIMIT sqlc.arg(page_limit);

-- name: FindGrants :many
SELECT g.id, ''::text AS label, g.state, g.created_at AS at, count(*) OVER () AS total
FROM pc.grants g
WHERE g.org_id = sqlc.arg(org_id)
  AND (sqlc.arg(all_agents)::boolean OR g.agent_id = ANY (sqlc.arg(agents)::uuid[]))
  AND g.id BETWEEN sqlc.arg(id_lo)::uuid AND sqlc.arg(id_hi)::uuid
ORDER BY g.id DESC
LIMIT sqlc.arg(page_limit);

-- name: FindApprovals :many
SELECT a.id, a.operation::text AS label, a.state, a.created_at AS at, count(*) OVER () AS total
FROM pc.approval_requests a
WHERE a.org_id = sqlc.arg(org_id)
  AND (sqlc.arg(all_agents)::boolean OR a.agent_id = ANY (sqlc.arg(agents)::uuid[]))
  AND a.id BETWEEN sqlc.arg(id_lo)::uuid AND sqlc.arg(id_hi)::uuid
ORDER BY a.id DESC
LIMIT sqlc.arg(page_limit);

-- name: FindFindings :many
SELECT f.id, f.title::text AS label, f.state, f.first_seen_at AS at, count(*) OVER () AS total
FROM pc.posture_findings f
WHERE f.org_id = sqlc.arg(org_id)
  AND (sqlc.arg(all_agents)::boolean OR f.agent_id = ANY (sqlc.arg(agents)::uuid[]))
  AND f.id BETWEEN sqlc.arg(id_lo)::uuid AND sqlc.arg(id_hi)::uuid
ORDER BY f.id DESC
LIMIT sqlc.arg(page_limit);

-- name: FindPolicyVersions :many
SELECT v.id, (p.bundle_id || ' v' || v.version)::text AS label, v.state, v.created_at AS at, count(*) OVER () AS total
FROM pc.policy_versions v
JOIN pc.policies p ON p.org_id = v.org_id AND p.id = v.policy_id
WHERE v.org_id = sqlc.arg(org_id)
  AND v.id BETWEEN sqlc.arg(id_lo)::uuid AND sqlc.arg(id_hi)::uuid
ORDER BY v.id DESC
LIMIT sqlc.arg(page_limit);

-- name: FindAudit :many
SELECT e.id, e.kind::text AS label, ''::text AS state, e.occurred_at AS at, count(*) OVER () AS total
FROM pc.ledger_entries e
WHERE e.org_id = sqlc.arg(org_id)
  AND e.id BETWEEN sqlc.arg(id_lo)::uuid AND sqlc.arg(id_hi)::uuid
ORDER BY e.id DESC
LIMIT sqlc.arg(page_limit);

-- name: FindAutomations :many
SELECT a.id, a.name::text AS label, a.state, a.created_at AS at, count(*) OVER () AS total
FROM pc.automations a
WHERE a.org_id = sqlc.arg(org_id)
  AND ((sqlc.narg(id_lo)::uuid IS NOT NULL AND a.id BETWEEN sqlc.narg(id_lo)::uuid AND sqlc.narg(id_hi)::uuid)
       OR (sqlc.arg(name_hi)::text <> '' AND lower(a.name) ~>=~ sqlc.arg(name_lo)::text AND lower(a.name) ~<=~ sqlc.arg(name_hi)::text)
       OR (sqlc.arg(contains)::text <> '' AND lower(a.name) LIKE sqlc.arg(contains)::text ESCAPE '\'))
ORDER BY lower(a.name) = sqlc.arg(lowered)::text DESC, starts_with(lower(a.name), sqlc.arg(lowered)::text) DESC, a.name, a.id
LIMIT sqlc.arg(page_limit);

-- Executions have no name: they are found by id, labelled with their
-- automation's name.
-- name: FindAutomationExecutions :many
SELECT e.id, a.name::text AS label, e.state, e.created_at AS at, count(*) OVER () AS total
FROM pc.automation_executions e
JOIN pc.automations a ON a.org_id = e.org_id AND a.id = e.automation_id
WHERE e.org_id = sqlc.arg(org_id)
  AND e.id BETWEEN sqlc.arg(id_lo)::uuid AND sqlc.arg(id_hi)::uuid
ORDER BY e.id DESC
LIMIT sqlc.arg(page_limit);
