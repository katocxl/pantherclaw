-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

-- Structured search over the M10 and authority records (G0 M11 part 2
-- coordinator decision D44; HR-257, HR-295). Like queries/search.sql, every
-- query takes the viewer's scope and filters rows outside it before paging
-- and counting. An alert or incident is in a scoped viewer's scope when it
-- names at least one agent and every agent it names is visible (as on the
-- Operations queue); a case when pc.case_within says so; a finding when its
-- agent is visible (a finding without an agent needs the org-wide scope).
-- Policy versions, packages and gateways are org-level. Searches page
-- newest first by id; counts stop at 10001.

-- name: SearchAlerts :many
SELECT a.id, a.source, a.rule_id, a.title, a.severity, a.attention, a.basis, a.state, a.incident_id, a.count,
       a.first_seen, a.last_seen, a.test, a.created_at,
       coalesce((SELECT array_agg(DISTINCT s ->> 'id') FROM jsonb_array_elements(a.subjects) s
                 WHERE s ->> 'type' = 'agent'), '{}')::text[] AS agents
FROM pc.alerts a
WHERE a.org_id = sqlc.arg(org_id)
  AND (sqlc.arg(all_agents)::boolean
       OR (EXISTS (SELECT 1 FROM jsonb_array_elements(a.subjects) s WHERE s ->> 'type' = 'agent')
           AND NOT EXISTS (SELECT 1 FROM jsonb_array_elements(a.subjects) s
                           WHERE s ->> 'type' = 'agent' AND NOT (s ->> 'id') = ANY (sqlc.arg(agents)::uuid[]::text[]))))
  AND (sqlc.narg(before)::uuid IS NULL OR a.id < sqlc.narg(before)::uuid)
  AND (sqlc.narg(id)::uuid IS NULL OR a.id = sqlc.narg(id)::uuid)
  AND (sqlc.narg(agent_id)::uuid IS NULL
       OR a.subjects @> jsonb_build_array(jsonb_build_object('type', 'agent', 'id', sqlc.narg(agent_id)::uuid::text)))
  AND (sqlc.narg(incident_id)::uuid IS NULL OR a.incident_id = sqlc.narg(incident_id)::uuid)
  AND (cardinality(sqlc.arg(states)::text[]) = 0 OR a.state = ANY (sqlc.arg(states)::text[]))
  AND (cardinality(sqlc.arg(severities)::text[]) = 0 OR a.severity = ANY (sqlc.arg(severities)::text[]))
  AND (cardinality(sqlc.arg(sources)::text[]) = 0 OR a.source = ANY (sqlc.arg(sources)::text[]))
  AND (sqlc.narg(start_time)::timestamptz IS NULL OR a.created_at >= sqlc.narg(start_time)::timestamptz)
  AND (sqlc.narg(end_time)::timestamptz IS NULL OR a.created_at < sqlc.narg(end_time)::timestamptz)
ORDER BY a.id DESC
LIMIT sqlc.arg(page_limit);

-- name: CountAlerts :one
SELECT count(*) FROM (
    SELECT 1 FROM pc.alerts a
    WHERE a.org_id = sqlc.arg(org_id)
      AND (sqlc.arg(all_agents)::boolean
           OR (EXISTS (SELECT 1 FROM jsonb_array_elements(a.subjects) s WHERE s ->> 'type' = 'agent')
               AND NOT EXISTS (SELECT 1 FROM jsonb_array_elements(a.subjects) s
                               WHERE s ->> 'type' = 'agent' AND NOT (s ->> 'id') = ANY (sqlc.arg(agents)::uuid[]::text[]))))
      AND (sqlc.narg(id)::uuid IS NULL OR a.id = sqlc.narg(id)::uuid)
      AND (sqlc.narg(agent_id)::uuid IS NULL
           OR a.subjects @> jsonb_build_array(jsonb_build_object('type', 'agent', 'id', sqlc.narg(agent_id)::uuid::text)))
      AND (sqlc.narg(incident_id)::uuid IS NULL OR a.incident_id = sqlc.narg(incident_id)::uuid)
      AND (cardinality(sqlc.arg(states)::text[]) = 0 OR a.state = ANY (sqlc.arg(states)::text[]))
      AND (cardinality(sqlc.arg(severities)::text[]) = 0 OR a.severity = ANY (sqlc.arg(severities)::text[]))
      AND (cardinality(sqlc.arg(sources)::text[]) = 0 OR a.source = ANY (sqlc.arg(sources)::text[]))
      AND (sqlc.narg(start_time)::timestamptz IS NULL OR a.created_at >= sqlc.narg(start_time)::timestamptz)
      AND (sqlc.narg(end_time)::timestamptz IS NULL OR a.created_at < sqlc.narg(end_time)::timestamptz)
    LIMIT 10001
) x;

-- name: SearchIncidents :many
SELECT i.id, i.title, i.severity, i.state, i.owner_id, i.opened_by, i.test, i.created_at, i.updated_at,
       coalesce((SELECT array_agg(DISTINCT s ->> 'id') FROM pc.alerts a, jsonb_array_elements(a.subjects) s
                 WHERE a.org_id = i.org_id AND a.incident_id = i.id AND s ->> 'type' = 'agent'), '{}')::text[] AS agents
FROM pc.incidents i
WHERE i.org_id = sqlc.arg(org_id)
  AND (sqlc.arg(all_agents)::boolean
       OR (EXISTS (SELECT 1 FROM pc.alerts a, jsonb_array_elements(a.subjects) s
                   WHERE a.org_id = i.org_id AND a.incident_id = i.id AND s ->> 'type' = 'agent')
           AND NOT EXISTS (SELECT 1 FROM pc.alerts a, jsonb_array_elements(a.subjects) s
                           WHERE a.org_id = i.org_id AND a.incident_id = i.id AND s ->> 'type' = 'agent'
                             AND NOT (s ->> 'id') = ANY (sqlc.arg(agents)::uuid[]::text[]))))
  AND (sqlc.narg(before)::uuid IS NULL OR i.id < sqlc.narg(before)::uuid)
  AND (sqlc.narg(id)::uuid IS NULL OR i.id = sqlc.narg(id)::uuid)
  AND (sqlc.narg(agent_id)::uuid IS NULL
       OR EXISTS (SELECT 1 FROM pc.alerts a WHERE a.org_id = i.org_id AND a.incident_id = i.id
                    AND a.subjects @> jsonb_build_array(jsonb_build_object('type', 'agent', 'id', sqlc.narg(agent_id)::uuid::text))))
  AND (cardinality(sqlc.arg(states)::text[]) = 0 OR i.state = ANY (sqlc.arg(states)::text[]))
  AND (cardinality(sqlc.arg(severities)::text[]) = 0 OR i.severity = ANY (sqlc.arg(severities)::text[]))
  AND (sqlc.narg(start_time)::timestamptz IS NULL OR i.created_at >= sqlc.narg(start_time)::timestamptz)
  AND (sqlc.narg(end_time)::timestamptz IS NULL OR i.created_at < sqlc.narg(end_time)::timestamptz)
ORDER BY i.id DESC
LIMIT sqlc.arg(page_limit);

-- name: CountIncidents :one
SELECT count(*) FROM (
    SELECT 1 FROM pc.incidents i
    WHERE i.org_id = sqlc.arg(org_id)
      AND (sqlc.arg(all_agents)::boolean
           OR (EXISTS (SELECT 1 FROM pc.alerts a, jsonb_array_elements(a.subjects) s
                       WHERE a.org_id = i.org_id AND a.incident_id = i.id AND s ->> 'type' = 'agent')
               AND NOT EXISTS (SELECT 1 FROM pc.alerts a, jsonb_array_elements(a.subjects) s
                               WHERE a.org_id = i.org_id AND a.incident_id = i.id AND s ->> 'type' = 'agent'
                                 AND NOT (s ->> 'id') = ANY (sqlc.arg(agents)::uuid[]::text[]))))
      AND (sqlc.narg(id)::uuid IS NULL OR i.id = sqlc.narg(id)::uuid)
      AND (sqlc.narg(agent_id)::uuid IS NULL
           OR EXISTS (SELECT 1 FROM pc.alerts a WHERE a.org_id = i.org_id AND a.incident_id = i.id
                        AND a.subjects @> jsonb_build_array(jsonb_build_object('type', 'agent', 'id', sqlc.narg(agent_id)::uuid::text))))
      AND (cardinality(sqlc.arg(states)::text[]) = 0 OR i.state = ANY (sqlc.arg(states)::text[]))
      AND (cardinality(sqlc.arg(severities)::text[]) = 0 OR i.severity = ANY (sqlc.arg(severities)::text[]))
      AND (sqlc.narg(start_time)::timestamptz IS NULL OR i.created_at >= sqlc.narg(start_time)::timestamptz)
      AND (sqlc.narg(end_time)::timestamptz IS NULL OR i.created_at < sqlc.narg(end_time)::timestamptz)
    LIMIT 10001
) x;

-- name: SearchCases :many
SELECT c.id, c.title, c.source, c.state, c.owner_id, c.alert_id, c.incident_id, c.disposition, c.impact,
       c.created_at, c.closed_at,
       ARRAY(SELECT x::text FROM pc.case_agents(c.org_id, c.id) x ORDER BY 1)::text[] AS agents
FROM pc.cases c
WHERE c.org_id = sqlc.arg(org_id)
  AND (sqlc.arg(all_agents)::boolean OR pc.case_within(c.org_id, c.id, sqlc.arg(agents)::uuid[]))
  AND (sqlc.narg(before)::uuid IS NULL OR c.id < sqlc.narg(before)::uuid)
  AND (sqlc.narg(id)::uuid IS NULL OR c.id = sqlc.narg(id)::uuid)
  AND (sqlc.narg(agent_id)::uuid IS NULL
       OR EXISTS (SELECT 1 FROM pc.case_agents(c.org_id, c.id) x WHERE x = sqlc.narg(agent_id)::uuid))
  AND (sqlc.narg(alert_id)::uuid IS NULL OR c.alert_id = sqlc.narg(alert_id)::uuid)
  AND (sqlc.narg(incident_id)::uuid IS NULL OR c.incident_id = sqlc.narg(incident_id)::uuid)
  AND (cardinality(sqlc.arg(states)::text[]) = 0 OR c.state = ANY (sqlc.arg(states)::text[]))
  AND (sqlc.narg(start_time)::timestamptz IS NULL OR c.created_at >= sqlc.narg(start_time)::timestamptz)
  AND (sqlc.narg(end_time)::timestamptz IS NULL OR c.created_at < sqlc.narg(end_time)::timestamptz)
ORDER BY c.id DESC
LIMIT sqlc.arg(page_limit);

-- name: CountCases :one
SELECT count(*) FROM (
    SELECT 1 FROM pc.cases c
    WHERE c.org_id = sqlc.arg(org_id)
      AND (sqlc.arg(all_agents)::boolean OR pc.case_within(c.org_id, c.id, sqlc.arg(agents)::uuid[]))
      AND (sqlc.narg(id)::uuid IS NULL OR c.id = sqlc.narg(id)::uuid)
      AND (sqlc.narg(agent_id)::uuid IS NULL
           OR EXISTS (SELECT 1 FROM pc.case_agents(c.org_id, c.id) x WHERE x = sqlc.narg(agent_id)::uuid))
      AND (sqlc.narg(alert_id)::uuid IS NULL OR c.alert_id = sqlc.narg(alert_id)::uuid)
      AND (sqlc.narg(incident_id)::uuid IS NULL OR c.incident_id = sqlc.narg(incident_id)::uuid)
      AND (cardinality(sqlc.arg(states)::text[]) = 0 OR c.state = ANY (sqlc.arg(states)::text[]))
      AND (sqlc.narg(start_time)::timestamptz IS NULL OR c.created_at >= sqlc.narg(start_time)::timestamptz)
      AND (sqlc.narg(end_time)::timestamptz IS NULL OR c.created_at < sqlc.narg(end_time)::timestamptz)
    LIMIT 10001
) x;

-- A temporary acceptance past its end reads OPEN, as on the posture queue.
-- name: SearchFindings :many
SELECT f.id, f.kind, f.root_cause, f.agent_id, f.connection_id, f.grant_id, f.title, f.severity,
       (CASE WHEN f.state = 'ACCEPTED_TEMPORARILY' AND f.accepted_until <= now() THEN 'OPEN' ELSE f.state END)::text AS state,
       f.owner_user_id, f.first_seen_at, f.last_seen_at
FROM pc.posture_findings f
WHERE f.org_id = sqlc.arg(org_id)
  AND (sqlc.arg(all_agents)::boolean OR f.agent_id = ANY (sqlc.arg(agents)::uuid[]))
  AND (sqlc.narg(before)::uuid IS NULL OR f.id < sqlc.narg(before)::uuid)
  AND (sqlc.narg(id)::uuid IS NULL OR f.id = sqlc.narg(id)::uuid)
  AND (sqlc.narg(agent_id)::uuid IS NULL OR f.agent_id = sqlc.narg(agent_id)::uuid)
  AND (sqlc.narg(connection_id)::uuid IS NULL OR f.connection_id = sqlc.narg(connection_id)::uuid)
  AND (sqlc.narg(grant_id)::uuid IS NULL OR f.grant_id = sqlc.narg(grant_id)::uuid)
  AND (cardinality(sqlc.arg(states)::text[]) = 0
       OR (CASE WHEN f.state = 'ACCEPTED_TEMPORARILY' AND f.accepted_until <= now() THEN 'OPEN' ELSE f.state END)
          = ANY (sqlc.arg(states)::text[]))
  AND (cardinality(sqlc.arg(kinds)::text[]) = 0 OR f.kind = ANY (sqlc.arg(kinds)::text[]))
  AND (cardinality(sqlc.arg(severities)::text[]) = 0 OR upper(f.severity) = ANY (sqlc.arg(severities)::text[]))
  AND (sqlc.narg(start_time)::timestamptz IS NULL OR f.first_seen_at >= sqlc.narg(start_time)::timestamptz)
  AND (sqlc.narg(end_time)::timestamptz IS NULL OR f.first_seen_at < sqlc.narg(end_time)::timestamptz)
ORDER BY f.id DESC
LIMIT sqlc.arg(page_limit);

-- name: CountFindings :one
SELECT count(*) FROM (
    SELECT 1 FROM pc.posture_findings f
    WHERE f.org_id = sqlc.arg(org_id)
      AND (sqlc.arg(all_agents)::boolean OR f.agent_id = ANY (sqlc.arg(agents)::uuid[]))
      AND (sqlc.narg(id)::uuid IS NULL OR f.id = sqlc.narg(id)::uuid)
      AND (sqlc.narg(agent_id)::uuid IS NULL OR f.agent_id = sqlc.narg(agent_id)::uuid)
      AND (sqlc.narg(connection_id)::uuid IS NULL OR f.connection_id = sqlc.narg(connection_id)::uuid)
      AND (sqlc.narg(grant_id)::uuid IS NULL OR f.grant_id = sqlc.narg(grant_id)::uuid)
      AND (cardinality(sqlc.arg(states)::text[]) = 0
           OR (CASE WHEN f.state = 'ACCEPTED_TEMPORARILY' AND f.accepted_until <= now() THEN 'OPEN' ELSE f.state END)
              = ANY (sqlc.arg(states)::text[]))
      AND (cardinality(sqlc.arg(kinds)::text[]) = 0 OR f.kind = ANY (sqlc.arg(kinds)::text[]))
      AND (cardinality(sqlc.arg(severities)::text[]) = 0 OR upper(f.severity) = ANY (sqlc.arg(severities)::text[]))
      AND (sqlc.narg(start_time)::timestamptz IS NULL OR f.first_seen_at >= sqlc.narg(start_time)::timestamptz)
      AND (sqlc.narg(end_time)::timestamptz IS NULL OR f.first_seen_at < sqlc.narg(end_time)::timestamptz)
    LIMIT 10001
) x;

-- name: SearchPolicyVersions :many
SELECT v.id, v.policy_id, p.bundle_id, v.version, v.state, v.created_by, v.created_at, v.published_by, v.published_at
FROM pc.policy_versions v
JOIN pc.policies p ON p.org_id = v.org_id AND p.id = v.policy_id
WHERE v.org_id = sqlc.arg(org_id)
  AND (sqlc.narg(before)::uuid IS NULL OR v.id < sqlc.narg(before)::uuid)
  AND (sqlc.narg(id)::uuid IS NULL OR v.id = sqlc.narg(id)::uuid)
  AND (cardinality(sqlc.arg(states)::text[]) = 0 OR v.state = ANY (sqlc.arg(states)::text[]))
  AND (sqlc.narg(start_time)::timestamptz IS NULL OR v.created_at >= sqlc.narg(start_time)::timestamptz)
  AND (sqlc.narg(end_time)::timestamptz IS NULL OR v.created_at < sqlc.narg(end_time)::timestamptz)
ORDER BY v.id DESC
LIMIT sqlc.arg(page_limit);

-- name: CountPolicyVersions :one
SELECT count(*) FROM (
    SELECT 1 FROM pc.policy_versions v
    WHERE v.org_id = sqlc.arg(org_id)
      AND (sqlc.narg(id)::uuid IS NULL OR v.id = sqlc.narg(id)::uuid)
      AND (cardinality(sqlc.arg(states)::text[]) = 0 OR v.state = ANY (sqlc.arg(states)::text[]))
      AND (sqlc.narg(start_time)::timestamptz IS NULL OR v.created_at >= sqlc.narg(start_time)::timestamptz)
      AND (sqlc.narg(end_time)::timestamptz IS NULL OR v.created_at < sqlc.narg(end_time)::timestamptz)
    LIMIT 10001
) x;

-- A package's state is its latest imported version's.
-- name: SearchPackages :many
SELECT k.id, k.name, k.created_at, coalesce(v.version, '')::text AS latest_version,
       coalesce(v.state, '')::text AS latest_state, coalesce(v.file_digest, '')::text AS latest_digest
FROM pc.tool_packages k
LEFT JOIN LATERAL (SELECT pv.version, pv.state, pv.file_digest FROM pc.package_versions pv
                   WHERE pv.org_id = k.org_id AND pv.package_id = k.id
                   ORDER BY pv.imported_at DESC, pv.id DESC LIMIT 1) v ON true
WHERE k.org_id = sqlc.arg(org_id)
  AND (sqlc.narg(before)::uuid IS NULL OR k.id < sqlc.narg(before)::uuid)
  AND (sqlc.narg(id)::uuid IS NULL OR k.id = sqlc.narg(id)::uuid)
  AND (cardinality(sqlc.arg(states)::text[]) = 0 OR v.state = ANY (sqlc.arg(states)::text[]))
  AND (sqlc.narg(start_time)::timestamptz IS NULL OR k.created_at >= sqlc.narg(start_time)::timestamptz)
  AND (sqlc.narg(end_time)::timestamptz IS NULL OR k.created_at < sqlc.narg(end_time)::timestamptz)
ORDER BY k.id DESC
LIMIT sqlc.arg(page_limit);

-- name: CountPackages :one
SELECT count(*) FROM (
    SELECT 1 FROM pc.tool_packages k
    LEFT JOIN LATERAL (SELECT pv.state FROM pc.package_versions pv
                       WHERE pv.org_id = k.org_id AND pv.package_id = k.id
                       ORDER BY pv.imported_at DESC, pv.id DESC LIMIT 1) v ON true
    WHERE k.org_id = sqlc.arg(org_id)
      AND (sqlc.narg(id)::uuid IS NULL OR k.id = sqlc.narg(id)::uuid)
      AND (cardinality(sqlc.arg(states)::text[]) = 0 OR v.state = ANY (sqlc.arg(states)::text[]))
      AND (sqlc.narg(start_time)::timestamptz IS NULL OR k.created_at >= sqlc.narg(start_time)::timestamptz)
      AND (sqlc.narg(end_time)::timestamptz IS NULL OR k.created_at < sqlc.narg(end_time)::timestamptz)
    LIMIT 10001
) x;

-- name: SearchGateways :many
SELECT g.id, g.name, g.state, g.config_version, g.created_by, g.created_at, g.revoked_at
FROM pc.gateways g
WHERE g.org_id = sqlc.arg(org_id)
  AND (sqlc.narg(before)::uuid IS NULL OR g.id < sqlc.narg(before)::uuid)
  AND (sqlc.narg(id)::uuid IS NULL OR g.id = sqlc.narg(id)::uuid)
  AND (cardinality(sqlc.arg(states)::text[]) = 0 OR g.state = ANY (sqlc.arg(states)::text[]))
  AND (sqlc.narg(start_time)::timestamptz IS NULL OR g.created_at >= sqlc.narg(start_time)::timestamptz)
  AND (sqlc.narg(end_time)::timestamptz IS NULL OR g.created_at < sqlc.narg(end_time)::timestamptz)
ORDER BY g.id DESC
LIMIT sqlc.arg(page_limit);

-- name: CountGateways :one
SELECT count(*) FROM (
    SELECT 1 FROM pc.gateways g
    WHERE g.org_id = sqlc.arg(org_id)
      AND (sqlc.narg(id)::uuid IS NULL OR g.id = sqlc.narg(id)::uuid)
      AND (cardinality(sqlc.arg(states)::text[]) = 0 OR g.state = ANY (sqlc.arg(states)::text[]))
      AND (sqlc.narg(start_time)::timestamptz IS NULL OR g.created_at >= sqlc.narg(start_time)::timestamptz)
      AND (sqlc.narg(end_time)::timestamptz IS NULL OR g.created_at < sqlc.narg(end_time)::timestamptz)
    LIMIT 10001
) x;

-- Automations (G0 M11 part 2 D44): org-level under automation.read.
-- name: SearchAutomations :many
SELECT a.id, a.name, a.kind, a.state, a.rollout, a.owner_user_id, a.service_account_id, a.enabled_version_id,
       a.pause_reason, a.created_at
FROM pc.automations a
WHERE a.org_id = sqlc.arg(org_id)
  AND (sqlc.narg(before)::uuid IS NULL OR a.id < sqlc.narg(before)::uuid)
  AND (sqlc.narg(id)::uuid IS NULL OR a.id = sqlc.narg(id)::uuid)
  AND (cardinality(sqlc.arg(states)::text[]) = 0 OR a.state = ANY (sqlc.arg(states)::text[]))
  AND (cardinality(sqlc.arg(kinds)::text[]) = 0 OR a.kind = ANY (sqlc.arg(kinds)::text[]))
  AND (sqlc.narg(start_time)::timestamptz IS NULL OR a.created_at >= sqlc.narg(start_time)::timestamptz)
  AND (sqlc.narg(end_time)::timestamptz IS NULL OR a.created_at < sqlc.narg(end_time)::timestamptz)
ORDER BY a.id DESC
LIMIT sqlc.arg(page_limit);

-- name: CountAutomations :one
SELECT count(*) FROM (
    SELECT 1 FROM pc.automations a
    WHERE a.org_id = sqlc.arg(org_id)
      AND (sqlc.narg(id)::uuid IS NULL OR a.id = sqlc.narg(id)::uuid)
      AND (cardinality(sqlc.arg(states)::text[]) = 0 OR a.state = ANY (sqlc.arg(states)::text[]))
      AND (cardinality(sqlc.arg(kinds)::text[]) = 0 OR a.kind = ANY (sqlc.arg(kinds)::text[]))
      AND (sqlc.narg(start_time)::timestamptz IS NULL OR a.created_at >= sqlc.narg(start_time)::timestamptz)
      AND (sqlc.narg(end_time)::timestamptz IS NULL OR a.created_at < sqlc.narg(end_time)::timestamptz)
    LIMIT 10001
) x;
