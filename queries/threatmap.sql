-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Threat map queries (G0 M28 D716, D719). Every query runs inside
-- db.InTenantTx and also filters by org_id explicitly.

-- name: UpsertThreatMapSnapshot :exec
-- Today's evaluation for one scope and framework; a later run the same day
-- replaces it.
INSERT INTO pc.threat_map_snapshots (org_id, scope_key, framework, day, evaluated_at,
    catalog_version, catalog_digest, mapping_digest, states, counts)
VALUES (sqlc.arg(org_id), sqlc.arg(scope_key), sqlc.arg(framework), sqlc.arg(day), sqlc.arg(evaluated_at),
    sqlc.arg(catalog_version), sqlc.arg(catalog_digest), sqlc.arg(mapping_digest), sqlc.arg(states), sqlc.arg(counts))
ON CONFLICT (org_id, scope_key, framework, day) DO UPDATE SET
    evaluated_at = EXCLUDED.evaluated_at, catalog_version = EXCLUDED.catalog_version,
    catalog_digest = EXCLUDED.catalog_digest, mapping_digest = EXCLUDED.mapping_digest,
    states = EXCLUDED.states, counts = EXCLUDED.counts;

-- name: LatestThreatMapSnapshot :one
-- The newest stored evaluation for one scope and framework, the one a new
-- evaluation is compared with to find dropped lanes.
SELECT day, evaluated_at, catalog_version, catalog_digest, mapping_digest, states, counts
FROM pc.threat_map_snapshots
WHERE org_id = sqlc.arg(org_id) AND scope_key = sqlc.arg(scope_key) AND framework = sqlc.arg(framework)
ORDER BY day DESC
LIMIT 1;

-- name: ThreatMapSnapshotsSince :many
-- One scope and framework's days from since on, oldest first (history).
SELECT day, evaluated_at, catalog_version, mapping_digest, states, counts
FROM pc.threat_map_snapshots
WHERE org_id = sqlc.arg(org_id) AND scope_key = sqlc.arg(scope_key) AND framework = sqlc.arg(framework)
    AND day >= sqlc.arg(since)
ORDER BY day;

-- name: DeleteOldThreatMapSnapshots :execrows
-- Rows older than the history keeps (400 days, D719).
DELETE FROM pc.threat_map_snapshots WHERE org_id = sqlc.arg(org_id) AND day < sqlc.arg(before);

-- The evaluator's inputs (G0 M28 D713). Each read is bounded by what the
-- org has: its agents, the latest coverage record per route, its rule
-- states, custom rules, automations and library results.

-- name: ThreatMapAgents :many
-- The org's agents but range agents. Active: neither suspended nor retired.
SELECT a.id, a.name, a.environment_id, (a.state NOT IN ('SUSPENDED', 'RETIRED'))::boolean AS active
FROM pc.agents a
WHERE a.org_id = sqlc.arg(org_id) AND NOT a.range_agent
ORDER BY a.name, a.id;

-- name: ThreatMapAgentActivity :many
-- Per agent, the newest real transaction since since (the input window).
SELECT r.agent_id, max(t.created_at)::timestamptz AS last_real
FROM pc.transactions t
JOIN pc.runs r ON r.org_id = t.org_id AND r.id = t.run_id
WHERE t.org_id = sqlc.arg(org_id) AND NOT t.simulated AND t.created_at >= sqlc.arg(since)
GROUP BY r.agent_id
ORDER BY r.agent_id;

-- name: ThreatMapRoutes :many
-- The latest coverage record per (agent, connection, operation).
SELECT DISTINCT ON (s.agent_id, s.connection_id, s.operation)
       s.agent_id, s.connection_id, s.operation, s.state, s.expires_at
FROM pc.coverage_snapshots s
WHERE s.org_id = sqlc.arg(org_id)
ORDER BY s.agent_id, s.connection_id, s.operation, s.id DESC;

-- name: ThreatMapRuleStates :many
SELECT rule_id, disabled_at, last_input_at
FROM pc.detection_rule_state
WHERE org_id = sqlc.arg(org_id);

-- name: ThreatMapOrgWideSuppressions :many
-- Rules an active suppression silences across the whole org.
SELECT DISTINCT s.rule_id
FROM pc.suppressions s
WHERE s.org_id = sqlc.arg(org_id) AND s.ended_at IS NULL AND s.expires_at > sqlc.arg(now)
  AND jsonb_array_length(s.subjects) = 0
ORDER BY s.rule_id;

-- name: ThreatMapCustomRules :many
-- Each custom rule's current row: its PUBLISHED version, else its newest.
SELECT DISTINCT ON (c.rule_id) c.id, c.rule_id, c.version, c.content, c.state
FROM pc.custom_detection_rules c
WHERE c.org_id = sqlc.arg(org_id)
ORDER BY c.rule_id, (c.state = 'PUBLISHED') DESC, c.version DESC;

-- name: ThreatMapHubInstalls :many
-- What INSTALLED Hub items made: a custom rule row or an automation (D716).
SELECT h.name, h.result_kind, h.result_ref
FROM pc.hub_installs h
WHERE h.org_id = sqlc.arg(org_id) AND h.status = 'INSTALLED' AND h.result_kind IN ('custom_rule', 'automation')
ORDER BY h.name, h.result_ref;

-- name: ThreatMapCursor :one
-- The detection cursor against the ledger head.
SELECT coalesce(c.seq, 0)::bigint AS seq, c.updated_at,
       coalesce((SELECT h.seq FROM pc.ledger_heads h WHERE h.org_id = sqlc.arg(org_id)), 0)::bigint AS head
FROM (SELECT sqlc.arg(org_id)::uuid AS org_id) o
LEFT JOIN pc.detection_cursors c ON c.org_id = o.org_id;

-- name: ThreatMapAutomations :many
-- The org's automations but retired ones, with the definition of their
-- enabled version, or of their newest version when none is enabled.
SELECT a.id, a.name, a.state,
       coalesce((SELECT v.definition FROM pc.automation_versions v
                 WHERE v.org_id = a.org_id AND v.automation_id = a.id
                 ORDER BY (v.id = a.enabled_version_id) DESC, v.number DESC LIMIT 1), '{}'::jsonb)::jsonb AS definition
FROM pc.automations a
WHERE a.org_id = sqlc.arg(org_id) AND a.state <> 'RETIRED'
ORDER BY a.name;

-- name: ThreatMapResults :many
-- Per library scenario and digest, the newest result of a FINISHED library
-- range (HR-689).
SELECT DISTINCT ON (x.scenario_id, x.scenario_digest)
       x.scenario_id, x.scenario_digest, x.range_id, x.verdict, x.observed_by, x.recorded_at
FROM pc.redteam_results x
JOIN pc.redteam_runs r ON r.org_id = x.org_id AND r.id = x.range_id
WHERE x.org_id = sqlc.arg(org_id) AND x.origin = 'library' AND r.origin = 'library' AND r.state = 'FINISHED'
ORDER BY x.scenario_id, x.scenario_digest, x.recorded_at DESC;

-- name: ThreatMapContentMode :one
SELECT coalesce((SELECT s.mode FROM pc.content_signal_settings s WHERE s.org_id = sqlc.arg(org_id)), 'OFF')::text;

-- name: ThreatMapMCPCatalogMode :one
SELECT coalesce((SELECT s.mode FROM pc.mcp_catalog_settings s WHERE s.org_id = sqlc.arg(org_id)), 'WATCH')::text;

-- name: ThreatMapAlertGroups :many
-- Non-test alerts first seen since since, grouped by their techniques, in
-- scope: every alert, or one with an agent subject in agents.
SELECT a.atlas::text[] AS techniques, count(*)::bigint AS n
FROM pc.alerts a
WHERE a.org_id = sqlc.arg(org_id) AND NOT a.test AND a.first_seen >= sqlc.arg(since) AND cardinality(a.atlas) > 0
  AND (sqlc.arg(all_agents)::boolean
       OR EXISTS (SELECT 1 FROM jsonb_array_elements(a.subjects) s
                  WHERE s ->> 'type' = 'agent' AND (s ->> 'id') = ANY (sqlc.arg(agents)::uuid[]::text[])))
GROUP BY a.atlas
ORDER BY a.atlas;

-- name: ThreatMapDecisionCounts :many
-- Real refusals and holds since since, by decisive reason code, in scope.
SELECT t.reason_code, t.decision, count(*)::bigint AS n
FROM pc.transactions t
JOIN pc.runs r ON r.org_id = t.org_id AND r.id = t.run_id
WHERE t.org_id = sqlc.arg(org_id) AND NOT t.simulated AND t.created_at >= sqlc.arg(since)
  AND t.decision IN ('DENY', 'REQUIRE_APPROVAL')
  AND (sqlc.arg(all_agents)::boolean OR r.agent_id = ANY (sqlc.arg(agents)::uuid[]))
GROUP BY t.reason_code, t.decision
ORDER BY t.reason_code, t.decision;
