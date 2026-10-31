-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Recommendations (G0 M21 D302, D308): the read-only signals of the closed
-- catalog, and dismissals. Agent-backed signals are filtered to the
-- viewer's agents before anything is counted (HR-536). Range agents never
-- count.

-- name: RecommendationAgentContexts :many
-- The live agents the viewer may read, per execution context.
SELECT execution_context::text AS context, count(*)::int AS agents,
    (array_agg(id ORDER BY id))[1:20]::uuid[] AS refs
FROM pc.agents
WHERE org_id = sqlc.arg(org_id) AND state <> 'RETIRED' AND NOT range_agent AND execution_context IS NOT NULL
  AND (sqlc.arg(all_agents)::boolean OR id = ANY (sqlc.arg(agent_ids)::uuid[]))
GROUP BY execution_context
ORDER BY execution_context;

-- name: RecommendationOpenSecrets :many
-- The open scan discoveries of the given credential kinds on agents the
-- viewer may read. observed is untrusted: it is matched against the closed
-- kinds only, and nothing from it is returned except a kind on that list.
SELECT (d.observed->>'secret_kind')::text AS secret_kind, count(*)::int AS discoveries,
    (array_agg(d.id ORDER BY d.id))[1:20]::uuid[] AS refs
FROM pc.discoveries d
JOIN pc.agents a ON a.org_id = d.org_id AND a.id = d.agent_id
WHERE d.org_id = sqlc.arg(org_id) AND d.state = 'OPEN' AND d.source = 'scan' AND a.state <> 'RETIRED' AND NOT a.range_agent
  AND d.observed->>'kind' = 'env_secret' AND d.observed->>'secret_kind' = ANY (sqlc.arg(kinds)::text[])
  AND (sqlc.arg(all_agents)::boolean OR d.agent_id = ANY (sqlc.arg(agent_ids)::uuid[]))
GROUP BY d.observed->>'secret_kind'
ORDER BY d.observed->>'secret_kind';

-- name: RecommendationDataAgents :one
-- The agents the viewer may read that coverage records on an active
-- database connection.
SELECT count(DISTINCT s.agent_id)::int AS agents,
    COALESCE((array_agg(DISTINCT s.agent_id ORDER BY s.agent_id))[1:20], '{}')::uuid[] AS refs
FROM pc.coverage_snapshots s
JOIN pc.connections c ON c.org_id = s.org_id AND c.id = s.connection_id
JOIN pc.agents a ON a.org_id = s.org_id AND a.id = s.agent_id
WHERE s.org_id = sqlc.arg(org_id) AND c.kind = 'postgres' AND c.state = 'ACTIVE' AND a.state <> 'RETIRED' AND NOT a.range_agent
  AND (sqlc.arg(all_agents)::boolean OR s.agent_id = ANY (sqlc.arg(agent_ids)::uuid[]));

-- name: RecommendationIntegrations :one
-- What the org has connected, whichever agents the viewer may read.
SELECT
    (SELECT COALESCE(array_agg(DISTINCT i.kind), '{}')::text[] FROM pc.trusted_issuers i
     WHERE i.org_id = sqlc.arg(org_id) AND i.state = 'ACTIVE') AS issuers,
    (SELECT COALESCE(array_agg(DISTINCT c.package), '{}')::text[] FROM pc.connections c
     WHERE c.org_id = sqlc.arg(org_id) AND c.state = 'ACTIVE') AS packages,
    (SELECT COALESCE(array_agg(DISTINCT n.kind), '{}')::text[] FROM pc.notification_channels n
     WHERE n.org_id = sqlc.arg(org_id) AND n.state = 'ACTIVE'
       -- A slack_app or teams_app channel counts once activated (D317).
       AND (n.kind <> 'slack_app' OR EXISTS (
           SELECT 1 FROM pc.slack_app_channels a
           WHERE a.org_id = n.org_id AND a.channel_record_id = n.id AND a.state = 'ACTIVE'))
       AND (n.kind <> 'teams_app' OR EXISTS (
           SELECT 1 FROM pc.teams_app_channels a
           WHERE a.org_id = n.org_id AND a.channel_record_id = n.id AND a.state = 'ACTIVE'))) AS channels,
    (SELECT EXISTS (SELECT 1 FROM pc.siem_destinations d WHERE d.org_id = sqlc.arg(org_id) AND d.state = 'ACTIVE'))::boolean AS siem,
    (SELECT EXISTS (SELECT 1 FROM pc.fact_providers f WHERE f.org_id = sqlc.arg(org_id) AND f.state = 'ACTIVE'))::boolean AS fact_providers;

-- name: ListRecommendationDismissals :many
SELECT * FROM pc.recommendation_dismissals WHERE org_id = sqlc.arg(org_id);

-- name: InsertRecommendationDismissal :execrows
INSERT INTO pc.recommendation_dismissals (org_id, recommendation_id, dismissed_by, reason)
VALUES (sqlc.arg(org_id), sqlc.arg(recommendation_id), sqlc.arg(dismissed_by), sqlc.arg(reason))
ON CONFLICT (org_id, recommendation_id) DO NOTHING;

-- name: DeleteRecommendationDismissal :execrows
DELETE FROM pc.recommendation_dismissals WHERE org_id = sqlc.arg(org_id) AND recommendation_id = sqlc.arg(recommendation_id);
