-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- The ranked posture queue (G0 M24 D200-D206): the sources it joins that no
-- existing read covers, what ranking reads of an agent, and the daily rollup.

-- PostureQueueAgents reads what ranking needs of the agents findings name.
-- name: PostureQueueAgents :many
SELECT a.id, a.name, a.team_id, (a.owner_user_id IS NOT NULL)::boolean AS owned,
       (coalesce(e.kind, '') = 'PRODUCTION')::boolean AS production
FROM pc.agents a
LEFT JOIN pc.environments e ON e.org_id = a.org_id AND e.id = a.environment_id
WHERE a.org_id = sqlc.arg(org_id) AND a.id = ANY (sqlc.arg(ids)::uuid[])
ORDER BY a.id;

-- PostureQueueCoverageFindings lists open coverage findings a posture finding
-- has not imported: an imported one is already in the queue through it.
-- name: PostureQueueCoverageFindings :many
SELECT c.id, c.kind, c.connection_id, c.agent_id, c.subject, c.severity, c.first_seen_at
FROM pc.coverage_findings c
WHERE c.org_id = sqlc.arg(org_id) AND c.state = 'OPEN'
  AND (sqlc.arg(all_agents)::boolean OR c.agent_id = ANY (sqlc.arg(agent_ids)::uuid[])
       OR (c.agent_id IS NULL AND sqlc.arg(org_scope)::boolean))
  AND NOT EXISTS (
      SELECT 1 FROM pc.posture_findings p
      WHERE p.org_id = c.org_id AND p.coverage_finding_id = c.id
        AND p.state IN ('OPEN', 'ASSIGNED', 'TESTING', 'EVIDENCE_INCOMPLETE', 'ACCEPTED_TEMPORARILY'))
ORDER BY c.id DESC
LIMIT sqlc.arg(max_rows);

-- PostureQueueNewInventory lists the org's NEW inventory items. Only names:
-- a description is untrusted and is never served.
-- name: PostureQueueNewInventory :many
SELECT id, connection_id, kind, name, first_seen FROM pc.connection_inventory
WHERE org_id = sqlc.arg(org_id) AND state = 'NEW'
ORDER BY id DESC
LIMIT sqlc.arg(max_rows);

-- PostureQueueTeams lists the org's teams and where they sit, to scope trends.
-- name: PostureQueueTeams :many
SELECT id, business_unit_id FROM pc.teams WHERE org_id = sqlc.arg(org_id) ORDER BY id;

-- InsertPostureDailyRun records that a day was collected, once.
-- name: InsertPostureDailyRun :execrows
INSERT INTO pc.posture_daily_runs (org_id, day, truncated_sources)
VALUES (sqlc.arg(org_id), sqlc.arg(day)::date, sqlc.arg(truncated_sources)::text[])
ON CONFLICT (org_id, day) DO NOTHING;

-- name: InsertPostureDaily :exec
INSERT INTO pc.posture_daily (org_id, day, kind, severity, team_id, open_count, closed_count)
VALUES (sqlc.arg(org_id), sqlc.arg(day)::date, sqlc.arg(kind), sqlc.arg(severity), sqlc.narg(team_id), sqlc.arg(open_count),
    sqlc.narg(closed_count));

-- name: ListPostureDailyRuns :many
SELECT day, truncated_sources FROM pc.posture_daily_runs
WHERE org_id = sqlc.arg(org_id) AND day >= sqlc.arg(first_day)::date AND day <= sqlc.arg(last_day)::date
ORDER BY day;

-- name: ListPostureDaily :many
SELECT day, kind, severity, team_id, open_count, closed_count FROM pc.posture_daily
WHERE org_id = sqlc.arg(org_id) AND day >= sqlc.arg(first_day)::date AND day <= sqlc.arg(last_day)::date
ORDER BY day, kind, severity, team_id;
