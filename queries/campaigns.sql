-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Attack campaigns (G0 M25 D309; migration 00281). Everything runs as pc_app
-- in a tenant transaction. Steps are only inserted (HR-055); a campaign
-- changes once, from RUNNING.

-- name: InsertCampaign :one
INSERT INTO pc.campaigns (org_id, id, range_agent_id, started_by, runner_version, set_digest, scenario_ids, image_digest,
    model_host, relay_connection_id, scripted)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(range_agent_id), sqlc.arg(started_by), sqlc.arg(runner_version),
    sqlc.arg(set_digest), sqlc.arg(scenario_ids), sqlc.arg(image_digest), sqlc.arg(model_host),
    sqlc.arg(relay_connection_id), sqlc.arg(scripted))
RETURNING *;

-- name: GetCampaign :one
SELECT * FROM pc.campaigns WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: LockCampaign :one
SELECT * FROM pc.campaigns WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) FOR UPDATE;

-- name: OpenCampaignOfAgent :one
SELECT * FROM pc.campaigns WHERE org_id = sqlc.arg(org_id) AND range_agent_id = sqlc.arg(range_agent_id) AND state = 'RUNNING';

-- name: ListCampaigns :many
SELECT * FROM pc.campaigns
WHERE org_id = sqlc.arg(org_id)
  AND (sqlc.narg(range_agent_id)::uuid IS NULL OR range_agent_id = sqlc.narg(range_agent_id))
  AND (coalesce(sqlc.arg(before)::uuid, '00000000-0000-0000-0000-000000000000') = '00000000-0000-0000-0000-000000000000' OR id < sqlc.arg(before))
ORDER BY id DESC
LIMIT sqlc.arg(page_limit);

-- A conditional state change: nothing happens unless the campaign still runs.
-- name: TransitionCampaign :one
UPDATE pc.campaigns SET state = sqlc.arg(state)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'RUNNING'
RETURNING finished_at;

-- Campaigns still running after 24 hours, oldest first, locked for the sweep.
-- name: StaleCampaigns :many
SELECT * FROM pc.campaigns
WHERE org_id = sqlc.arg(org_id) AND state = 'RUNNING' AND started_at <= now() - interval '24 hours'
ORDER BY started_at, id
LIMIT sqlc.arg(max_rows)
FOR UPDATE SKIP LOCKED;

-- name: InsertCampaignStep :exec
INSERT INTO pc.campaign_steps (org_id, campaign_id, scenario_id, step_id, boundary, expected, outcome, basis, transaction_id,
    reason, route_locator)
VALUES (sqlc.arg(org_id), sqlc.arg(campaign_id), sqlc.arg(scenario_id), sqlc.arg(step_id), sqlc.arg(boundary),
    sqlc.arg(expected), sqlc.arg(outcome), sqlc.arg(basis), sqlc.narg(transaction_id), sqlc.arg(reason), sqlc.arg(route_locator));

-- name: ListCampaignSteps :many
SELECT * FROM pc.campaign_steps
WHERE org_id = sqlc.arg(org_id) AND campaign_id = sqlc.arg(campaign_id)
ORDER BY scenario_id, recorded_at, step_id;

-- Finished campaigns by finish time, for compliance evidence (D312).
-- name: FinishedCampaigns :many
SELECT * FROM pc.campaigns
WHERE org_id = sqlc.arg(org_id) AND state = 'FINISHED'
  AND finished_at >= sqlc.arg(from_time) AND finished_at < sqlc.arg(to_time)
  AND (sqlc.narg(range_agent_id)::uuid IS NULL OR range_agent_id = sqlc.narg(range_agent_id))
ORDER BY finished_at, id
LIMIT sqlc.arg(page_limit);

-- name: CampaignStepOutcomes :many
SELECT campaign_id, outcome, count(*)::int AS steps FROM pc.campaign_steps
WHERE org_id = sqlc.arg(org_id) AND campaign_id = ANY(sqlc.arg(campaign_ids)::uuid[])
GROUP BY campaign_id, outcome;

-- A run as a campaign needs it: its agent, whether it is simulated, when it
-- was created.
-- name: CampaignRunRecord :one
SELECT id, agent_id, simulated, created_at FROM pc.runs
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- A run's transactions: the server's own records behind every outcome. The
-- limit bounds one run; the campaign's attempts look at them all.
-- name: CampaignRunTransactions :many
SELECT t.id, t.operation, t.decision, t.reason_code, t.mode, t.simulated, t.created_at, coalesce(t.effect_state, '')::text AS effect_state
FROM pc.transactions t
WHERE t.org_id = sqlc.arg(org_id) AND t.run_id = sqlc.arg(run_id)
ORDER BY t.created_at, t.id
LIMIT 2000;

-- name: SetCampaignRunScenario :exec
INSERT INTO pc.campaign_runs (org_id, campaign_id, run_id, scenario_id, model_host)
VALUES (sqlc.arg(org_id), sqlc.arg(campaign_id), sqlc.arg(run_id), sqlc.arg(scenario_id), sqlc.arg(model_host))
ON CONFLICT (org_id, campaign_id, run_id) DO UPDATE SET scenario_id = EXCLUDED.scenario_id;

-- name: ListCampaignRuns :many
SELECT * FROM pc.campaign_runs
WHERE org_id = sqlc.arg(org_id) AND campaign_id = sqlc.arg(campaign_id)
ORDER BY run_id;
