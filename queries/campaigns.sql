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

-- The worst simulated transaction for each of the operations, over every
-- run bound to a step (D525 M2): the server's own records behind every
-- outcome, with no row cap. The order is domain.Transaction.stopped's: an
-- allowed, monitored or effective action first, then a held one, then a
-- denied one. One row per operation comes back.
-- name: CampaignWorstTransactions :many
SELECT DISTINCT ON (t.operation) t.id, t.operation, t.decision, t.reason_code, t.mode, t.simulated, t.created_at,
    coalesce(t.effect_state, '')::text AS effect_state
FROM pc.transactions t
WHERE t.org_id = sqlc.arg(org_id) AND t.run_id = ANY (sqlc.arg(run_ids)::uuid[])
  AND t.operation = ANY (sqlc.arg(operations)::text[]) AND t.simulated
ORDER BY t.operation,
    CASE
        WHEN t.mode::text = 'monitor' OR coalesce(t.effect_state::text, '') NOT IN ('', 'NONE_CONFIRMED') THEN 3
        WHEN t.decision::text IN ('REQUIRE_APPROVAL', 'REQUIRE_STEP_UP') THEN 2
        WHEN t.decision::text IN ('DENY', 'CANNOT_AUTHORIZE') THEN 1
        ELSE 3
    END DESC, t.created_at, t.id;

-- Opens a step: runs of the twin created from now on bind to it (D525 M1).
-- name: OpenCampaignStep :execrows
UPDATE pc.campaigns SET open_step = sqlc.arg(scenario_id)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'RUNNING';

-- The runs the server bound to a campaign's steps.
-- name: CampaignBoundRuns :many
SELECT run_id, scenario_id FROM pc.campaign_runs
WHERE org_id = sqlc.arg(org_id) AND campaign_id = sqlc.arg(campaign_id)
ORDER BY scenario_id, run_id;

-- The edge's stored route reports for a step, at most max_rows.
-- name: CampaignStepRoutes :many
SELECT kind, locator FROM pc.campaign_routes
WHERE org_id = sqlc.arg(org_id) AND campaign_id = sqlc.arg(campaign_id) AND scenario_id = sqlc.arg(scenario_id)
ORDER BY recorded_at, locator
LIMIT sqlc.arg(max_rows);

-- Stores one route of a twin's report on its open campaign's open step, if
-- any (D525 L6).
-- name: InsertCampaignRoute :execrows
INSERT INTO pc.campaign_routes (org_id, campaign_id, scenario_id, kind, locator)
SELECT c.org_id, c.id, c.open_step, sqlc.arg(kind)::text, sqlc.arg(locator)::text
FROM pc.campaigns c
WHERE c.org_id = sqlc.arg(org_id) AND c.range_agent_id = sqlc.arg(range_agent_id) AND c.state = 'RUNNING'
  AND c.open_step IS NOT NULL;

-- name: ListCampaignRuns :many
SELECT * FROM pc.campaign_runs
WHERE org_id = sqlc.arg(org_id) AND campaign_id = sqlc.arg(campaign_id)
ORDER BY run_id;

-- A connection as the model route needs it (D313).
-- name: CampaignRelayConnection :one
SELECT gateway_id, simulated, model_relay, state FROM pc.connections
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- One model request of a bound run (D313): counted before it is sent, with
-- the most its answer may bring reserved (D525 L2), so the count holds
-- whatever becomes of the answer and concurrent calls never pass the total.
-- No row comes back for a run the server did not bind, or when the bytes
-- would take the run past its total.
-- name: AddModelRequest :one
UPDATE pc.campaign_runs
SET requests = requests + 1, bytes_to_model = bytes_to_model + sqlc.arg(bytes), bytes_reserved = bytes_reserved + sqlc.arg(reserve)
WHERE org_id = sqlc.arg(org_id) AND campaign_id = sqlc.arg(campaign_id) AND run_id = sqlc.arg(run_id)
  AND bytes_to_model + bytes_from_model + bytes_reserved + sqlc.arg(bytes) + sqlc.arg(reserve) <= sqlc.arg(run_total)
RETURNING requests;

-- An answer's bytes, settling the reservation its request made.
-- name: AddModelAnswer :execrows
UPDATE pc.campaign_runs
SET bytes_from_model = bytes_from_model + sqlc.arg(bytes), bytes_reserved = greatest(bytes_reserved - sqlc.arg(reserve), 0)
WHERE org_id = sqlc.arg(org_id) AND campaign_id = sqlc.arg(campaign_id) AND run_id = sqlc.arg(run_id);
