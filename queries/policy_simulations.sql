-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Historical policy simulation (G0 M11.1 D15; migration 00113; HR-232,
-- HR-237). Everything runs as pc_app in a tenant transaction. The window
-- is the database's: it ends when the simulation is asked for.

-- name: InsertPolicySimulation :one
INSERT INTO pc.policy_simulations (org_id, id, version_id, content_digest, window_start, window_end, max_evaluations, requested_by,
    cohort_id, cohort_agents)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(version_id), sqlc.arg(content_digest),
    now() - make_interval(days => sqlc.arg(days)::integer), now(), sqlc.arg(max_evaluations), sqlc.arg(requested_by),
    sqlc.narg(cohort_id)::uuid, sqlc.narg(cohort_agents)::uuid[])
RETURNING *;

-- How many days back recorded decisions can still be replayed: the shorter
-- of the replay inputs' (normalized_facts) and the receipts' retention in
-- effect now, or their defaults when the org never recorded one.
-- name: SimulationRetentionDays :one
SELECT LEAST(
    coalesce((SELECT days FROM pc.retention_current('normalized_facts', now())), sqlc.arg(facts_default)::integer),
    coalesce((SELECT days FROM pc.retention_current('receipts', now())), sqlc.arg(receipts_default)::integer))::integer AS days;

-- name: GetPolicySimulation :one
SELECT * FROM pc.policy_simulations WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: LockPolicySimulation :one
SELECT * FROM pc.policy_simulations WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) FOR UPDATE;

-- name: ListPolicySimulations :many
SELECT * FROM pc.policy_simulations
WHERE org_id = sqlc.arg(org_id)
  AND (sqlc.narg(before)::uuid IS NULL OR id < sqlc.narg(before))
ORDER BY id DESC
LIMIT sqlc.arg(page_limit);

-- A conditional start: nothing happens unless the simulation is queued.
-- name: StartPolicySimulation :one
UPDATE pc.policy_simulations SET state = 'RUNNING'
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'QUEUED'
RETURNING *;

-- Records progress, or finishes (DONE or FAILED), while it runs. It is a
-- compare-and-set (D34): nothing changes unless the simulation is still
-- at the count and cursor the step read, so a chunk two steps read from
-- one position is counted once.
-- name: AdvancePolicySimulation :one
UPDATE pc.policy_simulations
SET state = sqlc.arg(state), evaluated = sqlc.arg(evaluated), counts = sqlc.arg(counts), by_workflow = sqlc.arg(by_workflow),
    burden = sqlc.arg(burden), by_cohort = sqlc.arg(by_cohort), cursor_created_at = sqlc.narg(cursor_created_at), cursor_txn = sqlc.narg(cursor_txn),
    cursor_evaluation = sqlc.narg(cursor_evaluation), error = sqlc.narg(error)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'RUNNING'
  AND evaluated = sqlc.arg(prev_evaluated)
  AND cursor_txn IS NOT DISTINCT FROM sqlc.narg(prev_cursor_txn)
  AND cursor_evaluation IS NOT DISTINCT FROM sqlc.narg(prev_cursor_evaluation)
RETURNING *;

-- name: CancelPolicySimulation :one
UPDATE pc.policy_simulations SET state = 'CANCELLED'
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state IN ('QUEUED', 'RUNNING')
RETURNING *;

-- The next recorded decisions of a window, newest first, after the
-- cursor: ids, the agent and the operation only; for a cohort simulation,
-- only those of its snapshotted agents (00221).
-- name: SimulationReceipts :many
SELECT d.transaction_id, d.evaluation, d.created_at, r.agent_id, t.operation
FROM pc.decision_receipts d
JOIN pc.transactions t ON t.org_id = d.org_id AND t.id = d.transaction_id
JOIN pc.runs r ON r.org_id = t.org_id AND r.id = t.run_id
WHERE d.org_id = sqlc.arg(org_id)
  AND d.created_at >= sqlc.arg(window_start) AND d.created_at <= sqlc.arg(window_end)
  AND (sqlc.narg(cohort_agents)::uuid[] IS NULL OR r.agent_id = ANY (sqlc.narg(cohort_agents)::uuid[]))
  AND (sqlc.narg(cursor_created_at)::timestamptz IS NULL
       OR (d.created_at, d.transaction_id, d.evaluation) < (sqlc.narg(cursor_created_at)::timestamptz, sqlc.narg(cursor_txn)::uuid,
                                                            sqlc.narg(cursor_evaluation)::integer))
ORDER BY d.created_at DESC, d.transaction_id DESC, d.evaluation DESC
LIMIT sqlc.arg(page_limit);

-- name: SimulationSampleCounts :many
SELECT category, operation, count(*)::integer AS n
FROM pc.policy_simulation_samples
WHERE org_id = sqlc.arg(org_id) AND simulation_id = sqlc.arg(simulation_id)
GROUP BY category, operation;

-- A sample already recorded (a chunk counted again after a retry) is kept.
-- name: InsertSimulationSample :exec
INSERT INTO pc.policy_simulation_samples (org_id, simulation_id, category, transaction_id, evaluation, agent_id, operation,
    original_decision, original_reason, proposed_decision, proposed_reason, limitation)
VALUES (sqlc.arg(org_id), sqlc.arg(simulation_id), sqlc.arg(category), sqlc.arg(transaction_id), sqlc.arg(evaluation),
    sqlc.arg(agent_id), sqlc.arg(operation), sqlc.arg(original_decision), sqlc.arg(original_reason),
    sqlc.arg(proposed_decision), sqlc.arg(proposed_reason), sqlc.arg(limitation))
ON CONFLICT (org_id, simulation_id, transaction_id, evaluation) DO NOTHING;

-- name: ListSimulationSamples :many
SELECT * FROM pc.policy_simulation_samples
WHERE org_id = sqlc.arg(org_id) AND simulation_id = sqlc.arg(simulation_id)
  AND (sqlc.arg(category)::text = '' OR category = sqlc.arg(category))
  AND (sqlc.arg(operation)::text = '' OR operation = sqlc.arg(operation))
  AND (sqlc.narg(after_txn)::uuid IS NULL
       OR (transaction_id, evaluation) > (sqlc.narg(after_txn)::uuid, sqlc.arg(after_evaluation)::integer))
ORDER BY transaction_id, evaluation
LIMIT sqlc.arg(page_limit);
