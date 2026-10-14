-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Adversarial ranges (G0 M12 W5; migration 00097; HR-224). Everything runs
-- as pc_app in a tenant transaction. Results are only inserted (HR-055); a
-- range changes once, from RUNNING.

-- name: InsertRedteamRun :one
INSERT INTO pc.redteam_runs (org_id, id, range_agent_id, started_by, runner_version, scenario_set_digest, scenarios,
    policy_versions, package_versions, baseline_range_id)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(range_agent_id), sqlc.arg(started_by), sqlc.arg(runner_version),
    sqlc.arg(scenario_set_digest), sqlc.arg(scenarios), sqlc.arg(policy_versions), sqlc.arg(package_versions),
    sqlc.narg(baseline_range_id))
RETURNING *;

-- name: GetRedteamRun :one
SELECT * FROM pc.redteam_runs WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- The range row is locked while a result is recorded or the range finishes.
-- name: LockRedteamRun :one
SELECT * FROM pc.redteam_runs WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) FOR UPDATE;

-- name: ListRedteamRuns :many
SELECT * FROM pc.redteam_runs
WHERE org_id = sqlc.arg(org_id)
  AND (sqlc.narg(range_agent_id)::uuid IS NULL OR range_agent_id = sqlc.narg(range_agent_id))
  AND (sqlc.arg(before)::uuid = '00000000-0000-0000-0000-000000000000'::uuid OR id < sqlc.arg(before))
ORDER BY id DESC
LIMIT sqlc.arg(page_limit);

-- A conditional state change: nothing happens unless the range still runs.
-- name: TransitionRedteamRun :one
UPDATE pc.redteam_runs SET state = sqlc.arg(state)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'RUNNING'
RETURNING finished_at;

-- Ranges still running after 24 hours, oldest first, locked for the sweep.
-- name: StaleRedteamRuns :many
SELECT * FROM pc.redteam_runs
WHERE org_id = sqlc.arg(org_id) AND state = 'RUNNING' AND started_at <= now() - interval '24 hours'
ORDER BY started_at, id
LIMIT sqlc.arg(max_rows)
FOR UPDATE SKIP LOCKED;

-- name: InsertRedteamResult :one
INSERT INTO pc.redteam_results (org_id, range_id, scenario_id, scenario_digest, title, suite, category, tier, verdict,
    claimed_verdict, steps, observed_by, mismatches)
VALUES (sqlc.arg(org_id), sqlc.arg(range_id), sqlc.arg(scenario_id), sqlc.arg(scenario_digest), sqlc.arg(title),
    sqlc.arg(suite), sqlc.arg(category), sqlc.arg(tier), sqlc.arg(verdict), sqlc.narg(claimed_verdict), sqlc.arg(steps),
    sqlc.arg(observed_by), sqlc.arg(mismatches))
ON CONFLICT (org_id, range_id, scenario_id) DO NOTHING
RETURNING recorded_at;

-- name: RedteamResults :many
SELECT * FROM pc.redteam_results
WHERE org_id = sqlc.arg(org_id) AND range_id = sqlc.arg(range_id)
ORDER BY recorded_at, scenario_id;

-- The server's own record of a transaction a step names: its run's agent,
-- the simulated flag, its decision and effect.
-- name: RangeTransaction :one
SELECT t.id, r.agent_id, t.simulated, t.created_at, t.decision, t.reason_code, coalesce(t.effect_state, '')::text AS effect_state,
    coalesce(d.receipt_jws, '')::text AS receipt_jws
FROM pc.transactions t
JOIN pc.runs r ON r.org_id = t.org_id AND r.id = t.run_id
LEFT JOIN pc.decision_receipts d ON d.org_id = t.org_id AND d.transaction_id = t.id
WHERE t.org_id = sqlc.arg(org_id) AND t.id = sqlc.arg(id);

-- A stored probe report: the session's agent and the report as signed.
-- name: RangeProbeReport :one
SELECT p.id, s.agent_id, p.received_at, p.report
FROM pc.probe_runs p
JOIN pc.sandbox_sessions s ON s.org_id = p.org_id AND s.id = p.session_id
WHERE p.org_id = sqlc.arg(org_id) AND p.id = sqlc.arg(id);

-- The policy version in force and the pinned packages, as a range starts.
-- name: RangePolicyVersions :many
SELECT p.bundle_id AS name, v.version::text AS version, v.id::text AS id
FROM pc.policy_versions v
JOIN pc.policies p ON p.org_id = v.org_id AND p.id = v.policy_id
WHERE v.org_id = sqlc.arg(org_id) AND v.state = 'PUBLISHED'
ORDER BY p.bundle_id;

-- name: RangePackageVersions :many
SELECT tp.name AS name, pp.version AS version, pp.version_id::text AS id
FROM pc.package_pins pp
JOIN pc.tool_packages tp ON tp.org_id = pp.org_id AND tp.id = pp.package_id
WHERE pp.org_id = sqlc.arg(org_id)
ORDER BY tp.name;
