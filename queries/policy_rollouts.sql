-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Policy rollouts, pilot cohorts, per-agent targets and shadow results (G0
-- M11.1, D12, D13). The Authority reads only the pilot selection; the
-- rollout service and its sweeper write the rest.

-- The pilot rollout whose ENFORCE cohorts hold the agent and that did not
-- exclude it, with the version it enforces (the Authority's selection,
-- HR-234). At most one rollout per org is in PILOT.
-- name: PilotRolloutForAgent :one
SELECT r.id, r.version_id
FROM pc.policy_rollouts r
WHERE r.org_id = sqlc.arg(org_id) AND r.stage = 'PILOT'
  AND EXISTS (SELECT 1 FROM pc.policy_rollout_cohorts rc
              JOIN pc.policy_cohort_members m ON m.org_id = rc.org_id AND m.cohort_id = rc.cohort_id
              WHERE rc.org_id = r.org_id AND rc.rollout_id = r.id AND rc.mode = 'ENFORCE' AND m.agent_id = sqlc.arg(agent_id))
  AND NOT EXISTS (SELECT 1 FROM pc.policy_rollout_targets t
                  WHERE t.org_id = r.org_id AND t.rollout_id = r.id AND t.agent_id = sqlc.arg(agent_id) AND t.state = 'EXCEPTION');

-- name: GetPolicyVersionBundle :one
SELECT v.bundle, v.state FROM pc.policy_versions v WHERE v.org_id = sqlc.arg(org_id) AND v.id = sqlc.arg(id);

-- name: InsertPolicyCohort :one
INSERT INTO pc.policy_cohorts (org_id, id, name, created_by)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(name), sqlc.arg(created_by))
RETURNING *;

-- name: GetPolicyCohortByName :one
SELECT * FROM pc.policy_cohorts WHERE org_id = sqlc.arg(org_id) AND name = sqlc.arg(name);

-- name: ListPolicyCohorts :many
SELECT * FROM pc.policy_cohorts WHERE org_id = sqlc.arg(org_id) ORDER BY name LIMIT sqlc.arg(max_rows);

-- name: AddPolicyCohortMember :execrows
INSERT INTO pc.policy_cohort_members (org_id, cohort_id, agent_id, added_by)
VALUES (sqlc.arg(org_id), sqlc.arg(cohort_id), sqlc.arg(agent_id), sqlc.arg(added_by))
ON CONFLICT DO NOTHING;

-- name: RemovePolicyCohortMember :execrows
DELETE FROM pc.policy_cohort_members
WHERE org_id = sqlc.arg(org_id) AND cohort_id = sqlc.arg(cohort_id) AND agent_id = sqlc.arg(agent_id);

-- name: ListPolicyCohortMembers :many
SELECT agent_id FROM pc.policy_cohort_members
WHERE org_id = sqlc.arg(org_id) AND cohort_id = sqlc.arg(cohort_id)
ORDER BY agent_id;

-- name: InsertPolicyRollout :one
INSERT INTO pc.policy_rollouts (org_id, id, version_id, base_version_id, stage, created_by)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(version_id), sqlc.narg(base_version_id), sqlc.arg(stage), sqlc.arg(created_by))
RETURNING *;

-- name: GetPolicyRollout :one
SELECT * FROM pc.policy_rollouts WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- The rollout, locked until the transaction ends, so stage changes of one
-- rollout are serialized.
-- name: LockPolicyRollout :one
SELECT * FROM pc.policy_rollouts WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) FOR UPDATE;

-- name: ListPolicyRollouts :many
SELECT * FROM pc.policy_rollouts WHERE org_id = sqlc.arg(org_id) ORDER BY created_at DESC, id DESC LIMIT sqlc.arg(max_rows);

-- Rollouts the sweeper works on: in SHADOW or PILOT, or completed less than
-- 7 days ago with targets not VERIFIED (the lister's policy_rollouts_due).
-- name: DuePolicyRollouts :many
SELECT * FROM pc.policy_rollouts r
WHERE r.org_id = sqlc.arg(org_id)
  AND (r.stage IN ('SHADOW', 'PILOT')
       OR (r.stage = 'COMPLETE' AND r.completed_at > now() - interval '7 days'
           AND EXISTS (SELECT 1 FROM pc.policy_rollout_targets t
                       WHERE t.org_id = r.org_id AND t.rollout_id = r.id AND t.state <> 'VERIFIED')))
ORDER BY r.created_at, r.id;

-- A conditional stage change (HR-004): only from the stages given.
-- name: SetPolicyRolloutStage :one
UPDATE pc.policy_rollouts SET stage = sqlc.arg(stage)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND stage = ANY (sqlc.arg(from_stages)::text[])
RETURNING *;

-- name: SetPolicyRolloutBase :exec
UPDATE pc.policy_rollouts SET base_version_id = sqlc.narg(base_version_id)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: SetPolicyRolloutCohort :exec
INSERT INTO pc.policy_rollout_cohorts (org_id, rollout_id, cohort_id, mode)
VALUES (sqlc.arg(org_id), sqlc.arg(rollout_id), sqlc.arg(cohort_id), sqlc.arg(mode))
ON CONFLICT (org_id, rollout_id, cohort_id) DO UPDATE SET mode = EXCLUDED.mode;

-- name: ListPolicyRolloutCohorts :many
SELECT rc.cohort_id, rc.mode, c.name, c.members
FROM pc.policy_rollout_cohorts rc
JOIN pc.policy_cohorts c ON c.org_id = rc.org_id AND c.id = rc.cohort_id
WHERE rc.org_id = sqlc.arg(org_id) AND rc.rollout_id = sqlc.arg(rollout_id)
ORDER BY c.name;

-- Targets for every agent of the rollout's ENFORCE cohorts that has none
-- yet, CONFIGURED, with the agent's owner (F3). Retired agents are left out.
-- name: AddCohortRolloutTargets :execrows
INSERT INTO pc.policy_rollout_targets (org_id, rollout_id, agent_id, state, owner_id)
SELECT DISTINCT rc.org_id, rc.rollout_id, m.agent_id, 'CONFIGURED', a.owner_user_id
FROM pc.policy_rollout_cohorts rc
JOIN pc.policy_cohort_members m ON m.org_id = rc.org_id AND m.cohort_id = rc.cohort_id
JOIN pc.agents a ON a.org_id = m.org_id AND a.id = m.agent_id
WHERE rc.org_id = sqlc.arg(org_id) AND rc.rollout_id = sqlc.arg(rollout_id) AND rc.mode = 'ENFORCE' AND a.state <> 'RETIRED'
ON CONFLICT DO NOTHING;

-- Targets for every agent of the org that has none yet (a completed
-- rollout: the version is published for everyone).
-- name: AddAllRolloutTargets :execrows
INSERT INTO pc.policy_rollout_targets (org_id, rollout_id, agent_id, state, owner_id)
SELECT a.org_id, sqlc.arg(rollout_id), a.id, 'CONFIGURED', a.owner_user_id
FROM pc.agents a
WHERE a.org_id = sqlc.arg(org_id) AND a.state <> 'RETIRED'
ON CONFLICT DO NOTHING;

-- An agent excluded from a rollout: it stays on the published version.
-- name: ExcludeRolloutTarget :one
INSERT INTO pc.policy_rollout_targets (org_id, rollout_id, agent_id, state, owner_id, reason)
SELECT a.org_id, sqlc.arg(rollout_id), a.id, 'EXCEPTION', a.owner_user_id, sqlc.arg(reason)
FROM pc.agents a WHERE a.org_id = sqlc.arg(org_id) AND a.id = sqlc.arg(agent_id)
ON CONFLICT (org_id, rollout_id, agent_id)
    DO UPDATE SET state = 'EXCEPTION', reason = EXCLUDED.reason, coverage = NULL, updated_at = now()
RETURNING *;

-- A conditional target change (HR-004): only from the states given.
-- name: SetRolloutTargetState :execrows
UPDATE pc.policy_rollout_targets
SET state = sqlc.arg(state), coverage = sqlc.narg(coverage), reason = sqlc.narg(reason), updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND rollout_id = sqlc.arg(rollout_id) AND agent_id = sqlc.arg(agent_id)
  AND state = ANY (sqlc.arg(from_states)::text[]);

-- name: GetRolloutTarget :one
SELECT * FROM pc.policy_rollout_targets
WHERE org_id = sqlc.arg(org_id) AND rollout_id = sqlc.arg(rollout_id) AND agent_id = sqlc.arg(agent_id);

-- name: ListRolloutTargets :many
SELECT * FROM pc.policy_rollout_targets
WHERE org_id = sqlc.arg(org_id) AND rollout_id = sqlc.arg(rollout_id)
  AND (sqlc.narg(state)::text IS NULL OR state = sqlc.narg(state)::text)
  AND agent_id > sqlc.arg(after_agent)
ORDER BY agent_id
LIMIT sqlc.arg(max_rows);

-- Targets the sweeper may advance to VERIFIED.
-- name: AcknowledgedRolloutTargets :many
SELECT * FROM pc.policy_rollout_targets
WHERE org_id = sqlc.arg(org_id) AND rollout_id = sqlc.arg(rollout_id) AND state = 'ACKNOWLEDGED'
ORDER BY updated_at, agent_id
LIMIT sqlc.arg(max_rows);

-- name: CountRolloutTargets :many
SELECT state, count(*)::bigint AS n FROM pc.policy_rollout_targets
WHERE org_id = sqlc.arg(org_id) AND rollout_id = sqlc.arg(rollout_id)
GROUP BY state ORDER BY state;

-- name: GetRolloutCursor :one
SELECT last_created_at, last_txn FROM pc.policy_rollout_cursors
WHERE org_id = sqlc.arg(org_id) AND rollout_id = sqlc.arg(rollout_id);

-- name: SetRolloutCursor :exec
INSERT INTO pc.policy_rollout_cursors (org_id, rollout_id, last_created_at, last_txn)
VALUES (sqlc.arg(org_id), sqlc.arg(rollout_id), sqlc.arg(last_created_at), sqlc.arg(last_txn))
ON CONFLICT (org_id, rollout_id) DO UPDATE SET last_created_at = EXCLUDED.last_created_at, last_txn = EXCLUDED.last_txn;

-- Decisions after a cursor, oldest first, with the agent of their run and
-- their operation. Only decisions older than the lag (a minute in
-- production) are read, so one whose transaction committed late is not
-- passed over; receipts whose body retention removed have nothing to
-- replay or read.
-- name: RolloutDecisionsAfter :many
SELECT d.transaction_id, d.evaluation, d.created_at, r.agent_id, t.operation
FROM pc.decision_receipts d
JOIN pc.transactions t ON t.org_id = d.org_id AND t.id = d.transaction_id
JOIN pc.runs r ON r.org_id = t.org_id AND r.id = t.run_id
WHERE d.org_id = sqlc.arg(org_id) AND d.body_removed_at IS NULL
  AND d.created_at <= now() - make_interval(secs => sqlc.arg(lag_seconds)::double precision)
  AND (d.created_at, d.transaction_id) > (sqlc.arg(after_created_at)::timestamptz, sqlc.arg(after_txn)::uuid)
ORDER BY d.created_at, d.transaction_id, d.evaluation
LIMIT sqlc.arg(max_rows);

-- name: InsertShadowResult :execrows
INSERT INTO pc.policy_shadow_results (org_id, rollout_id, transaction_id, evaluation, agent_id, operation, original_decision,
    original_reason, shadow_decision, shadow_reason, category, limitation)
VALUES (sqlc.arg(org_id), sqlc.arg(rollout_id), sqlc.arg(transaction_id), sqlc.arg(evaluation), sqlc.arg(agent_id),
    sqlc.arg(operation), sqlc.arg(original_decision), sqlc.arg(original_reason), sqlc.narg(shadow_decision),
    sqlc.narg(shadow_reason), sqlc.arg(category), sqlc.narg(limitation))
ON CONFLICT DO NOTHING;

-- name: CountShadowResults :one
SELECT count(*)::bigint FROM pc.policy_shadow_results WHERE org_id = sqlc.arg(org_id) AND rollout_id = sqlc.arg(rollout_id);

-- name: AddShadowCount :exec
INSERT INTO pc.policy_shadow_counts (org_id, rollout_id, day, category, n)
VALUES (sqlc.arg(org_id), sqlc.arg(rollout_id), (now() AT TIME ZONE 'UTC')::date, sqlc.arg(category), 1)
ON CONFLICT (org_id, rollout_id, day, category) DO UPDATE SET n = pc.policy_shadow_counts.n + 1;

-- name: ShadowCountsByDay :many
SELECT day, category, n FROM pc.policy_shadow_counts
WHERE org_id = sqlc.arg(org_id) AND rollout_id = sqlc.arg(rollout_id)
ORDER BY day, category;

-- name: ShadowResultsByOperation :many
SELECT operation, category, count(*)::bigint AS n FROM pc.policy_shadow_results
WHERE org_id = sqlc.arg(org_id) AND rollout_id = sqlc.arg(rollout_id)
GROUP BY operation, category ORDER BY operation, category;

-- name: ShadowResultsByAgent :many
SELECT agent_id, category, count(*)::bigint AS n FROM pc.policy_shadow_results
WHERE org_id = sqlc.arg(org_id) AND rollout_id = sqlc.arg(rollout_id)
GROUP BY agent_id, category ORDER BY agent_id, category;

-- The newest results of each changed category: ids, decisions and reasons
-- only (HR-237).
-- name: ShadowSamples :many
SELECT transaction_id, evaluation, agent_id, operation, original_decision, original_reason, shadow_decision, shadow_reason,
    category, limitation, created_at
FROM (SELECT s.*, row_number() OVER (PARTITION BY s.category ORDER BY s.created_at DESC, s.transaction_id DESC) AS rn
      FROM pc.policy_shadow_results s
      WHERE s.org_id = sqlc.arg(org_id) AND s.rollout_id = sqlc.arg(rollout_id) AND s.category <> 'UNCHANGED') x
WHERE x.rn <= sqlc.arg(per_category)::bigint
ORDER BY category, created_at DESC;

-- The latest coverage snapshot of each (connection, operation) of an
-- agent (D12's VERIFIED check).
-- name: LatestAgentCoverage :many
SELECT DISTINCT ON (s.connection_id, s.operation) s.connection_id, s.operation, s.state, s.expires_at,
    (s.expires_at IS NOT NULL AND s.expires_at <= now())::boolean AS expired
FROM pc.coverage_snapshots s
WHERE s.org_id = sqlc.arg(org_id) AND s.agent_id = sqlc.arg(agent_id)
ORDER BY s.connection_id, s.operation, s.id DESC;

-- name: RolloutAgentOwner :one
SELECT owner_user_id, name FROM pc.agents WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);
