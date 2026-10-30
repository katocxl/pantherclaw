-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Aggregated findings per fleet cohort (G0 M18 D154, HR-480): query-only
-- counts over the cohort's agents the caller may read, which the caller
-- passes in (internal/cohorts filters them). No table of its own.

-- Open coverage findings of the agents.
-- name: CohortOpenCoverageFindings :one
SELECT count(*)::bigint AS n, count(DISTINCT agent_id)::bigint AS agents
FROM pc.coverage_findings
WHERE org_id = sqlc.arg(org_id) AND agent_id = ANY (sqlc.arg(agents)::uuid[]) AND state = 'OPEN';

-- FAILED targets of the agents in the rollouts the sweeper still follows:
-- open ones, and those completed in the last 7 days (00111).
-- name: CohortFailedRolloutTargets :one
SELECT count(*)::bigint AS n, count(DISTINCT t.agent_id)::bigint AS agents
FROM pc.policy_rollout_targets t
JOIN pc.policy_rollouts r ON r.org_id = t.org_id AND r.id = t.rollout_id
WHERE t.org_id = sqlc.arg(org_id) AND t.agent_id = ANY (sqlc.arg(agents)::uuid[]) AND t.state = 'FAILED'
  AND (r.stage IN ('SHADOW', 'PILOT') OR (r.stage = 'COMPLETE' AND r.completed_at > now() - interval '7 days'));

-- Exceptions of the agents that waive something now, by the database
-- clock.
-- name: CohortActiveExceptions :one
SELECT count(*)::bigint AS n, count(DISTINCT agent_id)::bigint AS agents
FROM pc.policy_exceptions
WHERE org_id = sqlc.arg(org_id) AND agent_id = ANY (sqlc.arg(agents)::uuid[]) AND state = 'ACTIVE' AND expires_at > now();
