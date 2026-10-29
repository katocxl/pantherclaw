-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Evidence-backed policy suggestions (G0 M16 D90–D92) and the evidence
-- their generation reads.

-- name: InsertPolicySuggestion :one
INSERT INTO pc.policy_suggestions (org_id, id, kind, posture_finding_id, grant_id, agent_id, owners, window_from, window_to,
    observed, coverage_limits, proposed, expected_effect, uncertainty, uncertainty_reasons)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(kind), sqlc.arg(posture_finding_id), sqlc.arg(grant_id), sqlc.arg(agent_id),
    sqlc.arg(owners), sqlc.arg(window_from), sqlc.arg(window_to), sqlc.arg(observed), sqlc.arg(coverage_limits), sqlc.arg(proposed),
    sqlc.arg(expected_effect), sqlc.arg(uncertainty), sqlc.arg(uncertainty_reasons))
RETURNING *;

-- RefreshPolicySuggestion replaces an OPEN suggestion's evidence.
-- name: RefreshPolicySuggestion :one
UPDATE pc.policy_suggestions SET owners = sqlc.arg(owners), window_from = sqlc.arg(window_from), window_to = sqlc.arg(window_to),
    observed = sqlc.arg(observed), coverage_limits = sqlc.arg(coverage_limits), proposed = sqlc.arg(proposed),
    expected_effect = sqlc.arg(expected_effect), uncertainty = sqlc.arg(uncertainty), uncertainty_reasons = sqlc.arg(uncertainty_reasons)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'OPEN'
RETURNING *;

-- SuggestionFinding reads the posture finding a generation follows,
-- share-locked: a reconciliation that moves it waits for the generation,
-- or the generation waits for it and reads the new state (D91).
-- name: SuggestionFinding :one
SELECT * FROM pc.posture_findings WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) FOR SHARE;

-- LatestPolicySuggestionForFinding is a finding's newest suggestion,
-- locked.
-- name: LatestPolicySuggestionForFinding :one
SELECT * FROM pc.policy_suggestions
WHERE org_id = sqlc.arg(org_id) AND posture_finding_id = sqlc.arg(posture_finding_id)
ORDER BY id DESC
LIMIT 1
FOR UPDATE;

-- StalePolicySuggestions marks a resolved finding's open and drafted
-- suggestions STALE.
-- name: StalePolicySuggestions :execrows
UPDATE pc.policy_suggestions SET state = 'STALE'
WHERE org_id = sqlc.arg(org_id) AND posture_finding_id = sqlc.arg(posture_finding_id) AND state IN ('OPEN', 'DRAFTED');

-- EndPolicySuggestionDismissals records a finding's remediation on its
-- dismissed suggestions that have none yet: their dismissal ends with it.
-- name: EndPolicySuggestionDismissals :execrows
UPDATE pc.policy_suggestions SET finding_remediated_at = now()
WHERE org_id = sqlc.arg(org_id) AND posture_finding_id = sqlc.arg(posture_finding_id) AND state = 'DISMISSED'
  AND finding_remediated_at IS NULL;

-- name: GetPolicySuggestion :one
SELECT * FROM pc.policy_suggestions WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: LockPolicySuggestion :one
SELECT * FROM pc.policy_suggestions WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) FOR UPDATE;

-- ListPolicySuggestions lists suggestions newest first, filtered in SQL by
-- the agents the caller may see before a page is cut (HR-444).
-- name: ListPolicySuggestions :many
SELECT * FROM pc.policy_suggestions
WHERE org_id = sqlc.arg(org_id)
  AND (cardinality(sqlc.arg(states)::text[]) = 0 OR state = ANY (sqlc.arg(states)::text[]))
  AND (sqlc.narg(kind)::text IS NULL OR kind = sqlc.narg(kind)::text)
  AND (sqlc.narg(before)::uuid IS NULL OR id < sqlc.narg(before)::uuid)
  AND (sqlc.arg(all_agents)::boolean OR agent_id = ANY (sqlc.arg(agent_ids)::uuid[]))
ORDER BY id DESC
LIMIT sqlc.arg(max_rows);

-- name: DraftPolicySuggestion :one
UPDATE pc.policy_suggestions SET state = 'DRAFTED', draft_policy_version_id = sqlc.arg(draft_policy_version_id)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'OPEN'
RETURNING *;

-- name: DismissPolicySuggestion :one
UPDATE pc.policy_suggestions SET state = 'DISMISSED', dismissed_by = sqlc.arg(dismissed_by), dismiss_reason = sqlc.arg(dismiss_reason)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'OPEN'
RETURNING *;

-- SuggestionGrantRoutes lists the routes (agent, connection, operation)
-- a grant reaches in a snapshot's effective view.
-- name: SuggestionGrantRoutes :many
SELECT DISTINCT agent_id::uuid AS agent_id, connection_id::uuid AS connection_id, operation::text AS operation
FROM pc.exposure_rights
WHERE org_id = sqlc.arg(org_id) AND snapshot_id = sqlc.arg(snapshot_id) AND grant_id = sqlc.arg(grant_id)
  AND reach_view = 'EFFECTIVE' AND agent_id IS NOT NULL AND connection_id IS NOT NULL AND operation IS NOT NULL
ORDER BY 1, 2, 3
LIMIT 1001;

-- SuggestionCoverageHistory is the coverage of the agents' paths over a
-- window: the snapshot in force at its start (the latest at or before it)
-- and every one computed inside it, oldest first per path.
-- name: SuggestionCoverageHistory :many
SELECT s.agent_id, s.connection_id, s.operation, s.state, s.computed_at, s.expires_at
FROM pc.coverage_snapshots s
WHERE s.org_id = sqlc.arg(org_id) AND s.agent_id = ANY (sqlc.arg(agent_ids)::uuid[])
  AND s.connection_id = ANY (sqlc.arg(connection_ids)::uuid[]) AND s.computed_at < sqlc.arg(window_to)
  AND (s.computed_at > sqlc.arg(window_from) OR s.id = (
      SELECT p.id FROM pc.coverage_snapshots p
      WHERE p.org_id = s.org_id AND p.agent_id = s.agent_id AND p.connection_id = s.connection_id AND p.operation = s.operation
        AND p.computed_at <= sqlc.arg(window_from)
      ORDER BY p.computed_at DESC, p.id DESC LIMIT 1))
ORDER BY s.agent_id, s.connection_id, s.operation, s.computed_at, s.id
LIMIT 20001;

-- SuggestionObserved counts a grant's recorded transactions per operation
-- in a window, most used first.
-- name: SuggestionObserved :many
SELECT operation, count(*)::bigint AS actions
FROM pc.transactions
WHERE org_id = sqlc.arg(org_id) AND grant_id = sqlc.arg(grant_id) AND NOT simulated
  AND created_at >= sqlc.arg(window_from) AND created_at < sqlc.arg(window_to)
GROUP BY operation
ORDER BY 2 DESC, 1
LIMIT 101;

-- SuggestionEffect counts an agent's recorded transactions in a window
-- that a FORBID over operations would match, and how many of them it did
-- not already deny.
-- name: SuggestionEffect :one
SELECT count(*)::bigint AS matching, count(*) FILTER (WHERE t.decision <> 'DENY')::bigint AS not_denied
FROM pc.transactions t
JOIN pc.runs r ON r.org_id = t.org_id AND r.id = t.run_id
WHERE t.org_id = sqlc.arg(org_id) AND r.agent_id = sqlc.arg(agent_id) AND NOT t.simulated
  AND t.operation = ANY (sqlc.arg(operations)::text[])
  AND t.created_at >= sqlc.arg(window_from) AND t.created_at < sqlc.arg(window_to);
