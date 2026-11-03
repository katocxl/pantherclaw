-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Behaviour analytics (G0 M27 D502). It reads pc.transactions, never the
-- ledger, and real and simulated rows never meet in one result (HR-642).

-- name: BehaviorBatch :many
-- An org's transactions of one kind since the cursor, oldest first: a page
-- the rollup compares, then moves the cursor over (D526). Every decision is
-- read: an attempt is behaviour, though only a known action shapes a
-- profile.
SELECT t.id, t.run_id, r.agent_id, t.operation, t.connection_id,
       coalesce(c.destination_class, '')::text AS destination_class, t.created_at, t.decision, t.state, t.amount,
       t.currency
FROM pc.transactions t
JOIN pc.runs r ON r.org_id = t.org_id AND r.id = t.run_id
LEFT JOIN pc.connections c ON c.org_id = t.org_id AND c.id = t.connection_id
WHERE t.org_id = sqlc.arg(org_id) AND t.simulated = sqlc.arg(simulated)::boolean
  AND t.created_at >= sqlc.arg(since) AND t.created_at < sqlc.arg(until)
ORDER BY t.created_at, t.id
LIMIT sqlc.arg(max_rows);

-- name: BehaviorAgents :many
-- The agents with activity of one kind in a range: their transactions, and
-- for the SIMULATED origin their generated history too (HR-642).
SELECT DISTINCT a.agent_id
FROM (SELECT r.agent_id
      FROM pc.transactions t
      JOIN pc.runs r ON r.org_id = t.org_id AND r.id = t.run_id
      WHERE t.org_id = sqlc.arg(org_id) AND t.simulated = sqlc.arg(simulated)::boolean
        AND t.created_at >= sqlc.arg(since) AND t.created_at < sqlc.arg(until)
      UNION ALL
      SELECT h.agent_id
      FROM pc.behavior_simulated_actions h
      WHERE sqlc.arg(simulated)::boolean AND h.org_id = sqlc.arg(org_id)
        AND h.occurred_at >= sqlc.arg(since) AND h.occurred_at < sqlc.arg(until)) a
ORDER BY a.agent_id
LIMIT sqlc.arg(max_rows);

-- name: BehaviorKnownActions :many
-- One agent's known actions of one kind in a range, newest first: allowed
-- and run, the transaction FINAL (D526). A hold, a denial or a retry of
-- either is never known. The cap is per agent and keeps the most recent.
SELECT t.id, t.run_id, t.operation, t.connection_id,
       coalesce(c.destination_class, '')::text AS destination_class, t.created_at, t.amount, t.currency
FROM pc.transactions t
JOIN pc.runs r ON r.org_id = t.org_id AND r.id = t.run_id
LEFT JOIN pc.connections c ON c.org_id = t.org_id AND c.id = t.connection_id
WHERE t.org_id = sqlc.arg(org_id) AND r.agent_id = sqlc.arg(agent_id) AND t.simulated = sqlc.arg(simulated)::boolean
  AND t.created_at >= sqlc.arg(since) AND t.created_at < sqlc.arg(until)
  AND t.decision IN ('ALLOW', 'ALLOW_WITH_OBLIGATIONS') AND t.state = 'FINAL'
ORDER BY t.created_at DESC, t.id DESC
LIMIT sqlc.arg(max_rows);

-- name: BehaviorNotAllowedCount :one
-- One agent's other actions of one kind in a range: held, denied, refused
-- or still open. Counted apart, never known (D526).
SELECT count(*)::bigint
FROM pc.transactions t
JOIN pc.runs r ON r.org_id = t.org_id AND r.id = t.run_id
WHERE t.org_id = sqlc.arg(org_id) AND r.agent_id = sqlc.arg(agent_id) AND t.simulated = sqlc.arg(simulated)::boolean
  AND t.created_at >= sqlc.arg(since) AND t.created_at < sqlc.arg(until)
  AND NOT (t.decision IN ('ALLOW', 'ALLOW_WITH_OBLIGATIONS') AND t.state = 'FINAL');

-- name: BehaviorSimulatedHistory :many
-- One agent's generated history (HR-642), newest first, capped per agent.
-- Only the SIMULATED origin reads it.
SELECT id, run_ref, operation, connection_id, destination_class, occurred_at, amount, currency
FROM pc.behavior_simulated_actions
WHERE org_id = sqlc.arg(org_id) AND agent_id = sqlc.arg(agent_id)
  AND occurred_at >= sqlc.arg(since) AND occurred_at < sqlc.arg(until)
ORDER BY occurred_at DESC, id DESC
LIMIT sqlc.arg(max_rows);

-- name: InsertBehaviorSimulatedAction :exec
INSERT INTO pc.behavior_simulated_actions (org_id, id, agent_id, run_ref, operation, connection_id, destination_class,
                                           amount, currency, occurred_at, generator, seed)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(agent_id), sqlc.arg(run_ref), sqlc.arg(operation), sqlc.narg(connection_id),
        sqlc.arg(destination_class), sqlc.narg(amount), sqlc.narg(currency), sqlc.arg(occurred_at), sqlc.arg(generator),
        sqlc.arg(seed));

-- name: BehaviorScannedTo :one
SELECT scanned_to FROM pc.behavior_cursors WHERE org_id = sqlc.arg(org_id) AND origin = sqlc.arg(origin);

-- name: StartBehaviorCursor :execrows
INSERT INTO pc.behavior_cursors (org_id, origin, scanned_to)
VALUES (sqlc.arg(org_id), sqlc.arg(origin), sqlc.arg(scanned_to))
ON CONFLICT (org_id, origin) DO NOTHING;

-- name: AdvanceBehaviorCursor :execrows
-- Compare-and-set: a second job in the same hour moves nothing.
UPDATE pc.behavior_cursors SET scanned_to = sqlc.arg(scanned_to)
WHERE org_id = sqlc.arg(org_id) AND origin = sqlc.arg(origin) AND scanned_to = sqlc.arg(from_time);

-- name: BehaviorCollectionStarted :one
-- Whether the org ever collected.
SELECT EXISTS (SELECT FROM pc.behavior_cursors WHERE org_id = sqlc.arg(org_id))::boolean;

-- name: UpsertBehaviorProfile :exec
INSERT INTO pc.behavior_profiles (org_id, agent_id, origin, state, window_start, window_end, actions, active_days, method,
                                  truncated, body, computed_at)
VALUES (sqlc.arg(org_id), sqlc.arg(agent_id), sqlc.arg(origin), sqlc.arg(state), sqlc.arg(window_start), sqlc.arg(window_end),
        sqlc.arg(actions), sqlc.arg(active_days), sqlc.arg(method), sqlc.arg(truncated), sqlc.arg(body), now())
ON CONFLICT (org_id, agent_id, origin) DO UPDATE
SET state = EXCLUDED.state, window_start = EXCLUDED.window_start, window_end = EXCLUDED.window_end,
    actions = EXCLUDED.actions, active_days = EXCLUDED.active_days, method = EXCLUDED.method,
    truncated = EXCLUDED.truncated, body = EXCLUDED.body, computed_at = now();

-- name: GetBehaviorProfile :one
SELECT * FROM pc.behavior_profiles
WHERE org_id = sqlc.arg(org_id) AND agent_id = sqlc.arg(agent_id) AND origin = sqlc.arg(origin);

-- name: BehaviorApprovalAction :one
-- The held action behind an approval request. Read beside the approval
-- display, never by it (HR-645).
SELECT r.agent_id, t.id, t.run_id, t.operation, t.connection_id,
       coalesce(c.destination_class, '')::text AS destination_class, t.created_at, t.simulated
FROM pc.approval_requests a
JOIN pc.transactions t ON t.org_id = a.org_id AND t.id = a.transaction_id
JOIN pc.runs r ON r.org_id = t.org_id AND r.id = t.run_id
LEFT JOIN pc.connections c ON c.org_id = t.org_id AND c.id = t.connection_id
WHERE a.org_id = sqlc.arg(org_id) AND a.id = sqlc.arg(id);
