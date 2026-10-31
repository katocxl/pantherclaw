-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Run investigation (G0 M10 D20; F239, F241, F232, F284, F234, F248). Every
-- read runs in the org's tenant transaction and returns agent ids, so the
-- caller filters by the viewer's scope before assembling or counting
-- (HR-247, D8). Nothing here asserts causation.

-- One transaction with its run, grant, permit and execution (F239).
-- name: InvTransaction :one
SELECT t.id, t.run_id, r.agent_id, t.operation, t.decision, t.reason_code, t.state, t.mode, t.channel,
       t.connection_id, t.target_type, t.target_id, t.grant_id, t.grant_revision, t.effect_state,
       t.effect_level_required, t.effect_level_achieved, t.simulated, t.created_at,
       p.state AS permit_state, p.dispatching_at, p.finished_at,
       a.outcome, a.recorded_at AS outcome_at,
       c.destination_class
FROM pc.transactions t
JOIN pc.runs r ON r.org_id = t.org_id AND r.id = t.run_id
LEFT JOIN pc.permits p ON p.org_id = t.org_id AND p.transaction_id = t.id AND NOT p.replaced
LEFT JOIN pc.execution_attempts a ON a.org_id = p.org_id AND a.permit_id = p.id
LEFT JOIN pc.connections c ON c.org_id = t.org_id AND c.id = t.connection_id
WHERE t.org_id = sqlc.arg(org_id) AND t.id = sqlc.arg(id);

-- name: InvRun :one
SELECT id, agent_id, instance_id, environment_id, launcher_user_id, launcher_sa_id, launcher_instance_id,
       principal_user_id, principal_sa_id, principal_source, actor_chain, parent_run_id, depth, grant_id,
       task_ref, state, end_reason, created_at, expires_at, ended_at
FROM pc.runs WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- The run's parents, nearest first (delegation chain; depth ≤ 8).
-- name: InvRunAncestors :many
WITH RECURSIVE up AS (
    SELECT r.id, r.agent_id, r.parent_run_id, r.depth, r.launcher_user_id, r.launcher_sa_id, r.launcher_instance_id,
           r.principal_user_id, r.principal_sa_id, r.grant_id, 1 AS hop
    FROM pc.runs r
    WHERE r.org_id = sqlc.arg(org_id)
      AND r.id = (SELECT x.parent_run_id FROM pc.runs x WHERE x.org_id = sqlc.arg(org_id) AND x.id = sqlc.arg(run_id))
    UNION ALL
    SELECT r.id, r.agent_id, r.parent_run_id, r.depth, r.launcher_user_id, r.launcher_sa_id, r.launcher_instance_id,
           r.principal_user_id, r.principal_sa_id, r.grant_id, up.hop + 1
    FROM pc.runs r JOIN up ON r.org_id = sqlc.arg(org_id) AND r.id = up.parent_run_id
    WHERE up.hop < 9
)
SELECT id, agent_id, parent_run_id, depth, launcher_user_id, launcher_sa_id, launcher_instance_id,
       principal_user_id, principal_sa_id, grant_id
FROM up ORDER BY hop;

-- A grant and its ancestors, nearest first (grantor chain).
-- name: InvGrantChain :many
SELECT g.id, g.agent_id, g.parent_id, g.depth, g.state, g.grantor_kind, g.grantor_id, g.principal_user_id,
       g.principal_sa_id, g.created_at, g.revoked_at, g.revoke_reason, l.distance
FROM pc.grant_lineage l
JOIN pc.grants g ON g.org_id = l.org_id AND g.id = l.ancestor_id
WHERE l.org_id = sqlc.arg(org_id) AND l.grant_id = sqlc.arg(grant_id)
ORDER BY l.distance;

-- Holds of one transaction, or of every transaction of a run.
-- name: InvApprovals :many
SELECT q.id, q.transaction_id, q.evaluation, q.operation, q.state, q.end_reason, q.created_at, q.deadline_at,
       q.approved_at, q.consumed_at, q.ended_at
FROM pc.approval_requests q
WHERE q.org_id = sqlc.arg(org_id) AND q.subject_kind = 'ACTION'
  AND (sqlc.narg(transaction_id)::uuid IS NULL OR q.transaction_id = sqlc.narg(transaction_id))
  AND (sqlc.narg(run_id)::uuid IS NULL OR q.run_id = sqlc.narg(run_id))
ORDER BY q.created_at, q.id
LIMIT sqlc.arg(max_rows);

-- The run's transactions, oldest first (F284).
-- name: InvRunTransactions :many
SELECT t.id, t.operation, t.decision, t.reason_code, t.mode, t.channel, t.connection_id, t.target_type, t.target_id,
       t.grant_id, t.effect_state, t.read_class, t.created_at,
       p.state AS permit_state, p.dispatching_at, a.outcome, a.recorded_at AS outcome_at,
       EXISTS (SELECT 1 FROM pc.decision_receipts d WHERE d.org_id = t.org_id AND d.transaction_id = t.id)::boolean AS has_receipt,
       c.destination_class
FROM pc.transactions t
LEFT JOIN pc.permits p ON p.org_id = t.org_id AND p.transaction_id = t.id AND NOT p.replaced
LEFT JOIN pc.execution_attempts a ON a.org_id = p.org_id AND a.permit_id = p.id
LEFT JOIN pc.connections c ON c.org_id = t.org_id AND c.id = t.connection_id
WHERE t.org_id = sqlc.arg(org_id) AND t.run_id = sqlc.arg(run_id)
  AND (t.created_at, t.id) > (sqlc.arg(after_time)::timestamptz, sqlc.arg(after_id)::uuid)
ORDER BY t.created_at, t.id
LIMIT sqlc.arg(max_rows);

-- Child runs of a run after a (created_at, id) position, for reading
-- page by page until enough visible children are found (rows26 D25).
-- name: InvRunChildrenAfter :many
SELECT id, agent_id, state, created_at, ended_at
FROM pc.runs
WHERE org_id = sqlc.arg(org_id) AND parent_run_id = sqlc.arg(run_id)
  AND (created_at, id) > (sqlc.arg(after_time)::timestamptz, sqlc.arg(after_id)::uuid)
ORDER BY created_at, id
LIMIT sqlc.arg(max_rows);

-- Authority changes of an agent in a window: grants issued or revoked and
-- grant revisions made (F241, F284).
-- name: InvGrantChanges :many
SELECT g.id AS grant_id, g.agent_id, 'ISSUED'::text AS change, g.created_at AS at, g.grantor_kind, g.grantor_id,
       g.parent_id, false AS widens
FROM pc.grants g
WHERE g.org_id = sqlc.arg(org_id) AND g.agent_id = sqlc.arg(agent_id)
  AND g.created_at >= sqlc.arg(start_time) AND g.created_at < sqlc.arg(end_time)
UNION ALL
SELECT g.id, g.agent_id, 'REVOKED'::text, g.revoked_at, g.grantor_kind, g.grantor_id, g.parent_id, false
FROM pc.grants g
WHERE g.org_id = sqlc.arg(org_id) AND g.agent_id = sqlc.arg(agent_id)
  AND g.revoked_at >= sqlc.arg(start_time) AND g.revoked_at < sqlc.arg(end_time)
UNION ALL
SELECT g.id, g.agent_id, 'REVISED'::text, v.created_at, g.grantor_kind, g.grantor_id, g.parent_id, v.widens
FROM pc.grant_revisions v
JOIN pc.grants g ON g.org_id = v.org_id AND g.id = v.grant_id
WHERE v.org_id = sqlc.arg(org_id) AND g.agent_id = sqlc.arg(agent_id) AND v.revision > 1
  AND v.created_at >= sqlc.arg(start_time) AND v.created_at < sqlc.arg(end_time)
ORDER BY 4, 1
LIMIT 500;

-- Tools that are new or changed for the connections a run used: package
-- pins moved and connections created in the window (F241).
-- name: InvToolChanges :many
SELECT c.id AS connection_id, c.name AS connection, c.package, 'CONNECTION_CREATED'::text AS change, c.created_at AS at
FROM pc.connections c
WHERE c.org_id = sqlc.arg(org_id) AND c.id = ANY (sqlc.arg(connection_ids)::uuid[])
  AND c.created_at >= sqlc.arg(start_time) AND c.created_at < sqlc.arg(end_time)
UNION ALL
SELECT c.id, c.name, c.package, 'PACKAGE_PINNED'::text, p.updated_at
FROM pc.connections c
JOIN pc.tool_packages k ON k.org_id = c.org_id AND k.name = c.package
JOIN pc.package_pins p ON p.org_id = k.org_id AND p.package_id = k.id
WHERE c.org_id = sqlc.arg(org_id) AND c.id = ANY (sqlc.arg(connection_ids)::uuid[])
  AND p.updated_at >= sqlc.arg(start_time) AND p.updated_at < sqlc.arg(end_time)
ORDER BY 5, 1
LIMIT 200;

-- Other runs that touched the same destinations or resources (connection
-- and target) in the window: shared, never causal (F241, F248). A scoped
-- viewer sees only visible agents' runs, filtered before the limit (D60).
-- name: InvSharedTargets :many
SELECT t.run_id, r.agent_id, t.connection_id, coalesce(t.target_type, '')::text AS target_type,
       coalesce(t.target_id, '')::text AS target_id, count(*)::bigint AS actions,
       min(t.created_at)::timestamptz AS first_at, max(t.created_at)::timestamptz AS last_at
FROM pc.transactions t
JOIN pc.runs r ON r.org_id = t.org_id AND r.id = t.run_id
WHERE t.org_id = sqlc.arg(org_id) AND t.run_id <> sqlc.arg(run_id)
  AND (NOT sqlc.arg(scoped)::boolean OR r.agent_id = ANY (sqlc.arg(visible_agents)::uuid[]))
  AND t.created_at >= sqlc.arg(start_time) AND t.created_at < sqlc.arg(end_time)
  AND (t.connection_id, coalesce(t.target_type, ''), coalesce(t.target_id, '')) IN (
      SELECT s.connection_id, coalesce(s.target_type, ''), coalesce(s.target_id, '')
      FROM pc.transactions s
      WHERE s.org_id = sqlc.arg(org_id) AND s.run_id = sqlc.arg(run_id) AND s.connection_id IS NOT NULL)
GROUP BY t.run_id, r.agent_id, t.connection_id, t.target_type, t.target_id
ORDER BY min(t.created_at), t.run_id
LIMIT 500;

-- The agent's other runs in a reference window, for comparison (F234).
-- name: InvReferenceRuns :many
SELECT id FROM pc.runs
WHERE org_id = sqlc.arg(org_id) AND agent_id = sqlc.arg(agent_id) AND id <> sqlc.arg(run_id)
  AND created_at >= sqlc.arg(start_time) AND created_at < sqlc.arg(end_time)
ORDER BY created_at DESC, id
LIMIT sqlc.arg(max_rows);

-- What a set of runs did, per connection, operation and destination class
-- (F234: destinations, record counts, writes).
-- name: InvRunProfile :many
SELECT t.run_id, t.connection_id, t.operation, coalesce(c.destination_class, '')::text AS destination_class,
       coalesce(c.name, '')::text AS connection, count(*)::bigint AS actions,
       count(*) FILTER (WHERE a.outcome = 'accepted')::bigint AS accepted,
       max(t.created_at)::timestamptz AS last_at
FROM pc.transactions t
LEFT JOIN pc.permits p ON p.org_id = t.org_id AND p.transaction_id = t.id AND NOT p.replaced
LEFT JOIN pc.execution_attempts a ON a.org_id = p.org_id AND a.permit_id = p.id
LEFT JOIN pc.connections c ON c.org_id = t.org_id AND c.id = t.connection_id
WHERE t.org_id = sqlc.arg(org_id) AND t.run_id = ANY (sqlc.arg(run_ids)::uuid[])
GROUP BY t.run_id, t.connection_id, t.operation, c.destination_class, c.name
ORDER BY t.run_id, t.operation
LIMIT 5000;

-- Every agent of the org, for a scoped viewer's visible-agent list (D60):
-- at most 10 000 (one more tells the caller there are too many).
-- name: InvOrgAgents :many
SELECT id FROM pc.agents WHERE org_id = sqlc.arg(org_id) ORDER BY id LIMIT 10001;

-- The automation execution that launched a run (F065).
-- name: InvRunUpstreamExecution :one
SELECT e.id, e.automation_id, e.mode, e.state, e.trigger_kind, e.created_at, e.ended_at
FROM pc.automation_launches l
JOIN pc.automation_executions e ON e.org_id = l.org_id AND e.id = l.execution_id
WHERE l.org_id = sqlc.arg(org_id) AND l.run_id = sqlc.arg(run_id);

-- Automation executions whose subjects name a run, created since it
-- started (F065), oldest first.
-- name: InvRunDownstreamExecutions :many
SELECT e.id, e.automation_id, e.mode, e.state, e.trigger_kind, e.created_at, e.ended_at
FROM pc.automation_executions e
WHERE e.org_id = sqlc.arg(org_id) AND e.created_at >= sqlc.arg(since)
  AND e.subjects @> jsonb_build_array(jsonb_build_object('type', 'run', 'id', sqlc.arg(run_id)::uuid::text))
ORDER BY e.created_at, e.id
LIMIT sqlc.arg(max_rows);

-- What a run's actions reserved on each budget account and counter (F227):
-- the current permit's reservations of every transaction of the run.
-- name: InvRunBudget :many
SELECT coalesce(r.account_id, r.counter_id)::uuid AS line_id, (r.account_id IS NOT NULL)::boolean AS account,
       coalesce(a.rule, c.rule)::text AS rule, coalesce(a.currency, '')::text AS currency,
       coalesce(sum(r.amount) FILTER (WHERE r.state = 'HELD'), 0)::numeric(26,8) AS held,
       coalesce(sum(r.amount) FILTER (WHERE r.state = 'COMMITTED'), 0)::numeric(26,8) AS committed,
       coalesce(sum(r.amount) FILTER (WHERE r.state = 'RELEASED'), 0)::numeric(26,8) AS released,
       count(*) FILTER (WHERE r.state = 'HELD')::bigint AS held_count,
       count(*) FILTER (WHERE r.state = 'COMMITTED')::bigint AS committed_count,
       count(*) FILTER (WHERE r.state = 'RELEASED')::bigint AS released_count,
       count(*)::bigint AS reservations
FROM pc.transactions t
JOIN pc.permits p ON p.org_id = t.org_id AND p.transaction_id = t.id AND NOT p.replaced
JOIN pc.reservations r ON r.org_id = p.org_id AND r.permit_id = p.id
LEFT JOIN pc.budget_accounts a ON a.org_id = r.org_id AND a.id = r.account_id
LEFT JOIN pc.counters c ON c.org_id = r.org_id AND c.id = r.counter_id
WHERE t.org_id = sqlc.arg(org_id) AND t.run_id = sqlc.arg(run_id)
GROUP BY 1, 2, 3, 4
ORDER BY 3, 1
LIMIT 500;

-- The grants a run's transactions decided under.
-- name: InvRunGrants :many
SELECT DISTINCT t.grant_id::uuid AS grant_id
FROM pc.transactions t
WHERE t.org_id = sqlc.arg(org_id) AND t.run_id = sqlc.arg(run_id) AND t.grant_id IS NOT NULL
LIMIT 20;

-- The coverage snapshots a run's decision receipts claimed (F229, HR-217).
-- name: InvRunCoverage :many
SELECT s.id AS snapshot_id, s.connection_id, s.operation, s.state, s.reasons, s.computed_at,
       bool_or(s.expires_at IS NOT NULL AND s.expires_at <= d.created_at)::boolean AS stale_at_decision
FROM pc.transactions t
JOIN pc.decision_receipts d ON d.org_id = t.org_id AND d.transaction_id = t.id
JOIN pc.coverage_snapshots s ON s.org_id = d.org_id AND s.id = d.coverage_snapshot_id
WHERE t.org_id = sqlc.arg(org_id) AND t.run_id = sqlc.arg(run_id)
GROUP BY s.org_id, s.id
ORDER BY s.connection_id, s.operation, s.id
LIMIT 1000;

-- A run's decisions on a connection that claimed no coverage, or coverage
-- below ENFORCED or expired when decided (F229), oldest first.
-- name: InvRunCoverageGaps :many
SELECT t.id, t.created_at, t.connection_id, t.operation,
       (d.coverage_snapshot_id IS NULL)::boolean AS no_claim
FROM pc.transactions t
JOIN pc.decision_receipts d ON d.org_id = t.org_id AND d.transaction_id = t.id
LEFT JOIN pc.coverage_snapshots s ON s.org_id = d.org_id AND s.id = d.coverage_snapshot_id
WHERE t.org_id = sqlc.arg(org_id) AND t.run_id = sqlc.arg(run_id) AND t.connection_id IS NOT NULL
  AND (d.coverage_snapshot_id IS NULL OR s.state <> 'ENFORCED' OR s.expires_at <= d.created_at)
ORDER BY t.created_at, t.id
LIMIT sqlc.arg(max_rows);

-- When a run's transactions reached each gateway, oldest first (F229).
-- name: InvRunGatewayDecisions :many
SELECT g.id AS gateway_id, g.created_at AS gateway_created_at, t.created_at
FROM pc.transactions t
JOIN pc.gateways g ON g.org_id = t.org_id AND g.id::text = t.gateway_id
WHERE t.org_id = sqlc.arg(org_id) AND t.run_id = sqlc.arg(run_id)
ORDER BY g.id, t.created_at
LIMIT sqlc.arg(max_rows);

-- Certificate renewals of gateways in a window: a gateway's heartbeat.
-- name: InvGatewayRenewals :many
SELECT c.gateway_id, c.issued_at
FROM pc.gateway_certs c
WHERE c.org_id = sqlc.arg(org_id) AND c.gateway_id = ANY (sqlc.arg(gateway_ids)::uuid[])
  AND c.issued_at >= sqlc.arg(start_time) AND c.issued_at < sqlc.arg(end_time)
ORDER BY c.gateway_id, c.issued_at
LIMIT 10000;
