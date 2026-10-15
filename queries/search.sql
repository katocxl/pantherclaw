-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

-- Structured search (G0 M10 D34, HR-257). Every query takes the viewer's
-- scope: all_agents when the viewer holds the entity's permission at the
-- org, else the agents it may read. Rows outside the scope are filtered
-- here, before paging and counting, so counts never include hidden rows
-- (D8, T-042). Searches page newest first by id; counts stop at 10001.

-- name: SearchAgentPlacements :many
SELECT id, team_id, environment_id FROM pc.agents WHERE org_id = $1 ORDER BY id;

-- name: SearchTransactions :many
SELECT t.id, t.run_id, r.agent_id, t.operation, t.connection_id, t.decision, t.reason_code, t.mode, t.effect_state,
       t.target_type, t.target_id, t.created_at, t.simulated, e.kind AS environment_kind
FROM pc.transactions t
JOIN pc.runs r ON r.org_id = t.org_id AND r.id = t.run_id
JOIN pc.environments e ON e.org_id = r.org_id AND e.id = r.environment_id
WHERE t.org_id = sqlc.arg(org_id)
  AND (sqlc.arg(all_agents)::boolean OR r.agent_id = ANY (sqlc.arg(agents)::uuid[]))
  AND (sqlc.narg(before)::uuid IS NULL OR t.id < sqlc.narg(before)::uuid)
  AND (sqlc.narg(id)::uuid IS NULL OR t.id = sqlc.narg(id)::uuid)
  AND (sqlc.narg(agent_id)::uuid IS NULL OR r.agent_id = sqlc.narg(agent_id)::uuid)
  AND (sqlc.narg(run_id)::uuid IS NULL OR t.run_id = sqlc.narg(run_id)::uuid)
  AND (sqlc.narg(connection_id)::uuid IS NULL OR t.connection_id = sqlc.narg(connection_id)::uuid)
  AND (sqlc.narg(grant_id)::uuid IS NULL OR t.grant_id = sqlc.narg(grant_id)::uuid)
  AND (sqlc.narg(principal_user_id)::uuid IS NULL OR r.principal_user_id = sqlc.narg(principal_user_id)::uuid)
  AND (sqlc.narg(principal_sa_id)::uuid IS NULL OR r.principal_sa_id = sqlc.narg(principal_sa_id)::uuid)
  AND (sqlc.arg(operation)::text = '' OR t.operation = sqlc.arg(operation)::text)
  AND (sqlc.arg(operation_prefix)::text = '' OR starts_with(t.operation, sqlc.arg(operation_prefix)::text))
  AND (sqlc.arg(target_type)::text = '' OR t.target_type = sqlc.arg(target_type)::text)
  AND (cardinality(sqlc.arg(decisions)::text[]) = 0 OR t.decision = ANY (sqlc.arg(decisions)::text[]))
  AND (cardinality(sqlc.arg(modes)::text[]) = 0 OR t.mode = ANY (sqlc.arg(modes)::text[]))
  AND (cardinality(sqlc.arg(environment_kinds)::text[]) = 0 OR e.kind = ANY (sqlc.arg(environment_kinds)::text[]))
  AND (sqlc.narg(start_time)::timestamptz IS NULL OR t.created_at >= sqlc.narg(start_time)::timestamptz)
  AND (sqlc.narg(end_time)::timestamptz IS NULL OR t.created_at < sqlc.narg(end_time)::timestamptz)
ORDER BY t.id DESC
LIMIT sqlc.arg(page_limit);

-- name: CountTransactions :one
SELECT count(*) FROM (
    SELECT 1
    FROM pc.transactions t
    JOIN pc.runs r ON r.org_id = t.org_id AND r.id = t.run_id
    JOIN pc.environments e ON e.org_id = r.org_id AND e.id = r.environment_id
    WHERE t.org_id = sqlc.arg(org_id)
      AND (sqlc.arg(all_agents)::boolean OR r.agent_id = ANY (sqlc.arg(agents)::uuid[]))
      AND (sqlc.narg(id)::uuid IS NULL OR t.id = sqlc.narg(id)::uuid)
      AND (sqlc.narg(agent_id)::uuid IS NULL OR r.agent_id = sqlc.narg(agent_id)::uuid)
      AND (sqlc.narg(run_id)::uuid IS NULL OR t.run_id = sqlc.narg(run_id)::uuid)
      AND (sqlc.narg(connection_id)::uuid IS NULL OR t.connection_id = sqlc.narg(connection_id)::uuid)
      AND (sqlc.narg(grant_id)::uuid IS NULL OR t.grant_id = sqlc.narg(grant_id)::uuid)
      AND (sqlc.narg(principal_user_id)::uuid IS NULL OR r.principal_user_id = sqlc.narg(principal_user_id)::uuid)
      AND (sqlc.narg(principal_sa_id)::uuid IS NULL OR r.principal_sa_id = sqlc.narg(principal_sa_id)::uuid)
      AND (sqlc.arg(operation)::text = '' OR t.operation = sqlc.arg(operation)::text)
      AND (sqlc.arg(operation_prefix)::text = '' OR starts_with(t.operation, sqlc.arg(operation_prefix)::text))
      AND (sqlc.arg(target_type)::text = '' OR t.target_type = sqlc.arg(target_type)::text)
      AND (cardinality(sqlc.arg(decisions)::text[]) = 0 OR t.decision = ANY (sqlc.arg(decisions)::text[]))
      AND (cardinality(sqlc.arg(modes)::text[]) = 0 OR t.mode = ANY (sqlc.arg(modes)::text[]))
      AND (cardinality(sqlc.arg(environment_kinds)::text[]) = 0 OR e.kind = ANY (sqlc.arg(environment_kinds)::text[]))
      AND (sqlc.narg(start_time)::timestamptz IS NULL OR t.created_at >= sqlc.narg(start_time)::timestamptz)
      AND (sqlc.narg(end_time)::timestamptz IS NULL OR t.created_at < sqlc.narg(end_time)::timestamptz)
    LIMIT 10001
) x;

-- name: SearchRuns :many
SELECT r.id, r.agent_id, r.parent_run_id, r.principal_user_id, r.principal_sa_id, r.launcher_user_id, r.launcher_sa_id,
       r.grant_id, r.state, r.created_at, r.ended_at, r.simulated
FROM pc.runs r
WHERE r.org_id = sqlc.arg(org_id)
  AND (sqlc.arg(all_agents)::boolean OR r.agent_id = ANY (sqlc.arg(agents)::uuid[]))
  AND (sqlc.narg(before)::uuid IS NULL OR r.id < sqlc.narg(before)::uuid)
  AND (sqlc.narg(id)::uuid IS NULL OR r.id = sqlc.narg(id)::uuid)
  AND (sqlc.narg(agent_id)::uuid IS NULL OR r.agent_id = sqlc.narg(agent_id)::uuid)
  AND (sqlc.narg(grant_id)::uuid IS NULL OR r.grant_id = sqlc.narg(grant_id)::uuid)
  AND (sqlc.narg(principal_user_id)::uuid IS NULL OR r.principal_user_id = sqlc.narg(principal_user_id)::uuid)
  AND (sqlc.narg(principal_sa_id)::uuid IS NULL OR r.principal_sa_id = sqlc.narg(principal_sa_id)::uuid)
  AND (cardinality(sqlc.arg(states)::text[]) = 0 OR r.state = ANY (sqlc.arg(states)::text[]))
  AND (sqlc.narg(start_time)::timestamptz IS NULL OR r.created_at >= sqlc.narg(start_time)::timestamptz)
  AND (sqlc.narg(end_time)::timestamptz IS NULL OR r.created_at < sqlc.narg(end_time)::timestamptz)
ORDER BY r.id DESC
LIMIT sqlc.arg(page_limit);

-- name: CountRuns :one
SELECT count(*) FROM (
    SELECT 1 FROM pc.runs r
    WHERE r.org_id = sqlc.arg(org_id)
      AND (sqlc.arg(all_agents)::boolean OR r.agent_id = ANY (sqlc.arg(agents)::uuid[]))
      AND (sqlc.narg(id)::uuid IS NULL OR r.id = sqlc.narg(id)::uuid)
      AND (sqlc.narg(agent_id)::uuid IS NULL OR r.agent_id = sqlc.narg(agent_id)::uuid)
      AND (sqlc.narg(grant_id)::uuid IS NULL OR r.grant_id = sqlc.narg(grant_id)::uuid)
      AND (sqlc.narg(principal_user_id)::uuid IS NULL OR r.principal_user_id = sqlc.narg(principal_user_id)::uuid)
      AND (sqlc.narg(principal_sa_id)::uuid IS NULL OR r.principal_sa_id = sqlc.narg(principal_sa_id)::uuid)
      AND (cardinality(sqlc.arg(states)::text[]) = 0 OR r.state = ANY (sqlc.arg(states)::text[]))
      AND (sqlc.narg(start_time)::timestamptz IS NULL OR r.created_at >= sqlc.narg(start_time)::timestamptz)
      AND (sqlc.narg(end_time)::timestamptz IS NULL OR r.created_at < sqlc.narg(end_time)::timestamptz)
    LIMIT 10001
) x;

-- name: SearchAgents :many
SELECT a.id, a.name, a.state, a.team_id, a.environment_id, a.owner_user_id, a.created_at, e.kind AS environment_kind
FROM pc.agents a
LEFT JOIN pc.environments e ON e.org_id = a.org_id AND e.id = a.environment_id
WHERE a.org_id = sqlc.arg(org_id)
  AND (sqlc.arg(all_agents)::boolean OR a.id = ANY (sqlc.arg(agents)::uuid[]))
  AND (sqlc.narg(before)::uuid IS NULL OR a.id < sqlc.narg(before)::uuid)
  AND (sqlc.narg(id)::uuid IS NULL OR a.id = sqlc.narg(id)::uuid)
  AND (sqlc.narg(team_id)::uuid IS NULL OR a.team_id = sqlc.narg(team_id)::uuid)
  AND (cardinality(sqlc.arg(states)::text[]) = 0 OR a.state = ANY (sqlc.arg(states)::text[]))
  AND (cardinality(sqlc.arg(environment_kinds)::text[]) = 0 OR e.kind = ANY (sqlc.arg(environment_kinds)::text[]))
  AND (sqlc.narg(used_connection_id)::uuid IS NULL OR EXISTS (
        SELECT 1 FROM pc.transactions t JOIN pc.runs r ON r.org_id = t.org_id AND r.id = t.run_id
        WHERE t.org_id = a.org_id AND r.agent_id = a.id AND t.connection_id = sqlc.narg(used_connection_id)::uuid
          AND (sqlc.narg(start_time)::timestamptz IS NULL OR t.created_at >= sqlc.narg(start_time)::timestamptz)
          AND (sqlc.narg(end_time)::timestamptz IS NULL OR t.created_at < sqlc.narg(end_time)::timestamptz)))
ORDER BY a.id DESC
LIMIT sqlc.arg(page_limit);

-- name: CountAgents :one
SELECT count(*) FROM (
    SELECT 1 FROM pc.agents a
    LEFT JOIN pc.environments e ON e.org_id = a.org_id AND e.id = a.environment_id
    WHERE a.org_id = sqlc.arg(org_id)
      AND (sqlc.arg(all_agents)::boolean OR a.id = ANY (sqlc.arg(agents)::uuid[]))
      AND (sqlc.narg(id)::uuid IS NULL OR a.id = sqlc.narg(id)::uuid)
      AND (sqlc.narg(team_id)::uuid IS NULL OR a.team_id = sqlc.narg(team_id)::uuid)
      AND (cardinality(sqlc.arg(states)::text[]) = 0 OR a.state = ANY (sqlc.arg(states)::text[]))
      AND (cardinality(sqlc.arg(environment_kinds)::text[]) = 0 OR e.kind = ANY (sqlc.arg(environment_kinds)::text[]))
      AND (sqlc.narg(used_connection_id)::uuid IS NULL OR EXISTS (
            SELECT 1 FROM pc.transactions t JOIN pc.runs r ON r.org_id = t.org_id AND r.id = t.run_id
            WHERE t.org_id = a.org_id AND r.agent_id = a.id AND t.connection_id = sqlc.narg(used_connection_id)::uuid
              AND (sqlc.narg(start_time)::timestamptz IS NULL OR t.created_at >= sqlc.narg(start_time)::timestamptz)
              AND (sqlc.narg(end_time)::timestamptz IS NULL OR t.created_at < sqlc.narg(end_time)::timestamptz)))
    LIMIT 10001
) x;

-- name: SearchGrants :many
SELECT g.id, g.agent_id, g.principal_user_id, g.principal_sa_id, g.environment_id, g.parent_id, g.depth, g.state,
       g.current_revision, g.grantor_kind, g.grantor_id, g.created_at, g.revoked_at
FROM pc.grants g
WHERE g.org_id = sqlc.arg(org_id)
  AND (sqlc.arg(all_agents)::boolean OR g.agent_id = ANY (sqlc.arg(agents)::uuid[]))
  AND (sqlc.narg(before)::uuid IS NULL OR g.id < sqlc.narg(before)::uuid)
  AND (sqlc.narg(id)::uuid IS NULL OR g.id = sqlc.narg(id)::uuid)
  AND (sqlc.narg(agent_id)::uuid IS NULL OR g.agent_id = sqlc.narg(agent_id)::uuid)
  AND (sqlc.narg(principal_user_id)::uuid IS NULL OR g.principal_user_id = sqlc.narg(principal_user_id)::uuid)
  AND (sqlc.narg(principal_sa_id)::uuid IS NULL OR g.principal_sa_id = sqlc.narg(principal_sa_id)::uuid)
  AND (cardinality(sqlc.arg(states)::text[]) = 0 OR g.state = ANY (sqlc.arg(states)::text[]))
  AND (sqlc.narg(start_time)::timestamptz IS NULL OR g.created_at >= sqlc.narg(start_time)::timestamptz)
  AND (sqlc.narg(end_time)::timestamptz IS NULL OR g.created_at < sqlc.narg(end_time)::timestamptz)
  AND (sqlc.narg(unused_since)::timestamptz IS NULL OR NOT EXISTS (
        SELECT 1 FROM pc.transactions t
        WHERE t.org_id = g.org_id AND t.grant_id = g.id AND t.created_at >= sqlc.narg(unused_since)::timestamptz))
ORDER BY g.id DESC
LIMIT sqlc.arg(page_limit);

-- name: CountGrants :one
SELECT count(*) FROM (
    SELECT 1 FROM pc.grants g
    WHERE g.org_id = sqlc.arg(org_id)
      AND (sqlc.arg(all_agents)::boolean OR g.agent_id = ANY (sqlc.arg(agents)::uuid[]))
      AND (sqlc.narg(id)::uuid IS NULL OR g.id = sqlc.narg(id)::uuid)
      AND (sqlc.narg(agent_id)::uuid IS NULL OR g.agent_id = sqlc.narg(agent_id)::uuid)
      AND (sqlc.narg(principal_user_id)::uuid IS NULL OR g.principal_user_id = sqlc.narg(principal_user_id)::uuid)
      AND (sqlc.narg(principal_sa_id)::uuid IS NULL OR g.principal_sa_id = sqlc.narg(principal_sa_id)::uuid)
      AND (cardinality(sqlc.arg(states)::text[]) = 0 OR g.state = ANY (sqlc.arg(states)::text[]))
      AND (sqlc.narg(start_time)::timestamptz IS NULL OR g.created_at >= sqlc.narg(start_time)::timestamptz)
      AND (sqlc.narg(end_time)::timestamptz IS NULL OR g.created_at < sqlc.narg(end_time)::timestamptz)
      AND (sqlc.narg(unused_since)::timestamptz IS NULL OR NOT EXISTS (
            SELECT 1 FROM pc.transactions t
            WHERE t.org_id = g.org_id AND t.grant_id = g.id AND t.created_at >= sqlc.narg(unused_since)::timestamptz))
    LIMIT 10001
) x;

-- name: SearchGrantRevisions :many
SELECT v.id, v.grant_id, g.agent_id, v.revision, v.widens, v.created_by, v.created_at, v.expires_at
FROM pc.grant_revisions v
JOIN pc.grants g ON g.org_id = v.org_id AND g.id = v.grant_id
WHERE v.org_id = sqlc.arg(org_id)
  AND (sqlc.arg(all_agents)::boolean OR g.agent_id = ANY (sqlc.arg(agents)::uuid[]))
  AND (sqlc.narg(before)::uuid IS NULL OR v.id < sqlc.narg(before)::uuid)
  AND (sqlc.narg(agent_id)::uuid IS NULL OR g.agent_id = sqlc.narg(agent_id)::uuid)
  AND (sqlc.narg(grant_id)::uuid IS NULL OR v.grant_id = sqlc.narg(grant_id)::uuid)
  AND (NOT sqlc.arg(widens_only)::boolean OR v.widens OR v.revision = 1)
  AND (sqlc.narg(start_time)::timestamptz IS NULL OR v.created_at >= sqlc.narg(start_time)::timestamptz)
  AND (sqlc.narg(end_time)::timestamptz IS NULL OR v.created_at < sqlc.narg(end_time)::timestamptz)
ORDER BY v.id DESC
LIMIT sqlc.arg(page_limit);

-- name: CountGrantRevisions :one
SELECT count(*) FROM (
    SELECT 1 FROM pc.grant_revisions v
    JOIN pc.grants g ON g.org_id = v.org_id AND g.id = v.grant_id
    WHERE v.org_id = sqlc.arg(org_id)
      AND (sqlc.arg(all_agents)::boolean OR g.agent_id = ANY (sqlc.arg(agents)::uuid[]))
      AND (sqlc.narg(agent_id)::uuid IS NULL OR g.agent_id = sqlc.narg(agent_id)::uuid)
      AND (sqlc.narg(grant_id)::uuid IS NULL OR v.grant_id = sqlc.narg(grant_id)::uuid)
      AND (NOT sqlc.arg(widens_only)::boolean OR v.widens OR v.revision = 1)
      AND (sqlc.narg(start_time)::timestamptz IS NULL OR v.created_at >= sqlc.narg(start_time)::timestamptz)
      AND (sqlc.narg(end_time)::timestamptz IS NULL OR v.created_at < sqlc.narg(end_time)::timestamptz)
    LIMIT 10001
) x;

-- name: SearchConnections :many
SELECT c.id, c.name, c.kind, c.gateway_id, c.package, c.destination_class, c.access_mode, c.default_mode, c.state,
       c.created_at, c.simulated
FROM pc.connections c
WHERE c.org_id = sqlc.arg(org_id)
  AND (sqlc.narg(before)::uuid IS NULL OR c.id < sqlc.narg(before)::uuid)
  AND (sqlc.narg(id)::uuid IS NULL OR c.id = sqlc.narg(id)::uuid)
  AND (sqlc.narg(gateway_id)::uuid IS NULL OR c.gateway_id = sqlc.narg(gateway_id)::uuid)
  AND (cardinality(sqlc.arg(states)::text[]) = 0 OR c.state = ANY (sqlc.arg(states)::text[]))
  AND (cardinality(sqlc.arg(kinds)::text[]) = 0 OR c.kind = ANY (sqlc.arg(kinds)::text[]))
  AND (cardinality(sqlc.arg(access_modes)::text[]) = 0 OR c.access_mode = ANY (sqlc.arg(access_modes)::text[]))
  AND (sqlc.narg(start_time)::timestamptz IS NULL OR c.created_at >= sqlc.narg(start_time)::timestamptz)
  AND (sqlc.narg(end_time)::timestamptz IS NULL OR c.created_at < sqlc.narg(end_time)::timestamptz)
ORDER BY c.id DESC
LIMIT sqlc.arg(page_limit);

-- name: CountConnections :one
SELECT count(*) FROM (
    SELECT 1 FROM pc.connections c
    WHERE c.org_id = sqlc.arg(org_id)
      AND (sqlc.narg(id)::uuid IS NULL OR c.id = sqlc.narg(id)::uuid)
      AND (sqlc.narg(gateway_id)::uuid IS NULL OR c.gateway_id = sqlc.narg(gateway_id)::uuid)
      AND (cardinality(sqlc.arg(states)::text[]) = 0 OR c.state = ANY (sqlc.arg(states)::text[]))
      AND (cardinality(sqlc.arg(kinds)::text[]) = 0 OR c.kind = ANY (sqlc.arg(kinds)::text[]))
      AND (cardinality(sqlc.arg(access_modes)::text[]) = 0 OR c.access_mode = ANY (sqlc.arg(access_modes)::text[]))
      AND (sqlc.narg(start_time)::timestamptz IS NULL OR c.created_at >= sqlc.narg(start_time)::timestamptz)
      AND (sqlc.narg(end_time)::timestamptz IS NULL OR c.created_at < sqlc.narg(end_time)::timestamptz)
    LIMIT 10001
) x;

-- name: SearchApprovals :many
SELECT a.id, a.agent_id, a.run_id, a.transaction_id, a.operation, a.state, a.end_reason, a.created_at, a.deadline_at,
       a.ended_at
FROM pc.approval_requests a
WHERE a.org_id = sqlc.arg(org_id)
  AND (sqlc.arg(all_agents)::boolean OR a.agent_id = ANY (sqlc.arg(agents)::uuid[]))
  AND (sqlc.narg(before)::uuid IS NULL OR a.id < sqlc.narg(before)::uuid)
  AND (sqlc.narg(id)::uuid IS NULL OR a.id = sqlc.narg(id)::uuid)
  AND (sqlc.narg(agent_id)::uuid IS NULL OR a.agent_id = sqlc.narg(agent_id)::uuid)
  AND (sqlc.narg(run_id)::uuid IS NULL OR a.run_id = sqlc.narg(run_id)::uuid)
  AND (sqlc.arg(operation)::text = '' OR a.operation = sqlc.arg(operation)::text)
  AND (cardinality(sqlc.arg(states)::text[]) = 0 OR a.state = ANY (sqlc.arg(states)::text[]))
  AND (sqlc.narg(start_time)::timestamptz IS NULL OR a.created_at >= sqlc.narg(start_time)::timestamptz)
  AND (sqlc.narg(end_time)::timestamptz IS NULL OR a.created_at < sqlc.narg(end_time)::timestamptz)
ORDER BY a.id DESC
LIMIT sqlc.arg(page_limit);

-- name: CountApprovals :one
SELECT count(*) FROM (
    SELECT 1 FROM pc.approval_requests a
    WHERE a.org_id = sqlc.arg(org_id)
      AND (sqlc.arg(all_agents)::boolean OR a.agent_id = ANY (sqlc.arg(agents)::uuid[]))
      AND (sqlc.narg(id)::uuid IS NULL OR a.id = sqlc.narg(id)::uuid)
      AND (sqlc.narg(agent_id)::uuid IS NULL OR a.agent_id = sqlc.narg(agent_id)::uuid)
      AND (sqlc.narg(run_id)::uuid IS NULL OR a.run_id = sqlc.narg(run_id)::uuid)
      AND (sqlc.arg(operation)::text = '' OR a.operation = sqlc.arg(operation)::text)
      AND (cardinality(sqlc.arg(states)::text[]) = 0 OR a.state = ANY (sqlc.arg(states)::text[]))
      AND (sqlc.narg(start_time)::timestamptz IS NULL OR a.created_at >= sqlc.narg(start_time)::timestamptz)
      AND (sqlc.narg(end_time)::timestamptz IS NULL OR a.created_at < sqlc.narg(end_time)::timestamptz)
    LIMIT 10001
) x;

-- name: SearchAudit :many
SELECT e.id, e.kind, e.actor_type, e.actor_id, e.occurred_at, c.seq
FROM pc.ledger_entries e
LEFT JOIN pc.ledger_chain c ON c.org_id = e.org_id AND c.entry_id = e.id
WHERE e.org_id = sqlc.arg(org_id)
  AND starts_with(e.kind, 'audit.')
  AND (sqlc.narg(before)::uuid IS NULL OR e.id < sqlc.narg(before)::uuid)
  AND (sqlc.narg(id)::uuid IS NULL OR e.id = sqlc.narg(id)::uuid)
  AND (sqlc.arg(kind_prefix)::text = '' OR starts_with(e.kind, sqlc.arg(kind_prefix)::text))
  AND (sqlc.arg(actor_id)::text = '' OR e.actor_id = sqlc.arg(actor_id)::text)
  AND (sqlc.narg(start_time)::timestamptz IS NULL OR e.occurred_at >= sqlc.narg(start_time)::timestamptz)
  AND (sqlc.narg(end_time)::timestamptz IS NULL OR e.occurred_at < sqlc.narg(end_time)::timestamptz)
ORDER BY e.id DESC
LIMIT sqlc.arg(page_limit);

-- name: CountAudit :one
SELECT count(*) FROM (
    SELECT 1 FROM pc.ledger_entries e
    WHERE e.org_id = sqlc.arg(org_id)
      AND starts_with(e.kind, 'audit.')
      AND (sqlc.narg(id)::uuid IS NULL OR e.id = sqlc.narg(id)::uuid)
      AND (sqlc.arg(kind_prefix)::text = '' OR starts_with(e.kind, sqlc.arg(kind_prefix)::text))
      AND (sqlc.arg(actor_id)::text = '' OR e.actor_id = sqlc.arg(actor_id)::text)
      AND (sqlc.narg(start_time)::timestamptz IS NULL OR e.occurred_at >= sqlc.narg(start_time)::timestamptz)
      AND (sqlc.narg(end_time)::timestamptz IS NULL OR e.occurred_at < sqlc.narg(end_time)::timestamptz)
    LIMIT 10001
) x;
