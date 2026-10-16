-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Production promotions (G0 M11 part 2, D39, HR-290): the per-operation
-- checks read the agent, its instances, owner, environment, the published
-- policy and coverage; the promotion gate reads an agent's ACTIVE
-- promotions in one environment.

-- The agent a promotion is about, with what its checks read about it.
-- name: PromotionSubject :one
SELECT a.id, a.state, a.team_id, a.environment_id, a.owner_user_id, a.backup_owner_user_id,
       t.business_unit_id,
       coalesce(e.kind, '')::text AS environment_kind,
       coalesce(u.state = 'ACTIVE', false)::boolean AS owner_active,
       (SELECT count(*) FROM pc.agent_instances i
        WHERE i.org_id = a.org_id AND i.agent_id = a.id AND i.state = 'ADMITTED'
          AND (i.expires_at IS NULL OR i.expires_at > now()))::integer AS active_instances
FROM pc.agents a
LEFT JOIN pc.teams t ON t.org_id = a.org_id AND t.id = a.team_id
LEFT JOIN pc.environments e ON e.org_id = a.org_id AND e.id = a.environment_id
LEFT JOIN pc.users u ON u.org_id = a.org_id AND u.id = a.owner_user_id
WHERE a.org_id = sqlc.arg(org_id) AND a.id = sqlc.arg(id);

-- name: PromotionEnvironmentKind :one
SELECT kind FROM pc.environments WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- The operations an agent is promoted for in an environment now: ACTIVE,
-- or PROVISIONAL and not expired by the database clock (with its expiry,
-- D80). Locked FOR SHARE so a concurrent revocation or expiry waits for
-- the issuing transaction (D71 G7).
-- name: PromotedOperations :many
SELECT operation, state, expires_at FROM pc.agent_promotions
WHERE org_id = sqlc.arg(org_id) AND agent_id = sqlc.arg(agent_id) AND environment_id = sqlc.arg(environment_id)
  AND (state = 'ACTIVE' OR (state = 'PROVISIONAL' AND expires_at > now()))
ORDER BY operation
FOR SHARE;

-- name: ActiveAgentPromotion :one
SELECT * FROM pc.agent_promotions
WHERE org_id = sqlc.arg(org_id) AND agent_id = sqlc.arg(agent_id) AND environment_id = sqlc.arg(environment_id)
  AND operation = sqlc.arg(operation) AND state IN ('ACTIVE', 'PROVISIONAL')
FOR UPDATE;

-- name: InsertAgentPromotion :one
INSERT INTO pc.agent_promotions (org_id, id, agent_id, environment_id, operation, state, checks, failure_behavior,
    promoted_by, credential_id, expires_at)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(agent_id), sqlc.arg(environment_id), sqlc.arg(operation), sqlc.arg(state),
    sqlc.arg(checks), sqlc.arg(failure_behavior), sqlc.arg(promoted_by), sqlc.arg(credential_id), sqlc.narg(expires_at))
RETURNING *;

-- name: GetAgentPromotion :one
SELECT * FROM pc.agent_promotions WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: RevokeAgentPromotion :one
UPDATE pc.agent_promotions
SET state = 'REVOKED', revoked_by = sqlc.arg(revoked_by), revoked_at = now(), revoke_reason = sqlc.arg(reason)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state IN ('ACTIVE', 'PROVISIONAL')
RETURNING *;

-- Promotions, newest first, by agent, environment and state.
-- name: ListAgentPromotions :many
SELECT * FROM pc.agent_promotions
WHERE org_id = sqlc.arg(org_id)
  AND (sqlc.narg(agent_id)::uuid IS NULL OR agent_id = sqlc.narg(agent_id)::uuid)
  AND (sqlc.narg(environment_id)::uuid IS NULL OR environment_id = sqlc.narg(environment_id)::uuid)
  AND (sqlc.narg(state)::text IS NULL OR state = sqlc.narg(state)::text)
  AND (sqlc.narg(after)::uuid IS NULL OR id < sqlc.narg(after)::uuid)
ORDER BY id DESC
LIMIT sqlc.arg(max_rows);

-- The operations an agent's active, unexpired grants list (readiness
-- with no operation named).
-- name: AgentGrantBounds :many
SELECT r.bounds
FROM pc.grants g
JOIN pc.grant_revisions r ON r.org_id = g.org_id AND r.grant_id = g.id AND r.revision = g.current_revision
WHERE g.org_id = sqlc.arg(org_id) AND g.agent_id = sqlc.arg(agent_id) AND g.environment_id = sqlc.arg(environment_id)
  AND g.state = 'ACTIVE' AND r.expires_at > now()
ORDER BY g.id
LIMIT 200;

-- The agent's connections (D70, D93 L2, V4): the ACTIVE connections a
-- coverage route of the agent, or one of every agent of the connection,
-- goes through. A prefix expands to the operations their packages' active
-- definitions declare, and they are the connections COVERAGE needs a
-- passing record on.
-- name: PromotionAgentConnections :many
SELECT c.id, c.package FROM pc.connections c
WHERE c.org_id = sqlc.arg(org_id) AND c.state = 'ACTIVE'
  AND EXISTS (SELECT 1 FROM pc.coverage_routes r
              WHERE r.org_id = c.org_id AND r.connection_id = c.id
                AND (r.agent_id = sqlc.arg(agent_id) OR r.agent_id IS NULL))
ORDER BY c.id;

-- The agent's current coverage snapshot of one operation on each
-- connection, every one (no row cap can drop a record, D93 V4).
-- name: PromotionCoverageSnapshots :many
SELECT DISTINCT ON (connection_id) * FROM pc.coverage_snapshots
WHERE org_id = sqlc.arg(org_id) AND agent_id = sqlc.arg(agent_id) AND operation = sqlc.arg(operation)
ORDER BY connection_id, id DESC;

-- How many change windows the org has: a hold that counts only inside a
-- window can be answered only when one exists (D71 G10).
-- name: PromotionChangeWindows :one
SELECT count(*)::integer FROM pc.change_windows WHERE org_id = sqlc.arg(org_id);

-- Provisional promotions (D80): the sweep reads them oldest expiry first,
-- confirms one whose coverage appeared, and expires those the database
-- clock has passed.
-- name: ProvisionalPromotions :many
SELECT * FROM pc.agent_promotions
WHERE org_id = sqlc.arg(org_id) AND state = 'PROVISIONAL'
ORDER BY expires_at, id
LIMIT sqlc.arg(max_rows)
FOR UPDATE SKIP LOCKED;

-- name: ConfirmAgentPromotion :one
UPDATE pc.agent_promotions SET state = 'ACTIVE', confirmed_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'PROVISIONAL' AND expires_at > now()
RETURNING *;

-- name: ExpireAgentPromotion :one
UPDATE pc.agent_promotions SET state = 'EXPIRED', expired_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'PROVISIONAL' AND expires_at <= now()
RETURNING *;
