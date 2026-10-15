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

-- The operations an agent is promoted for in an environment now.
-- name: ActivePromotedOperations :many
SELECT operation FROM pc.agent_promotions
WHERE org_id = sqlc.arg(org_id) AND agent_id = sqlc.arg(agent_id) AND environment_id = sqlc.arg(environment_id)
  AND state = 'ACTIVE'
ORDER BY operation;

-- name: ActiveAgentPromotion :one
SELECT * FROM pc.agent_promotions
WHERE org_id = sqlc.arg(org_id) AND agent_id = sqlc.arg(agent_id) AND environment_id = sqlc.arg(environment_id)
  AND operation = sqlc.arg(operation) AND state = 'ACTIVE';

-- name: InsertAgentPromotion :one
INSERT INTO pc.agent_promotions (org_id, id, agent_id, environment_id, operation, state, checks, failure_behavior,
    promoted_by, credential_id)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(agent_id), sqlc.arg(environment_id), sqlc.arg(operation), 'ACTIVE',
    sqlc.arg(checks), sqlc.arg(failure_behavior), sqlc.arg(promoted_by), sqlc.arg(credential_id))
RETURNING *;

-- name: GetAgentPromotion :one
SELECT * FROM pc.agent_promotions WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: RevokeAgentPromotion :one
UPDATE pc.agent_promotions
SET state = 'REVOKED', revoked_by = sqlc.arg(revoked_by), revoked_at = now(), revoke_reason = sqlc.arg(reason)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'ACTIVE'
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
