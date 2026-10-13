-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Agent inventory (M3, G0 M3). Every query names org_id explicitly and runs
-- in a tenant transaction (forced RLS). Lifecycle changes are conditional on
-- the expected state (HR-004); a 0-row result is a lost race. Lists page by
-- id (UUIDv7, creation order).

-- name: InsertAgent :one
INSERT INTO pc.agents (org_id, id, name, purpose, team_id, environment_id, owner_user_id, backup_owner_user_id,
    execution_context, state, created_by, claimed_at)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(name), sqlc.arg(purpose), sqlc.arg(team_id), sqlc.arg(environment_id),
    sqlc.arg(owner_user_id), sqlc.narg(backup_owner_user_id), sqlc.arg(execution_context), 'CLAIMED',
    sqlc.arg(created_by), now())
RETURNING *;

-- name: InsertDiscoveredAgent :one
INSERT INTO pc.agents (org_id, id, name, state, created_by)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(name), 'DISCOVERED', sqlc.arg(created_by))
RETURNING *;

-- name: GetAgent :one
SELECT * FROM pc.agents WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: LockAgent :one
SELECT * FROM pc.agents WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) FOR UPDATE;

-- name: ListAgents :many
SELECT * FROM pc.agents
WHERE org_id = sqlc.arg(org_id) AND id > coalesce(sqlc.arg(after)::uuid, '00000000-0000-0000-0000-000000000000')
  AND (cardinality(sqlc.arg(states)::text[]) = 0 OR state = ANY (sqlc.arg(states)::text[]))
  AND (sqlc.narg(team_id)::uuid IS NULL OR team_id = sqlc.narg(team_id)::uuid)
ORDER BY id
LIMIT sqlc.arg(page_limit);

-- name: OrgHasAgents :one
SELECT EXISTS (SELECT 1 FROM pc.agents WHERE org_id = sqlc.arg(org_id))::boolean;

-- Governed agents for the edition limit: claimed and not retired (PRODUCT
-- §7 item 4). The caller holds the org's agent-limit lock.
-- name: CountGovernedAgents :one
SELECT count(*) FROM pc.agents
WHERE org_id = sqlc.arg(org_id) AND claimed_at IS NOT NULL AND state <> 'RETIRED';

-- Serializes agent creation and claims per org so the edition limit cannot
-- be exceeded by concurrent requests.
-- name: LockAgentLimit :exec
SELECT pg_advisory_xact_lock(hashtextextended('pc.agent_limit:' || sqlc.arg(org_id)::text, 0));

-- name: UpdateAgentText :one
UPDATE pc.agents
SET name = coalesce(sqlc.narg(name), name), purpose = coalesce(sqlc.narg(purpose), purpose), updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state <> 'RETIRED'
RETURNING *;

-- name: TransferAgentOwnership :one
UPDATE pc.agents
SET owner_user_id = sqlc.arg(owner_user_id), backup_owner_user_id = sqlc.narg(backup_owner_user_id), updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND claimed_at IS NOT NULL AND state <> 'RETIRED'
RETURNING *;

-- name: ClaimDiscoveredAgent :one
UPDATE pc.agents
SET name = sqlc.arg(name), purpose = sqlc.arg(purpose), team_id = sqlc.arg(team_id),
    environment_id = sqlc.arg(environment_id), owner_user_id = sqlc.arg(owner_user_id),
    backup_owner_user_id = sqlc.narg(backup_owner_user_id), execution_context = sqlc.arg(execution_context),
    state = 'CLAIMED', claimed_at = now(), updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'DISCOVERED'
RETURNING *;

-- name: SetAgentState :one
UPDATE pc.agents
SET state = sqlc.arg(to_state), suspended_from = sqlc.narg(suspended_from), updated_at = now(),
    retired_at = CASE WHEN sqlc.arg(to_state)::text = 'RETIRED' THEN now() ELSE retired_at END
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = sqlc.arg(from_state)
RETURNING *;

-- name: InsertAgentChange :exec
INSERT INTO pc.agent_changes (org_id, id, agent_id, kind, actor, reason, details)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(agent_id), sqlc.arg(kind), sqlc.arg(actor), sqlc.arg(reason),
    sqlc.arg(details));

-- name: ListAgentChanges :many
SELECT * FROM pc.agent_changes
WHERE org_id = sqlc.arg(org_id) AND agent_id = sqlc.arg(agent_id)
  AND id > coalesce(sqlc.arg(after)::uuid, '00000000-0000-0000-0000-000000000000')
ORDER BY id
LIMIT sqlc.arg(page_limit);

-- Placement: the hierarchy path an agent's permissions are checked at.
-- name: GetTeamPlacement :one
SELECT business_unit_id, state FROM pc.teams WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: GetEnvironmentPlacement :one
SELECT team_id, state FROM pc.environments WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: GetUserState :one
SELECT state FROM pc.users WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- Retirement (F023) and suspension cascades.
-- name: RevokeAgentInstances :execrows
UPDATE pc.agent_instances
SET state = 'REVOKED', revoke_reason = sqlc.arg(reason), decided_by = sqlc.arg(decided_by), decided_at = now(),
    updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND agent_id = sqlc.arg(agent_id) AND state IN ('PENDING_ADMISSION', 'ADMITTED');

-- name: RevokeAgentEnrollmentTokens :execrows
UPDATE pc.enrollment_tokens SET state = 'REVOKED', revoked_at = now()
WHERE org_id = sqlc.arg(org_id) AND agent_id = sqlc.arg(agent_id) AND state = 'ACTIVE';

-- Revokes the agent's active runs and their descendants (G0 M3 17).
-- name: RevokeAgentRuns :execrows
WITH RECURSIVE tree AS (
    SELECT r.id FROM pc.runs r WHERE r.org_id = sqlc.arg(org_id) AND r.agent_id = sqlc.arg(agent_id) AND r.state = 'ACTIVE'
    UNION
    SELECT c.id FROM pc.runs c JOIN tree t ON c.parent_run_id = t.id WHERE c.org_id = sqlc.arg(org_id)
)
UPDATE pc.runs
SET state = 'REVOKED',
    end_reason = CASE WHEN runs.agent_id = sqlc.arg(agent_id) THEN sqlc.arg(reason)::text ELSE 'parent_ended' END,
    ended_at = now()
WHERE runs.org_id = sqlc.arg(org_id) AND runs.id IN (SELECT id FROM tree) AND runs.state = 'ACTIVE';

-- name: CloseOpenAgentEntries :execrows
UPDATE pc.waitlist_entries
SET state = sqlc.arg(state), decided_by = sqlc.arg(decided_by), decided_at = now(),
    decision_reason = sqlc.arg(reason)
WHERE org_id = sqlc.arg(org_id) AND agent_id = sqlc.arg(agent_id)::uuid AND kind = 'ADMISSION' AND state = 'OPEN'
  AND (sqlc.narg(subject_type)::text IS NULL OR subject_type = sqlc.narg(subject_type)::text);

-- name: GetAgentDiscovery :one
SELECT * FROM pc.discoveries WHERE org_id = sqlc.arg(org_id) AND agent_id = sqlc.arg(agent_id)
ORDER BY first_seen_at LIMIT 1;

-- name: MoveDiscovery :exec
UPDATE pc.discoveries SET agent_id = sqlc.arg(to_agent_id), state = 'CLAIMED'
WHERE org_id = sqlc.arg(org_id) AND agent_id = sqlc.arg(from_agent_id) AND state = 'OPEN';

-- name: SetAgentDiscoveryState :exec
UPDATE pc.discoveries SET state = sqlc.arg(state)
WHERE org_id = sqlc.arg(org_id) AND agent_id = sqlc.arg(agent_id) AND state = 'OPEN';

-- name: AgentSummaryCounts :one
SELECT
    (SELECT count(*) FROM pc.agent_instances i
      WHERE i.org_id = sqlc.arg(org_id) AND i.agent_id = sqlc.arg(agent_id) AND i.state = 'PENDING_ADMISSION')::int AS pending,
    (SELECT count(*) FROM pc.agent_instances i
      WHERE i.org_id = sqlc.arg(org_id) AND i.agent_id = sqlc.arg(agent_id) AND i.state = 'ADMITTED')::int AS admitted,
    (SELECT count(*) FROM pc.agent_instances i
      WHERE i.org_id = sqlc.arg(org_id) AND i.agent_id = sqlc.arg(agent_id) AND i.decided_at IS NOT NULL
        AND i.state IN ('ADMITTED', 'REVOKED', 'EXPIRED'))::int AS ever_admitted,
    (SELECT coalesce(max(i.att_level), 0) FROM pc.agent_instances i
      WHERE i.org_id = sqlc.arg(org_id) AND i.agent_id = sqlc.arg(agent_id) AND i.state = 'ADMITTED')::int AS highest_level,
    (SELECT coalesce(max(i.last_seen_at), 'epoch') FROM pc.agent_instances i
      WHERE i.org_id = sqlc.arg(org_id) AND i.agent_id = sqlc.arg(agent_id))::timestamptz AS last_seen,
    (SELECT count(*) FROM pc.agent_instances i
      WHERE i.org_id = sqlc.arg(org_id) AND i.agent_id = sqlc.arg(agent_id) AND i.needs_review)::int AS needs_review,
    (SELECT count(*) FROM pc.runs r
      WHERE r.org_id = sqlc.arg(org_id) AND r.agent_id = sqlc.arg(agent_id) AND r.state = 'ACTIVE')::int AS active_runs,
    (SELECT count(*) FROM pc.waitlist_entries w
      WHERE w.org_id = sqlc.arg(org_id) AND w.agent_id = sqlc.arg(agent_id) AND w.state = 'OPEN')::int AS open_entries;

-- Scan findings (PN-001.1, F015): a finding already submitted is only
-- counted, with its latest observations.
-- A finding is matched within its own source only: a person's scan never
-- touches a finding of the gateway's org scan, nor the reverse (HR-209).
-- name: TouchScanDiscovery :execrows
UPDATE pc.discoveries SET seen_count = seen_count + 1, last_seen_at = now(), observed = sqlc.arg(observed)
WHERE org_id = sqlc.arg(org_id) AND scan_key = sqlc.arg(scan_key) AND source = sqlc.arg(source);

-- name: InsertScanDiscovery :one
-- A local scan's (source scan) or a gateway's organization scan's
-- (github_scan) finding.
INSERT INTO pc.discoveries (org_id, id, agent_id, source, scan_key, observed)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(agent_id), sqlc.arg(source), sqlc.arg(scan_key), sqlc.arg(observed))
RETURNING *;

-- CountOpenDiscoveriesOfSource counts the open discoveries of one source:
-- the gateway's unknown keys, people's local scans and the org scans are
-- each capped on their own, so none fills another's room (HR-148, HR-209).
-- name: CountOpenDiscoveriesOfSource :one
SELECT count(*)::int FROM pc.discoveries
WHERE org_id = sqlc.arg(org_id) AND state = 'OPEN' AND source = sqlc.arg(source);

-- GetScanDiscovery is a scan finding by its key within its source.
-- name: GetScanDiscovery :one
SELECT id, agent_id, state, observed FROM pc.discoveries
WHERE org_id = sqlc.arg(org_id) AND source = sqlc.arg(source) AND scan_key = sqlc.arg(scan_key);

-- ReopenScanDiscovery reopens a dismissed finding for a new DISCOVERED
-- agent: what its route may do changed since it was dismissed (HR-209).
-- name: ReopenScanDiscovery :execrows
UPDATE pc.discoveries
SET state = 'OPEN', agent_id = sqlc.arg(agent_id), observed = sqlc.arg(observed), seen_count = seen_count + 1, last_seen_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'DISMISSED';
