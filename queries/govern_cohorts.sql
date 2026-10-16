-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Fleet cohorts (G0 M11 part 2, D40, HR-291): static members plus the
-- agents a cohort's rule matches; the queue, changes and fleet overview
-- read the agents, their grants, promotions and approvals.

-- name: InsertFleetCohort :one
INSERT INTO pc.fleet_cohorts (org_id, id, name, description, rule, owner_user_id, baseline, created_by)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(name), sqlc.arg(description), sqlc.narg(rule), sqlc.arg(owner_user_id),
    sqlc.narg(baseline), sqlc.arg(created_by))
RETURNING *;

-- name: UpdateFleetCohort :one
UPDATE pc.fleet_cohorts
SET name = sqlc.arg(name), description = sqlc.arg(description), rule = sqlc.narg(rule), owner_user_id = sqlc.arg(owner_user_id),
    baseline = sqlc.narg(baseline), updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id)
RETURNING *;

-- name: GetFleetCohort :one
SELECT * FROM pc.fleet_cohorts WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: LockFleetCohort :one
SELECT * FROM pc.fleet_cohorts WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) FOR UPDATE;

-- name: ListFleetCohorts :many
SELECT c.*, (SELECT count(*) FROM pc.fleet_cohort_members m WHERE m.org_id = c.org_id AND m.cohort_id = c.id)::integer AS static_members
FROM pc.fleet_cohorts c
WHERE c.org_id = sqlc.arg(org_id) AND (sqlc.narg(after)::text IS NULL OR c.name > sqlc.narg(after)::text)
ORDER BY c.name
LIMIT sqlc.arg(max_rows);

-- name: DeleteFleetCohortMembers :execrows
DELETE FROM pc.fleet_cohort_members WHERE org_id = sqlc.arg(org_id) AND cohort_id = sqlc.arg(cohort_id);

-- name: DeleteFleetCohort :execrows
DELETE FROM pc.fleet_cohorts WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: AddFleetCohortMember :execrows
INSERT INTO pc.fleet_cohort_members (org_id, cohort_id, agent_id, added_by)
VALUES (sqlc.arg(org_id), sqlc.arg(cohort_id), sqlc.arg(agent_id), sqlc.arg(added_by))
ON CONFLICT DO NOTHING;

-- name: RemoveFleetCohortMember :execrows
DELETE FROM pc.fleet_cohort_members
WHERE org_id = sqlc.arg(org_id) AND cohort_id = sqlc.arg(cohort_id) AND agent_id = sqlc.arg(agent_id);

-- A cohort's agents: its static members and, with a rule, every agent
-- matching each field the rule gives, by id.
-- name: FleetCohortAgents :many
SELECT a.*,
       EXISTS (SELECT 1 FROM pc.fleet_cohort_members m
               WHERE m.org_id = a.org_id AND m.cohort_id = sqlc.arg(cohort_id) AND m.agent_id = a.id)::boolean AS static_member
FROM pc.agents a
WHERE a.org_id = sqlc.arg(org_id)
  AND (EXISTS (SELECT 1 FROM pc.fleet_cohort_members m
               WHERE m.org_id = a.org_id AND m.cohort_id = sqlc.arg(cohort_id) AND m.agent_id = a.id)
       OR (sqlc.arg(has_rule)::boolean
           AND (sqlc.narg(rule_team_id)::uuid IS NULL OR a.team_id = sqlc.narg(rule_team_id)::uuid)
           AND (sqlc.narg(rule_environment_id)::uuid IS NULL OR a.environment_id = sqlc.narg(rule_environment_id)::uuid)
           AND (sqlc.narg(rule_task_type)::text IS NULL OR a.task_type = sqlc.narg(rule_task_type)::text)))
  AND (sqlc.narg(after)::uuid IS NULL OR a.id > sqlc.narg(after)::uuid)
ORDER BY a.id
LIMIT sqlc.arg(max_rows);

-- name: SetAgentTaskType :execrows
UPDATE pc.agents SET task_type = sqlc.narg(task_type), updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- What the fleet overview and a cohort's queue show about agents: owner,
-- environment kind, last run, promoted operations, active grants and
-- pending approvals. last_run_at is the epoch for an agent that never ran.
-- name: FleetAgentFacts :many
SELECT a.id, a.name, a.state, a.owner_user_id, a.environment_id, a.team_id, a.task_type,
       coalesce(e.kind, '')::text AS environment_kind,
       coalesce((SELECT max(r.created_at) FROM pc.runs r WHERE r.org_id = a.org_id AND r.agent_id = a.id),
                'epoch'::timestamptz)::timestamptz AS last_run_at,
       ARRAY(SELECT p.operation FROM pc.agent_promotions p
             WHERE p.org_id = a.org_id AND p.agent_id = a.id AND p.environment_id = a.environment_id AND p.state = 'ACTIVE'
             ORDER BY p.operation)::text[] AS promoted,
       (SELECT count(*) FROM pc.grants g
        JOIN pc.grant_revisions gr ON gr.org_id = g.org_id AND gr.grant_id = g.id AND gr.revision = g.current_revision
        WHERE g.org_id = a.org_id AND g.agent_id = a.id AND g.state = 'ACTIVE' AND gr.expires_at > now())::integer AS active_grants,
       (SELECT count(*) FROM pc.approval_requests q
        WHERE q.org_id = a.org_id AND q.agent_id = a.id AND q.state IN ('PENDING', 'EVIDENCE_REQUESTED'))::integer AS pending_approvals
FROM pc.agents a
LEFT JOIN pc.environments e ON e.org_id = a.org_id AND e.id = a.environment_id
WHERE a.org_id = sqlc.arg(org_id) AND a.id = ANY (sqlc.arg(ids)::uuid[])
ORDER BY a.id;

-- Every agent of the org, by id (the fleet overview's pages).
-- name: FleetAgentIDs :many
SELECT id FROM pc.agents
WHERE org_id = sqlc.arg(org_id) AND (sqlc.narg(after)::uuid IS NULL OR id > sqlc.narg(after)::uuid)
ORDER BY id
LIMIT sqlc.arg(max_rows);

-- The active, unexpired root grants of agents, with their current
-- revision, for the baseline comparison.
-- name: FleetActiveGrants :many
SELECT g.id, g.agent_id, r.bounds, r.limits, r.not_before, r.expires_at
FROM pc.grants g
JOIN pc.grant_revisions r ON r.org_id = g.org_id AND r.grant_id = g.id AND r.revision = g.current_revision
WHERE g.org_id = sqlc.arg(org_id) AND g.agent_id = ANY (sqlc.arg(agent_ids)::uuid[]) AND g.parent_id IS NULL
  AND g.state = 'ACTIVE' AND r.expires_at > now()
ORDER BY g.id
LIMIT 2000;

-- Grant revisions of agents since a time (revision 1 is the issuance).
-- name: FleetGrantRevisionsSince :many
SELECT r.grant_id, g.agent_id, r.revision, r.widens, r.created_by, r.created_at
FROM pc.grant_revisions r
JOIN pc.grants g ON g.org_id = r.org_id AND g.id = r.grant_id
WHERE r.org_id = sqlc.arg(org_id) AND g.agent_id = ANY (sqlc.arg(agent_ids)::uuid[]) AND r.created_at >= sqlc.arg(since)
ORDER BY r.created_at, r.id
LIMIT 500;

-- name: FleetGrantRevocationsSince :many
SELECT g.id, g.agent_id, g.revoked_at::timestamptz AS revoked_at, coalesce(g.revoke_reason, '')::text AS reason
FROM pc.grants g
WHERE g.org_id = sqlc.arg(org_id) AND g.agent_id = ANY (sqlc.arg(agent_ids)::uuid[]) AND g.revoked_at >= sqlc.arg(since)
ORDER BY g.revoked_at, g.id
LIMIT 500;

-- name: FleetMembersAddedSince :many
SELECT agent_id, added_by, added_at FROM pc.fleet_cohort_members
WHERE org_id = sqlc.arg(org_id) AND cohort_id = sqlc.arg(cohort_id) AND added_at >= sqlc.arg(since)
ORDER BY added_at, agent_id
LIMIT 500;

-- name: FleetPolicyVersionsPublishedSince :many
SELECT v.id, v.version, p.bundle_id, v.published_at::timestamptz AS published_at
FROM pc.policy_versions v
JOIN pc.policies p ON p.org_id = v.org_id AND p.id = v.policy_id
WHERE v.org_id = sqlc.arg(org_id) AND v.published_at >= sqlc.arg(since)
ORDER BY v.published_at, v.id
LIMIT 100;

-- name: FleetPackageActivationsSince :many
SELECT p.name, v.version, v.changed_at
FROM pc.package_versions v
JOIN pc.tool_packages p ON p.org_id = v.org_id AND p.id = v.package_id
WHERE v.org_id = sqlc.arg(org_id) AND v.state = 'ACTIVE' AND v.changed_at >= sqlc.arg(since)
ORDER BY v.changed_at, p.name, v.version
LIMIT 100;

-- name: FleetPromotionsSince :many
SELECT * FROM pc.agent_promotions
WHERE org_id = sqlc.arg(org_id) AND agent_id = ANY (sqlc.arg(agent_ids)::uuid[])
  AND (promoted_at >= sqlc.arg(since) OR revoked_at >= sqlc.arg(since))
ORDER BY promoted_at, id
LIMIT 500;

-- A cohort's static members with what their paths are read from.
-- name: FleetCohortStaticAgents :many
SELECT a.* FROM pc.agents a
JOIN pc.fleet_cohort_members m ON m.org_id = a.org_id AND m.agent_id = a.id
WHERE m.org_id = sqlc.arg(org_id) AND m.cohort_id = sqlc.arg(cohort_id)
ORDER BY a.id;
