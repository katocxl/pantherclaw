-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Grants and guardrails (M4 part 2). Removals of authority take the org
-- containment row first (RaiseContainmentEpoch); uses of it take it FOR
-- SHARE first (ShareContainment), then read grants (design decision 8).
-- Every state change is conditional (HR-004).

-- name: GetGrant :one
SELECT g.id, g.agent_id, g.instance_id, g.principal_user_id, g.principal_sa_id, g.environment_id, g.parent_id,
       g.depth, g.state, g.current_revision, g.grantor_kind, g.grantor_id, g.basis,
       r.task_ref, r.not_before, r.expires_at, r.bounds, r.requirements, r.limits,
       r.delegation_depth, r.max_children, r.min_attestation, r.created_at, g.ceiling_id, g.automation_execution_id
FROM pc.grants g
JOIN pc.grant_revisions r ON r.org_id = g.org_id AND r.grant_id = g.id AND r.revision = g.current_revision
WHERE g.org_id = sqlc.arg(org_id) AND g.id = sqlc.arg(id);

-- GetGrantChain returns a grant and every ancestor, root first.
-- name: GetGrantChain :many
SELECT g.id, g.agent_id, g.instance_id, g.principal_user_id, g.principal_sa_id, g.environment_id, g.parent_id,
       g.depth, g.state, g.current_revision, g.grantor_kind, g.grantor_id, g.basis,
       r.task_ref, r.not_before, r.expires_at, r.bounds, r.requirements, r.limits,
       r.delegation_depth, r.max_children, r.min_attestation, r.created_at, g.ceiling_id, g.automation_execution_id
FROM pc.grant_lineage l
JOIN pc.grants g ON g.org_id = l.org_id AND g.id = l.ancestor_id
JOIN pc.grant_revisions r ON r.org_id = g.org_id AND r.grant_id = g.id AND r.revision = g.current_revision
WHERE l.org_id = sqlc.arg(org_id) AND l.grant_id = sqlc.arg(id)
ORDER BY l.distance DESC;

-- name: InsertGrant :exec
INSERT INTO pc.grants (org_id, id, agent_id, instance_id, principal_user_id, principal_sa_id, environment_id,
                       parent_id, depth, current_revision, grantor_kind, grantor_id, basis, ceiling_id,
                       automation_execution_id)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(agent_id), sqlc.narg(instance_id), sqlc.narg(principal_user_id),
        sqlc.narg(principal_sa_id), sqlc.arg(environment_id), sqlc.narg(parent_id), sqlc.arg(depth),
        sqlc.arg(current_revision), sqlc.arg(grantor_kind), sqlc.arg(grantor_id), sqlc.arg(basis), sqlc.narg(ceiling_id),
        sqlc.narg(automation_execution_id));

-- name: InsertGrantRevision :exec
INSERT INTO pc.grant_revisions (org_id, id, grant_id, revision, task_ref, not_before, expires_at, bounds,
                                requirements, limits, delegation_depth, max_children, min_attestation, widens, created_by)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(grant_id), sqlc.arg(revision), sqlc.arg(task_ref),
        sqlc.arg(not_before), sqlc.arg(expires_at), sqlc.arg(bounds), sqlc.arg(requirements), sqlc.arg(limits),
        sqlc.arg(delegation_depth), sqlc.arg(max_children), sqlc.arg(min_attestation), sqlc.arg(widens),
        sqlc.arg(created_by));

-- name: InsertGrantLineageSelf :exec
INSERT INTO pc.grant_lineage (org_id, grant_id, ancestor_id, distance)
VALUES (sqlc.arg(org_id), sqlc.arg(grant_id), sqlc.arg(grant_id), 0);

-- name: InsertGrantLineageFromParent :exec
INSERT INTO pc.grant_lineage (org_id, grant_id, ancestor_id, distance)
SELECT l.org_id, sqlc.arg(grant_id), l.ancestor_id, l.distance + 1
FROM pc.grant_lineage l
WHERE l.org_id = sqlc.arg(org_id) AND l.grant_id = sqlc.arg(parent_id);

-- LockGrant locks a parent while a child is delegated from it, so
-- fan-out is counted without a race.
-- name: LockGrant :one
SELECT state, current_revision, children_total
FROM pc.grants
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id)
FOR UPDATE;

-- name: CountActiveChildren :one
SELECT count(*)::integer AS active
FROM pc.grants g
JOIN pc.grant_revisions r ON r.org_id = g.org_id AND r.grant_id = g.id AND r.revision = g.current_revision
WHERE g.org_id = sqlc.arg(org_id) AND g.parent_id = sqlc.arg(parent_id) AND g.state = 'ACTIVE'
  AND r.expires_at > sqlc.arg(at);

-- name: GetChildrenTotal :one
SELECT children_total FROM pc.grants WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: IncrementGrantChildren :execresult
UPDATE pc.grants SET children_total = children_total + 1
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND children_total < sqlc.arg(max_total);

-- name: AdvanceGrantRevision :execresult
UPDATE pc.grants SET current_revision = sqlc.arg(next_revision)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND current_revision = sqlc.arg(prev_revision) AND state = 'ACTIVE';

-- RevokeGrantTree revokes a grant and every descendant in one statement
-- (HR-047) and returns what it revoked.
-- name: RevokeGrantTree :many
UPDATE pc.grants AS g
SET state = 'REVOKED', revoked_at = now(), revoke_reason = sqlc.arg(reason)
FROM pc.grant_lineage AS l
WHERE g.org_id = sqlc.arg(org_id) AND g.state = 'ACTIVE'
  AND l.org_id = g.org_id AND l.grant_id = g.id AND l.ancestor_id = sqlc.arg(id)
RETURNING g.id;

-- BindChildRunGrant gives a child run its delegated grant, once.
-- name: BindChildRunGrant :execresult
UPDATE pc.runs SET grant_id = sqlc.arg(grant_id)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(run_id) AND grant_id IS NULL AND state = 'ACTIVE'
  AND parent_run_id IS NOT NULL;

-- name: GetEnvelopes :many
SELECT e.id, e.scope_kind, e.scope_key, r.revision, r.name, r.bounds, r.requirements, r.limits, r.max_depth,
       r.max_children, r.max_root_lifetime_s, r.repeat_window_s, r.min_attestation, r.created_by, r.created_at
FROM pc.envelopes e
JOIN pc.envelope_revisions r ON r.org_id = e.org_id AND r.envelope_id = e.id AND r.revision = e.current_revision
WHERE e.org_id = sqlc.arg(org_id) AND e.scope_key = ANY(sqlc.arg(scope_keys)::text[]);

-- name: GetEnvelopeHead :one
SELECT id, current_revision FROM pc.envelopes
WHERE org_id = sqlc.arg(org_id) AND scope_key = sqlc.arg(scope_key)
FOR UPDATE;

-- name: InsertEnvelope :exec
INSERT INTO pc.envelopes (org_id, id, scope_kind, scope_key, current_revision)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(scope_kind), sqlc.arg(scope_key), 1);

-- name: AdvanceEnvelopeRevision :execresult
UPDATE pc.envelopes SET current_revision = sqlc.arg(next_revision)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND current_revision = sqlc.arg(prev_revision);

-- name: InsertEnvelopeRevision :exec
INSERT INTO pc.envelope_revisions (org_id, id, envelope_id, revision, name, bounds, requirements, limits,
                                   max_depth, max_children, max_root_lifetime_s, repeat_window_s, min_attestation,
                                   widens, created_by)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(envelope_id), sqlc.arg(revision), sqlc.arg(name), sqlc.arg(bounds),
        sqlc.arg(requirements), sqlc.arg(limits), sqlc.narg(max_depth), sqlc.narg(max_children),
        sqlc.narg(max_root_lifetime_s), sqlc.narg(repeat_window_s), sqlc.arg(min_attestation), sqlc.arg(widens),
        sqlc.arg(created_by));

-- Subjects: what grants need to know about agents, runs and principals.

-- name: SubjectAgent :one
SELECT a.state, a.team_id, a.environment_id, t.business_unit_id
FROM pc.agents a
LEFT JOIN pc.teams t ON t.org_id = a.org_id AND t.id = a.team_id
WHERE a.org_id = sqlc.arg(org_id) AND a.id = sqlc.arg(id);

-- name: SubjectRun :one
SELECT agent_id, instance_id, environment_id, launcher_user_id, launcher_sa_id, launcher_instance_id,
       principal_user_id, principal_sa_id, parent_run_id, grant_id, state, expires_at, task_ref, simulated,
       (state = 'ACTIVE' AND expires_at > now())::boolean AS live
FROM pc.runs
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: SubjectUserActive :one
SELECT state = 'ACTIVE' AS active FROM pc.users WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: SubjectServiceAccountActive :one
SELECT state = 'ACTIVE' AS active FROM pc.service_accounts WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- ListGrants pages through an org's grants, newest first.
-- name: ListGrants :many
SELECT g.id, g.agent_id, g.instance_id, g.principal_user_id, g.principal_sa_id, g.environment_id, g.parent_id,
       g.depth, g.state, g.current_revision, g.grantor_kind, g.grantor_id, g.basis,
       r.task_ref, r.not_before, r.expires_at, r.bounds, r.requirements, r.limits,
       r.delegation_depth, r.max_children, r.min_attestation, r.created_at
FROM pc.grants g
JOIN pc.grant_revisions r ON r.org_id = g.org_id AND r.grant_id = g.id AND r.revision = g.current_revision
WHERE g.org_id = sqlc.arg(org_id)
  AND (sqlc.narg(before)::uuid IS NULL OR g.id < sqlc.narg(before)::uuid)
  AND (sqlc.narg(agent_id)::uuid IS NULL OR g.agent_id = sqlc.narg(agent_id)::uuid)
  AND (sqlc.narg(parent_id)::uuid IS NULL OR g.parent_id = sqlc.narg(parent_id)::uuid)
  AND (sqlc.arg(state)::text = '' OR g.state = sqlc.arg(state)::text)
ORDER BY g.id DESC
LIMIT sqlc.arg(page_limit);

-- GetEnvelopeRevision returns one revision of a guardrail; revision 0 is
-- the current one.
-- name: GetEnvelopeRevision :one
SELECT e.id, e.scope_kind, e.scope_key, r.revision, r.name, r.bounds, r.requirements, r.limits, r.max_depth,
       r.max_children, r.max_root_lifetime_s, r.repeat_window_s, r.min_attestation, r.created_by, r.created_at
FROM pc.envelopes e
JOIN pc.envelope_revisions r ON r.org_id = e.org_id AND r.envelope_id = e.id
WHERE e.org_id = sqlc.arg(org_id) AND e.id = sqlc.arg(id)
  AND r.revision = CASE WHEN sqlc.arg(revision)::integer = 0 THEN e.current_revision ELSE sqlc.arg(revision)::integer END;

-- ListEnvelopes pages through an org's guardrails at their current
-- revision, oldest first.
-- name: ListEnvelopes :many
SELECT e.id, e.scope_kind, e.scope_key, r.revision, r.name, r.bounds, r.requirements, r.limits, r.max_depth,
       r.max_children, r.max_root_lifetime_s, r.repeat_window_s, r.min_attestation, r.created_by, r.created_at
FROM pc.envelopes e
JOIN pc.envelope_revisions r ON r.org_id = e.org_id AND r.envelope_id = e.id AND r.revision = e.current_revision
WHERE e.org_id = sqlc.arg(org_id) AND e.id > coalesce(sqlc.narg(after)::uuid, '00000000-0000-0000-0000-000000000000')
  AND (sqlc.arg(scope_kind)::text = '' OR e.scope_kind = sqlc.arg(scope_kind)::text)
ORDER BY e.id
LIMIT sqlc.arg(page_limit);
