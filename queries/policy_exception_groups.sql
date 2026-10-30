-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Policy exception groups (G0 M18 D154, migration 00220, HR-477): one
-- exceptable rule waived for the agents a fleet cohort held at approval,
-- one policy_exceptions row per agent. Every transition is conditional
-- (HR-004).

-- name: InsertPolicyExceptionGroup :one
INSERT INTO pc.policy_exception_groups (org_id, id, cohort_id, bundle_id, rule_id, rule_digest, operations, reason, owner_id,
    requested_by, requested_expiry, cohort_digest)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(cohort_id), sqlc.arg(bundle_id), sqlc.arg(rule_id), sqlc.arg(rule_digest),
    sqlc.arg(operations)::text[], sqlc.arg(reason), sqlc.arg(owner_id), sqlc.arg(requested_by),
    now() + make_interval(secs => sqlc.arg(expires_in_seconds)::bigint), sqlc.arg(cohort_digest))
RETURNING *;

-- name: GetPolicyExceptionGroup :one
SELECT * FROM pc.policy_exception_groups WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: LockPolicyExceptionGroup :one
SELECT * FROM pc.policy_exception_groups WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) FOR UPDATE;

-- A member row of a pending group: it repeats what the group waives (the
-- 00220 trigger checks it) for one agent of the snapshot.
-- name: InsertPolicyExceptionGroupMember :one
INSERT INTO pc.policy_exceptions (org_id, id, bundle_id, rule_id, rule_digest, agent_id, operations, reason, owner_id,
    requested_by, requested_expiry, group_id)
SELECT g.org_id, sqlc.arg(id), g.bundle_id, g.rule_id, g.rule_digest, sqlc.arg(agent_id), g.operations, g.reason, g.owner_id,
    g.requested_by, g.requested_expiry, g.id
FROM pc.policy_exception_groups g
WHERE g.org_id = sqlc.arg(org_id) AND g.id = sqlc.arg(group_id) AND g.state = 'PENDING'
RETURNING *;

-- Activates every pending member row of a group (in the confirming
-- transaction, right after they were inserted).
-- name: ActivatePolicyExceptionGroupMembers :many
UPDATE pc.policy_exceptions
SET state = 'ACTIVE', activated_at = now(), expires_at = least(requested_expiry, now() + interval '30 days')
WHERE org_id = sqlc.arg(org_id) AND group_id = sqlc.arg(group_id)::uuid AND state = 'PENDING' AND requested_expiry > now()
RETURNING *;

-- name: ActivatePolicyExceptionGroup :one
UPDATE pc.policy_exception_groups
SET state = 'ACTIVE', activated_at = now(), expires_at = least(requested_expiry, now() + interval '30 days'),
    truncated = sqlc.arg(truncated)::boolean
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'PENDING' AND requested_expiry > now()
RETURNING *;

-- name: DeclinePolicyExceptionGroup :one
UPDATE pc.policy_exception_groups SET state = 'DECLINED'
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'PENDING'
RETURNING *;

-- name: RevokePolicyExceptionGroup :one
UPDATE pc.policy_exception_groups SET state = 'REVOKED', revoked_by = sqlc.arg(revoked_by), revoked_reason = sqlc.arg(revoked_reason)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state IN ('PENDING', 'ACTIVE')
  AND coalesce(expires_at, requested_expiry) > now()
RETURNING *;

-- Revoking a group revokes each of its open member rows.
-- name: RevokePolicyExceptionGroupMembers :many
UPDATE pc.policy_exceptions SET state = 'REVOKED', revoked_by = sqlc.arg(revoked_by), revoked_reason = sqlc.arg(revoked_reason)
WHERE org_id = sqlc.arg(org_id) AND group_id = sqlc.arg(group_id)::uuid AND state IN ('PENDING', 'ACTIVE')
  AND coalesce(expires_at, requested_expiry) > now()
RETURNING *;

-- Groups the sweep closes: pending past their requested expiry and active
-- past their expiry. Their member rows expire through the exception sweep.
-- name: ExpirePolicyExceptionGroups :many
UPDATE pc.policy_exception_groups x SET state = 'EXPIRED'
WHERE x.org_id = sqlc.arg(org_id) AND x.id IN (
    SELECT g.id FROM pc.policy_exception_groups g
    WHERE g.org_id = x.org_id AND g.state IN ('PENDING', 'ACTIVE')
      AND coalesce(g.expires_at, g.requested_expiry) <= now()
    ORDER BY g.id
    LIMIT sqlc.arg(max_rows))
RETURNING *;

-- Pending groups whose EXCEPTION change request ended without approval, or
-- that never got one (as DeclineEndedPolicyExceptions).
-- name: DeclineEndedPolicyExceptionGroups :many
UPDATE pc.policy_exception_groups x SET state = 'DECLINED'
WHERE x.org_id = sqlc.arg(org_id) AND x.id IN (
    SELECT g.id FROM pc.policy_exception_groups g
    WHERE g.org_id = x.org_id AND g.state = 'PENDING' AND g.requested_expiry > now()
      AND g.created_at < now() - interval '5 minutes'
      AND NOT EXISTS (
          SELECT 1 FROM pc.policy_change_requests r
          WHERE r.org_id = g.org_id AND r.kind = 'EXCEPTION' AND r.subject_id = g.id
            AND (r.state = 'APPROVED' OR (r.state = 'PENDING' AND r.expires_at > now())))
    ORDER BY g.id
    LIMIT sqlc.arg(max_rows))
RETURNING *;

-- Newest first; an open group past its expiry reads as EXPIRED.
-- name: ListPolicyExceptionGroupsPage :many
SELECT g.*, (CASE WHEN g.state IN ('PENDING', 'ACTIVE') AND coalesce(g.expires_at, g.requested_expiry) <= now()
                  THEN 'EXPIRED' ELSE g.state END)::text AS effective_state
FROM pc.policy_exception_groups g
WHERE g.org_id = sqlc.arg(org_id)
  AND (sqlc.narg(cohort_id)::uuid IS NULL OR g.cohort_id = sqlc.narg(cohort_id)::uuid)
  AND (sqlc.narg(state)::text IS NULL
       OR (CASE WHEN g.state IN ('PENDING', 'ACTIVE') AND coalesce(g.expires_at, g.requested_expiry) <= now()
                THEN 'EXPIRED' ELSE g.state END) = sqlc.narg(state)::text)
  AND (sqlc.narg(before)::uuid IS NULL OR g.id < sqlc.narg(before)::uuid)
ORDER BY g.id DESC
LIMIT sqlc.arg(max_rows);

-- name: ReadPolicyExceptionGroup :one
SELECT g.*, (CASE WHEN g.state IN ('PENDING', 'ACTIVE') AND coalesce(g.expires_at, g.requested_expiry) <= now()
                  THEN 'EXPIRED' ELSE g.state END)::text AS effective_state
FROM pc.policy_exception_groups g
WHERE g.org_id = sqlc.arg(org_id) AND g.id = sqlc.arg(id);

-- The agents a group covers (its snapshot), by agent id.
-- name: PolicyExceptionGroupAgents :many
SELECT agent_id FROM pc.policy_exceptions
WHERE org_id = sqlc.arg(org_id) AND group_id = sqlc.arg(group_id)::uuid
ORDER BY agent_id;

-- Active groups that expire within the window, for the owner's one notice
-- (their member rows are left out of ExpiringPolicyExceptions).
-- name: ExpiringPolicyExceptionGroups :many
SELECT * FROM pc.policy_exception_groups
WHERE org_id = sqlc.arg(org_id) AND state = 'ACTIVE' AND expires_at > now()
  AND expires_at <= now() + make_interval(secs => sqlc.arg(within_seconds)::bigint)
ORDER BY id
LIMIT sqlc.arg(max_rows);
