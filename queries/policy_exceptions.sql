-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Policy exceptions (G0 M11.1 D14, HR-235): one exceptable rule waived for
-- one agent and the listed operations, until the database clock passes its
-- expiry. Every transition is conditional (HR-004).

-- name: InsertPolicyException :one
INSERT INTO pc.policy_exceptions (org_id, id, bundle_id, rule_id, rule_digest, agent_id, operations, reason, owner_id,
    requested_by, requested_expiry)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(bundle_id), sqlc.arg(rule_id), sqlc.arg(rule_digest), sqlc.arg(agent_id),
    sqlc.arg(operations)::text[], sqlc.arg(reason), sqlc.arg(owner_id), sqlc.arg(requested_by),
    now() + make_interval(secs => sqlc.arg(expires_in_seconds)::bigint))
RETURNING *;

-- name: GetPolicyException :one
SELECT * FROM pc.policy_exceptions WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- Activation sets activated_at and expires_at from the database clock (the
-- trigger enforces it too).
-- name: ActivatePolicyException :one
UPDATE pc.policy_exceptions
SET state = 'ACTIVE', activated_at = now(), expires_at = least(requested_expiry, now() + interval '30 days')
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'PENDING' AND requested_expiry > now()
RETURNING *;

-- name: DeclinePolicyException :one
UPDATE pc.policy_exceptions SET state = 'DECLINED'
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'PENDING'
RETURNING *;

-- name: RevokePolicyException :one
UPDATE pc.policy_exceptions SET state = 'REVOKED', revoked_by = sqlc.arg(revoked_by), revoked_reason = sqlc.arg(revoked_reason)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state IN ('PENDING', 'ACTIVE')
  AND coalesce(expires_at, requested_expiry) > now()
RETURNING *;

-- The exceptions the expiry sweep closes: pending past their requested
-- expiry and active past their expiry.
-- name: ExpirePolicyExceptions :many
UPDATE pc.policy_exceptions x SET state = 'EXPIRED'
WHERE x.org_id = sqlc.arg(org_id) AND x.id IN (
    SELECT e.id FROM pc.policy_exceptions e
    WHERE e.org_id = x.org_id AND e.state IN ('PENDING', 'ACTIVE')
      AND coalesce(e.expires_at, e.requested_expiry) <= now()
    ORDER BY e.id
    LIMIT sqlc.arg(max_rows))
RETURNING *;

-- Active exceptions that expire within the window, for the owner's notice.
-- name: ExpiringPolicyExceptions :many
SELECT * FROM pc.policy_exceptions
WHERE org_id = sqlc.arg(org_id) AND state = 'ACTIVE' AND expires_at > now()
  AND expires_at <= now() + make_interval(secs => sqlc.arg(within_seconds)::bigint)
ORDER BY id
LIMIT sqlc.arg(max_rows);

-- The exceptions that can waive a rule for an agent now (the Authority's
-- policy read, in its snapshot transaction).
-- name: ActivePolicyExceptionsForAgent :many
SELECT * FROM pc.policy_exceptions
WHERE org_id = sqlc.arg(org_id) AND agent_id = sqlc.arg(agent_id) AND state = 'ACTIVE' AND expires_at > now()
ORDER BY id
LIMIT 256;

-- Newest first; an open exception past its expiry reads as EXPIRED.
-- name: ListPolicyExceptionsPage :many
SELECT e.*, (CASE WHEN e.state IN ('PENDING', 'ACTIVE') AND coalesce(e.expires_at, e.requested_expiry) <= now()
                  THEN 'EXPIRED' ELSE e.state END)::text AS effective_state
FROM pc.policy_exceptions e
WHERE e.org_id = sqlc.arg(org_id)
  AND (sqlc.narg(agent_id)::uuid IS NULL OR e.agent_id = sqlc.narg(agent_id)::uuid)
  AND (sqlc.narg(rule_id)::text IS NULL OR e.rule_id = sqlc.narg(rule_id)::text)
  AND (sqlc.narg(state)::text IS NULL
       OR (CASE WHEN e.state IN ('PENDING', 'ACTIVE') AND coalesce(e.expires_at, e.requested_expiry) <= now()
                THEN 'EXPIRED' ELSE e.state END) = sqlc.narg(state)::text)
  AND (sqlc.narg(before)::uuid IS NULL OR e.id < sqlc.narg(before)::uuid)
ORDER BY e.id DESC
LIMIT sqlc.arg(max_rows);

-- name: ReadPolicyException :one
SELECT e.*, (CASE WHEN e.state IN ('PENDING', 'ACTIVE') AND coalesce(e.expires_at, e.requested_expiry) <= now()
                  THEN 'EXPIRED' ELSE e.state END)::text AS effective_state
FROM pc.policy_exceptions e
WHERE e.org_id = sqlc.arg(org_id) AND e.id = sqlc.arg(id);
