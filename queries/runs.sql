-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Runs (PAP-1 §5, HR-022, HR-146, G0 M3). Run ids are minted here, never by
-- a client. Expiry uses the database clock: an ACTIVE run past expires_at
-- reads as EXPIRED until the janitor records it. Ending or revoking a run
-- revokes its descendants in the same statement; every change is
-- conditional on ACTIVE (HR-004).

-- A child run never outlives not_after (its parent's expiry).
-- name: InsertRun :one
INSERT INTO pc.runs (org_id, id, agent_id, instance_id, environment_id, launcher_user_id, launcher_sa_id,
    launcher_instance_id, principal_user_id, principal_sa_id, principal_source, subject_issuer, subject_subject,
    actor_chain, parent_run_id, depth, grant_id, task_ref, simulated, expires_at)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(agent_id), sqlc.narg(instance_id), sqlc.arg(environment_id),
    sqlc.narg(launcher_user_id), sqlc.narg(launcher_sa_id), sqlc.narg(launcher_instance_id), sqlc.narg(principal_user_id),
    sqlc.narg(principal_sa_id), sqlc.arg(principal_source), sqlc.narg(subject_issuer), sqlc.narg(subject_subject),
    sqlc.arg(actor_chain), sqlc.narg(parent_run_id), sqlc.arg(depth), sqlc.narg(grant_id), sqlc.arg(task_ref), sqlc.arg(simulated),
    LEAST(now() + make_interval(mins => sqlc.arg(ttl_minutes)::int),
          coalesce(sqlc.narg(not_after)::timestamptz, 'infinity'::timestamptz)))
RETURNING *;

-- name: GetRun :one
SELECT sqlc.embed(r),
    (CASE WHEN r.state = 'ACTIVE' AND r.expires_at <= now() THEN 'EXPIRED' ELSE r.state END)::text AS effective_state
FROM pc.runs r WHERE r.org_id = sqlc.arg(org_id) AND r.id = sqlc.arg(id);

-- name: LockRun :one
SELECT sqlc.embed(r),
    (CASE WHEN r.state = 'ACTIVE' AND r.expires_at <= now() THEN 'EXPIRED' ELSE r.state END)::text AS effective_state
FROM pc.runs r WHERE r.org_id = sqlc.arg(org_id) AND r.id = sqlc.arg(id) FOR UPDATE;

-- name: ListRuns :many
SELECT sqlc.embed(r),
    (CASE WHEN r.state = 'ACTIVE' AND r.expires_at <= now() THEN 'EXPIRED' ELSE r.state END)::text AS effective_state
FROM pc.runs r
WHERE r.org_id = sqlc.arg(org_id) AND r.id > coalesce(sqlc.arg(after)::uuid, '00000000-0000-0000-0000-000000000000')
  AND (sqlc.narg(agent_id)::uuid IS NULL OR r.agent_id = sqlc.narg(agent_id)::uuid)
  AND (cardinality(sqlc.arg(states)::text[]) = 0
       OR (CASE WHEN r.state = 'ACTIVE' AND r.expires_at <= now() THEN 'EXPIRED' ELSE r.state END)
          = ANY (sqlc.arg(states)::text[]))
ORDER BY r.id
LIMIT sqlc.arg(page_limit);

-- Ends one run with state and reason, and revokes its active descendants.
-- name: EndRunTree :many
WITH RECURSIVE tree AS (
    SELECT r.id FROM pc.runs r WHERE r.org_id = sqlc.arg(org_id) AND r.id = sqlc.arg(id)
    UNION
    SELECT c.id FROM pc.runs c JOIN tree t ON c.parent_run_id = t.id WHERE c.org_id = sqlc.arg(org_id)
)
UPDATE pc.runs
SET state = CASE WHEN runs.id = sqlc.arg(id) THEN sqlc.arg(state)::text ELSE 'REVOKED' END,
    end_reason = CASE WHEN runs.id = sqlc.arg(id) THEN sqlc.arg(reason)::text ELSE 'parent_ended' END,
    ended_at = now()
WHERE runs.org_id = sqlc.arg(org_id) AND runs.id IN (SELECT id FROM tree) AND runs.state = 'ACTIVE'
RETURNING *;

-- A subject token proves only an existing, active user of the org; it
-- never creates one (HR-145).
-- name: ActiveUserBySubject :one
SELECT id FROM pc.users
WHERE org_id = sqlc.arg(org_id) AND issuer = sqlc.arg(issuer) AND subject = sqlc.arg(subject) AND state = 'ACTIVE';

-- First-use binding (HR-022): an unbound active run binds to the first
-- admitted instance that uses it; no row means another instance won.
-- name: BindRunInstance :execrows
UPDATE pc.runs SET instance_id = sqlc.arg(instance_id)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND instance_id IS NULL AND state = 'ACTIVE' AND expires_at > now();

-- Janitor: records the expiry of runs past expires_at (they already read
-- EXPIRED); a child never outlives its parent, so children expire too.
-- name: ExpireRuns :execrows
UPDATE pc.runs SET state = 'EXPIRED', end_reason = 'expired', ended_at = now()
WHERE org_id = sqlc.arg(org_id) AND state = 'ACTIVE' AND expires_at <= now();
