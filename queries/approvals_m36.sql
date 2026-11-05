-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Approval reach queries (G0 M36 D1063, D1064): fatigue metrics and flags,
-- the org's fatigue routing, and deputies. Every query runs inside
-- db.InTenantTx and also filters by org_id explicitly. Nothing here writes
-- an approval response.

-- name: ApprovalFatigue :many
-- Per decider, over the APPROVE and DECLINE responses since since: the
-- approvals and declines, the approvals between 22:00 and 06:00 in the
-- person's time zone (UTC without one), the most approvals in one clock
-- hour, the longest run of approvals with no decline, and the median
-- seconds from the person's first notice of a request to their approval
-- (over the approvals that had a notice).
WITH resp AS (
    SELECT r.org_id, r.id, r.user_id, r.request_id, r.kind, r.created_at
    FROM pc.approval_responses r
    WHERE r.org_id = sqlc.arg(org_id) AND r.created_at >= sqlc.arg(since)::timestamptz
      AND r.kind IN ('APPROVE', 'DECLINE')
      AND (sqlc.narg(decider)::uuid IS NULL OR r.user_id = sqlc.narg(decider)::uuid)
),
timed AS (
    SELECT a.user_id, extract(epoch FROM a.created_at - n.first_notice)::float8 AS secs
    FROM resp a
    JOIN LATERAL (
        SELECT min(w.routed_at) AS first_notice
        FROM pc.waitlist_entries e
        JOIN pc.waitlist_routes w ON w.org_id = e.org_id AND w.entry_id = e.id AND w.user_id = a.user_id
        WHERE e.org_id = a.org_id AND e.subject_type = 'approval_request' AND e.subject_id = a.request_id
    ) n ON n.first_notice IS NOT NULL
    WHERE a.kind = 'APPROVE'
),
hourly AS (
    SELECT h.user_id, count(*) AS n
    FROM resp h
    WHERE h.kind = 'APPROVE'
    GROUP BY h.user_id, date_trunc('hour', h.created_at)
),
runs AS (
    SELECT g.user_id, count(*) FILTER (WHERE g.kind = 'APPROVE') AS n
    FROM (
        SELECT s.user_id, s.kind,
               sum(CASE WHEN s.kind = 'DECLINE' THEN 1 ELSE 0 END) OVER (PARTITION BY s.user_id ORDER BY s.created_at, s.id) AS grp
        FROM resp s
    ) g
    GROUP BY g.user_id, g.grp
),
zones AS (
    SELECT DISTINCT z.user_id, coalesce(p.time_zone, 'UTC') AS tz
    FROM resp z
    LEFT JOIN pc.notification_preferences p ON p.org_id = z.org_id AND p.user_id = z.user_id
)
SELECT r.user_id::uuid AS user_id,
       count(*) FILTER (WHERE r.kind = 'APPROVE')::bigint AS approvals,
       count(*) FILTER (WHERE r.kind = 'DECLINE')::bigint AS declines,
       count(*) FILTER (WHERE r.kind = 'APPROVE'
                          AND extract(hour FROM r.created_at AT TIME ZONE z.tz) NOT BETWEEN 6 AND 21)::bigint AS night_approvals,
       coalesce((SELECT max(h.n) FROM hourly h WHERE h.user_id = r.user_id), 0)::bigint AS peak_per_hour,
       coalesce((SELECT max(s.n) FROM runs s WHERE s.user_id = r.user_id), 0)::bigint AS longest_streak,
       coalesce((SELECT percentile_cont(0.5) WITHIN GROUP (ORDER BY t.secs) FROM timed t WHERE t.user_id = r.user_id),
                0)::float8 AS median_seconds,
       (SELECT count(*) FROM timed t WHERE t.user_id = r.user_id)::bigint AS timed_approvals
FROM resp r
JOIN zones z ON z.user_id = r.user_id
GROUP BY r.user_id
ORDER BY approvals DESC, r.user_id
LIMIT 200;

-- name: ActiveFatigueFlags :many
-- The flags that have not cleared, of every decider (all_users) or of
-- users, newest first.
SELECT user_id, reason, approvals, flagged_at, clears_at
FROM pc.approval_fatigue_flags
WHERE org_id = sqlc.arg(org_id) AND clears_at > now()
  AND (sqlc.arg(all_users)::boolean OR user_id = ANY (sqlc.arg(users)::uuid[]))
ORDER BY flagged_at DESC
LIMIT 500;

-- name: InsertFatigueFlag :one
-- Raises a flag unless one of the same reason is still up for the person.
INSERT INTO pc.approval_fatigue_flags (org_id, id, user_id, reason, approvals, flagged_at, clears_at)
SELECT sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(user_id), sqlc.arg(reason), sqlc.arg(approvals)::int, now(),
       now() + interval '4 hours'
WHERE NOT EXISTS (
    SELECT FROM pc.approval_fatigue_flags f
    WHERE f.org_id = sqlc.arg(org_id) AND f.user_id = sqlc.arg(user_id) AND f.reason = sqlc.arg(reason) AND f.clears_at > now()
)
RETURNING id, clears_at;

-- name: GetFatigueRouting :one
SELECT routing, updated_by, updated_at FROM pc.approval_fatigue_settings WHERE org_id = sqlc.arg(org_id);

-- name: SetFatigueRouting :exec
INSERT INTO pc.approval_fatigue_settings (org_id, routing, updated_by)
VALUES (sqlc.arg(org_id), sqlc.arg(routing), sqlc.arg(updated_by))
ON CONFLICT (org_id) DO UPDATE SET routing = excluded.routing, updated_by = excluded.updated_by, updated_at = now();

-- name: LockDeputyPerson :exec
-- Serializes deputy changes of one person, so two windows never overlap.
SELECT pg_advisory_xact_lock(hashtextextended('pc.approval_deputies:' || sqlc.arg(org_id)::uuid::text || ':'
                                              || sqlc.arg(person_id)::uuid::text, 0));

-- name: OverlappingDeputies :one
SELECT count(*)::bigint
FROM pc.approval_deputies
WHERE org_id = sqlc.arg(org_id) AND person_id = sqlc.arg(person_id) AND state = 'ACTIVE'
  AND starts_at < sqlc.arg(ends_at)::timestamptz AND ends_at > sqlc.arg(starts_at)::timestamptz;

-- name: InsertApprovalDeputy :one
INSERT INTO pc.approval_deputies (org_id, id, person_id, deputy_id, starts_at, ends_at, created_by)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(person_id), sqlc.arg(deputy_id), sqlc.arg(starts_at), sqlc.arg(ends_at),
        sqlc.arg(created_by))
RETURNING *;

-- name: GetApprovalDeputy :one
SELECT * FROM pc.approval_deputies WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: CancelApprovalDeputy :one
UPDATE pc.approval_deputies SET state = 'CANCELLED', cancelled_by = sqlc.arg(cancelled_by), cancelled_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'ACTIVE'
RETURNING *;

-- name: ListApprovalDeputies :many
-- Windows of one person (person_id) or of everyone, newest first; without
-- include_ended only those still ACTIVE and not over.
SELECT * FROM pc.approval_deputies
WHERE org_id = sqlc.arg(org_id)
  AND (sqlc.narg(person_id)::uuid IS NULL OR person_id = sqlc.narg(person_id)::uuid)
  AND (sqlc.arg(include_ended)::boolean OR (state = 'ACTIVE' AND ends_at > now()))
ORDER BY created_at DESC, id
LIMIT 200;

-- name: ActiveDeputiesOf :many
-- The deputies whose window is open now, for persons.
SELECT person_id, deputy_id
FROM pc.approval_deputies
WHERE org_id = sqlc.arg(org_id) AND person_id = ANY (sqlc.arg(persons)::uuid[]) AND state = 'ACTIVE'
  AND starts_at <= now() AND ends_at > now()
ORDER BY person_id, deputy_id;
