-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Notification reach queries (G0 M36 D1065, D1066): per-person
-- preferences, approval digests and Web Push subscriptions. Every query
-- runs inside db.InTenantTx and also filters by org_id explicitly.

-- name: GetNotificationPreferences :one
SELECT * FROM pc.notification_preferences WHERE org_id = sqlc.arg(org_id) AND user_id = sqlc.arg(user_id);

-- name: UpsertNotificationPreferences :one
INSERT INTO pc.notification_preferences (org_id, user_id, approval_delivery, digest_minutes, quiet_start, quiet_end, time_zone)
VALUES (sqlc.arg(org_id), sqlc.arg(user_id), sqlc.arg(approval_delivery), sqlc.arg(digest_minutes), sqlc.narg(quiet_start),
        sqlc.narg(quiet_end), sqlc.narg(time_zone))
ON CONFLICT (org_id, user_id) DO UPDATE
SET approval_delivery = excluded.approval_delivery, digest_minutes = excluded.digest_minutes,
    quiet_start = excluded.quiet_start, quiet_end = excluded.quiet_end, time_zone = excluded.time_zone, updated_at = now()
RETURNING *;

-- name: PreferencesOf :many
SELECT * FROM pc.notification_preferences
WHERE org_id = sqlc.arg(org_id) AND user_id = ANY (sqlc.arg(users)::uuid[]);

-- name: DigestRecipients :many
-- The active people who take approval notices as a digest, with how many
-- open holds and restorations were routed to them as a decider, and one of
-- those requests.
SELECT p.user_id, p.digest_minutes, count(DISTINCT e.id)::bigint AS waiting,
       min(e.subject_id::text)::text AS one_request
FROM pc.notification_preferences p
JOIN pc.users u ON u.org_id = p.org_id AND u.id = p.user_id AND u.state = 'ACTIVE'
JOIN pc.waitlist_routes w ON w.org_id = p.org_id AND w.user_id = p.user_id AND w.kind = 'decider'
JOIN pc.waitlist_entries e ON e.org_id = w.org_id AND e.id = w.entry_id AND e.state = 'OPEN'
     AND e.kind IN ('ACTION_HOLD', 'RESTORATION') AND e.subject_type = 'approval_request'
WHERE p.org_id = sqlc.arg(org_id) AND p.approval_delivery = 'DIGEST'
GROUP BY p.user_id, p.digest_minutes
ORDER BY p.user_id
LIMIT 1000;

-- name: CountLivePushSubscriptions :one
SELECT count(*)::bigint FROM pc.push_subscriptions
WHERE org_id = sqlc.arg(org_id) AND user_id = sqlc.arg(user_id) AND state = 'ACTIVE';

-- name: InsertPushSubscription :one
INSERT INTO pc.push_subscriptions (org_id, id, user_id, endpoint, p256dh, auth, label)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(user_id), sqlc.arg(endpoint), sqlc.arg(p256dh), sqlc.arg(auth), sqlc.arg(label))
ON CONFLICT (org_id, user_id, endpoint) WHERE state = 'ACTIVE' DO NOTHING
RETURNING id, user_id, endpoint, label, state, created_at, last_success_at, failure_count;

-- name: RemovePushSubscription :one
UPDATE pc.push_subscriptions SET state = 'REMOVED', removed_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND user_id = sqlc.arg(user_id) AND state = 'ACTIVE'
RETURNING id, user_id, endpoint, label, state, created_at, last_success_at, failure_count;

-- name: ListPushSubscriptionsOf :many
SELECT id, user_id, endpoint, label, state, created_at, last_success_at, failure_count
FROM pc.push_subscriptions
WHERE org_id = sqlc.arg(org_id) AND user_id = sqlc.arg(user_id) AND state = 'ACTIVE'
ORDER BY created_at DESC, id
LIMIT 50;

-- name: ActivePushSubscriptions :many
-- A person's live subscriptions with their sealed keys, for one delivery.
SELECT id, endpoint, p256dh, auth
FROM pc.push_subscriptions
WHERE org_id = sqlc.arg(org_id) AND user_id = sqlc.arg(user_id) AND state = 'ACTIVE'
ORDER BY created_at, id
LIMIT 50;

-- name: UsersWithPushSubscriptions :many
SELECT DISTINCT user_id
FROM pc.push_subscriptions
WHERE org_id = sqlc.arg(org_id) AND user_id = ANY (sqlc.arg(users)::uuid[]) AND state = 'ACTIVE'
ORDER BY user_id;

-- name: PushSucceeded :exec
UPDATE pc.push_subscriptions SET last_success_at = now(), failure_count = 0
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'ACTIVE';

-- name: PushFailed :exec
UPDATE pc.push_subscriptions SET failure_count = failure_count + 1
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'ACTIVE';

-- name: PushGone :execrows
-- The push service answered 404 or 410: the subscription is gone.
UPDATE pc.push_subscriptions SET state = 'REMOVED', removed_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'ACTIVE';
