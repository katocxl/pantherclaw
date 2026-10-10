-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Notifications (G0 M5 part 1, HR-157..159). A notification and its
-- deliveries are inserted in the transaction of the change that caused
-- them (outbox); deliveries are then worked by River jobs that carry ids
-- only. Channel secrets are envelope ciphertexts (HR-062).

-- name: InsertChannel :exec
INSERT INTO pc.notification_channels (org_id, id, name, kind, event_types, min_severity, recipient_role, url, secret,
                                      created_by)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(name), sqlc.arg(kind), sqlc.arg(event_types), sqlc.arg(min_severity),
        sqlc.narg(recipient_role), sqlc.narg(url), sqlc.narg(secret), sqlc.arg(created_by));

-- name: ChannelsForRouting :many
SELECT id, kind, state, event_types, min_severity, recipient_role
FROM pc.notification_channels
WHERE org_id = sqlc.arg(org_id) AND state IN ('ACTIVE', 'PAUSED')
ORDER BY created_at, id;

-- name: PendingDeliveries :one
-- Counts a channel's pending deliveries, up to cap + 1.
SELECT count(*)::int FROM (
    SELECT 1 FROM pc.deliveries
    WHERE org_id = sqlc.arg(org_id) AND channel_id = sqlc.arg(channel_id) AND state = 'PENDING'
    LIMIT sqlc.arg(cap)::int + 1) p;

-- name: FlagChannelQueueFull :exec
UPDATE pc.notification_channels SET last_failure_at = now(), last_failure_code = 'queue_full', updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: ActiveUsersWithOrgRole :many
SELECT DISTINCT u.id
FROM pc.role_bindings b
JOIN pc.users u ON u.org_id = b.org_id AND u.id = b.user_id
WHERE b.org_id = sqlc.arg(org_id) AND b.role = sqlc.arg(role) AND b.scope_type = 'ORG' AND u.state = 'ACTIVE'
ORDER BY u.id
LIMIT 500;

-- name: InsertNotification :execrows
INSERT INTO pc.notifications (org_id, id, type, severity, subject_type, subject_id, title, body, link_path,
                              recipient_user_id, dedupe_key, expires_at)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(type), sqlc.arg(severity), sqlc.narg(subject_type), sqlc.narg(subject_id),
        sqlc.arg(title), sqlc.arg(body), sqlc.arg(link_path), sqlc.narg(recipient_user_id), sqlc.narg(dedupe_key),
        now() + make_interval(secs => sqlc.arg(ttl_seconds)::int))
ON CONFLICT (org_id, dedupe_key) WHERE dedupe_key IS NOT NULL DO NOTHING;

-- name: InsertDelivery :exec
INSERT INTO pc.deliveries (org_id, id, notification_id, channel_id, recipient_user_id, kind, state, last_error, finished_at)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(notification_id), sqlc.narg(channel_id), sqlc.narg(recipient_user_id),
        sqlc.arg(kind), sqlc.arg(state), sqlc.narg(last_error),
        CASE WHEN sqlc.arg(state)::text = 'PENDING' THEN NULL ELSE now() END);

-- Delivery (the worker). LoadDelivery reads everything one attempt needs;
-- the outcome is recorded with conditional updates on PENDING (HR-004).

-- name: LoadDelivery :one
SELECT d.id, d.kind, d.state, d.attempts, d.channel_id, d.recipient_user_id,
       n.id AS notification_id, n.type, n.severity, n.title, n.body, n.link_path, n.subject_type, n.subject_id,
       n.created_at AS notification_created_at, (n.expires_at <= now())::bool AS expired,
       c.state AS channel_state, c.name AS channel_name, c.url AS channel_url, c.secret AS channel_secret,
       c.prev_secret AS channel_prev_secret, coalesce(c.prev_secret_expires_at > now(), false)::bool AS prev_secret_live,
       u.email AS recipient_email, u.state AS recipient_state
FROM pc.deliveries d
JOIN pc.notifications n ON n.org_id = d.org_id AND n.id = d.notification_id
LEFT JOIN pc.notification_channels c ON c.org_id = d.org_id AND c.id = d.channel_id
LEFT JOIN pc.users u ON u.org_id = d.org_id AND u.id = d.recipient_user_id
WHERE d.org_id = sqlc.arg(org_id) AND d.id = sqlc.arg(id);

-- name: FinishDelivery :execrows
-- Ends a pending delivery without sending it (EXPIRED, SKIPPED, CANCELLED).
UPDATE pc.deliveries SET state = sqlc.arg(state), last_error = sqlc.narg(last_error), finished_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'PENDING';

-- name: RecordDeliveryAttempt :execrows
-- Records one attempt: DELIVERED, FAILED (last attempt or gone) or still
-- PENDING with its next attempt time.
UPDATE pc.deliveries
SET attempts = sqlc.arg(attempts), last_attempt_at = now(), last_status = sqlc.narg(last_status),
    last_error = sqlc.narg(last_error), state = sqlc.arg(state),
    next_attempt_at = CASE WHEN sqlc.arg(state)::text = 'PENDING' THEN now() + make_interval(secs => sqlc.arg(retry_seconds)::int) END,
    finished_at = CASE WHEN sqlc.arg(state)::text = 'PENDING' THEN NULL ELSE now() END
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'PENDING' AND attempts = sqlc.arg(attempts)::int - 1;

-- name: ChannelSucceeded :exec
UPDATE pc.notification_channels
SET consecutive_failures = 0, failing_since = NULL, last_success_at = now(), updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: ChannelFailed :one
-- Counts a failure and reports whether the channel has now failed for the
-- whole auto-pause period.
UPDATE pc.notification_channels
SET consecutive_failures = consecutive_failures + 1, failing_since = coalesce(failing_since, now()),
    last_failure_at = now(), last_failure_code = sqlc.arg(code), updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id)
RETURNING consecutive_failures, (coalesce(failing_since, now()) <= now() - make_interval(secs => sqlc.arg(pause_after_seconds)::int))::bool AS overdue,
          failing_since, name, state;

-- name: PauseChannel :execrows
UPDATE pc.notification_channels SET state = 'PAUSED', pause_reason = sqlc.arg(reason), updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'ACTIVE';

-- Housekeeping (the notifications janitor): deliveries finished more than
-- 30 days ago, then notifications that expired 30 days ago and have none.

-- name: DeleteOldDeliveries :execrows
DELETE FROM pc.deliveries WHERE org_id = sqlc.arg(org_id) AND finished_at < now() - interval '30 days';

-- name: DeleteOldNotifications :execrows
DELETE FROM pc.notifications n
WHERE n.org_id = sqlc.arg(org_id) AND n.expires_at < now() - interval '30 days'
  AND NOT EXISTS (SELECT 1 FROM pc.deliveries d WHERE d.org_id = n.org_id AND d.notification_id = n.id);

-- name: ExpireStaleDeliveries :execrows
-- A safety net: pending deliveries of expired notifications end EXPIRED
-- even if their job was lost.
UPDATE pc.deliveries d SET state = 'EXPIRED', last_error = 'notification_expired', finished_at = now()
FROM pc.notifications n
WHERE d.org_id = sqlc.arg(org_id) AND n.org_id = d.org_id AND n.id = d.notification_id AND d.state = 'PENDING'
  AND n.expires_at < now() - interval '1 hour';

-- Channel administration (NotificationService). DISABLED channels are
-- deleted ones: they are kept for their deliveries' history but never
-- listed or changed again.

-- name: ListChannels :many
SELECT * FROM pc.notification_channels
WHERE org_id = sqlc.arg(org_id) AND state <> 'DISABLED'
  AND id > coalesce(sqlc.narg(after)::uuid, '00000000-0000-0000-0000-000000000000')
ORDER BY id
LIMIT sqlc.arg(page_limit);

-- name: GetChannel :one
SELECT * FROM pc.notification_channels WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state <> 'DISABLED';

-- name: CountLiveChannels :one
SELECT count(*)::int FROM pc.notification_channels WHERE org_id = sqlc.arg(org_id) AND state <> 'DISABLED';

-- name: UpdateChannel :execrows
UPDATE pc.notification_channels
SET name = coalesce(sqlc.narg(name), name), event_types = coalesce(sqlc.narg(event_types)::text[], event_types),
    min_severity = coalesce(sqlc.narg(min_severity), min_severity), updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state <> 'DISABLED';

-- name: SetChannelPaused :execrows
-- Pauses (MANUAL) or resumes a channel; resuming clears its failure count.
UPDATE pc.notification_channels
SET state = CASE WHEN sqlc.arg(paused)::bool THEN 'PAUSED' ELSE 'ACTIVE' END,
    pause_reason = CASE WHEN sqlc.arg(paused)::bool THEN 'MANUAL' END,
    consecutive_failures = CASE WHEN sqlc.arg(paused)::bool THEN consecutive_failures ELSE 0 END,
    failing_since = CASE WHEN sqlc.arg(paused)::bool THEN failing_since END,
    updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state <> 'DISABLED';

-- name: DisableChannel :execrows
UPDATE pc.notification_channels SET state = 'DISABLED', pause_reason = NULL, updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state <> 'DISABLED';

-- name: CancelPendingDeliveries :execrows
UPDATE pc.deliveries SET state = 'CANCELLED', last_error = 'channel_deleted', finished_at = now()
WHERE org_id = sqlc.arg(org_id) AND channel_id = sqlc.arg(channel_id) AND state = 'PENDING';

-- name: LockChannelSecret :one
SELECT kind, secret FROM pc.notification_channels
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state <> 'DISABLED'
FOR UPDATE;

-- name: RotateChannelSecret :one
UPDATE pc.notification_channels
SET secret = sqlc.arg(secret), prev_secret = sqlc.arg(prev_secret),
    prev_secret_expires_at = now() + make_interval(secs => sqlc.arg(overlap_seconds)::int), updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND kind = 'webhook' AND state <> 'DISABLED'
RETURNING prev_secret_expires_at;

-- name: ListDeliveries :many
-- Newest first: the cursor is the last id of the previous page.
SELECT d.id, d.notification_id, n.type AS notification_type, d.channel_id, d.recipient_user_id, d.kind, d.state,
       d.attempts, d.last_status, d.last_error, d.created_at, d.next_attempt_at, d.finished_at
FROM pc.deliveries d
JOIN pc.notifications n ON n.org_id = d.org_id AND n.id = d.notification_id
WHERE d.org_id = sqlc.arg(org_id)
  AND (sqlc.narg(channel_id)::uuid IS NULL OR d.channel_id = sqlc.narg(channel_id)::uuid)
  AND (sqlc.narg(state)::text IS NULL OR d.state = sqlc.narg(state)::text)
  AND d.id < coalesce(sqlc.narg(before)::uuid, 'ffffffff-ffff-ffff-ffff-ffffffffffff')
ORDER BY d.id DESC
LIMIT sqlc.arg(page_limit);

-- The subjects, among subject_ids, whose notices failed to deliver (G0 M5
-- part 2: a waitlist entry's routing health). It is shown to people only
-- and never reaches an authorization decision (HR-039).
-- name: FailedNoticeSubjects :many
SELECT DISTINCT n.subject_id::uuid AS subject_id
FROM pc.notifications n
JOIN pc.deliveries d ON d.org_id = n.org_id AND d.notification_id = n.id
WHERE n.org_id = sqlc.arg(org_id) AND n.subject_type = sqlc.arg(subject_type) AND n.subject_id = ANY (sqlc.arg(subject_ids)::uuid[])
  AND d.state = 'FAILED';
