-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Slack approval cards (G0 M14 D22, D23; 00152).

-- name: InsertSlackAppChannel :exec
INSERT INTO pc.slack_app_channels (org_id, channel_record_id, slack_channel, data_level)
VALUES (sqlc.arg(org_id), sqlc.arg(channel_record_id), sqlc.arg(slack_channel), sqlc.arg(data_level));

-- name: GetSlackAppChannel :one
SELECT a.*, c.secret, c.state AS channel_state, c.name AS channel_name
FROM pc.slack_app_channels a
JOIN pc.notification_channels c ON c.org_id = a.org_id AND c.id = a.channel_record_id
WHERE a.org_id = sqlc.arg(org_id) AND a.channel_record_id = sqlc.arg(channel_record_id);

-- name: LockSlackAppChannel :one
SELECT a.*, c.secret, c.state AS channel_state, c.name AS channel_name
FROM pc.slack_app_channels a
JOIN pc.notification_channels c ON c.org_id = a.org_id AND c.id = a.channel_record_id
WHERE a.org_id = sqlc.arg(org_id) AND a.channel_record_id = sqlc.arg(channel_record_id)
FOR UPDATE OF a, c;

-- name: ListSlackAppChannels :many
SELECT * FROM pc.slack_app_channels
WHERE org_id = sqlc.arg(org_id) AND channel_record_id = ANY (sqlc.arg(channel_record_ids)::uuid[]);

-- name: ActivateSlackAppChannel :execrows
-- Activates a PENDING configuration with the person and key of a fresh
-- step-up and the workspace Slack's auth.test reported (HR-315).
UPDATE pc.slack_app_channels
SET state = 'ACTIVE', team_id = sqlc.arg(team_id), bot_id = sqlc.arg(bot_id),
    activated_by = sqlc.arg(activated_by), activated_credential = sqlc.arg(activated_credential)
WHERE org_id = sqlc.arg(org_id) AND channel_record_id = sqlc.arg(channel_record_id) AND state = 'PENDING_ACTIVATION'
  AND updated_at = sqlc.arg(seen_updated_at);

-- name: ReturnSlackAppToPending :execrows
-- A new bot token: the channel waits for a new activation (D66).
UPDATE pc.slack_app_channels
SET state = 'PENDING_ACTIVATION', token_replaced_by = sqlc.arg(token_replaced_by), token_replaced_at = now()
WHERE org_id = sqlc.arg(org_id) AND channel_record_id = sqlc.arg(channel_record_id);

-- name: SetChannelSecret :execrows
-- Replaces a slack_app channel's encrypted bot token.
UPDATE pc.notification_channels SET secret = sqlc.arg(secret), updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND kind = 'slack_app' AND state <> 'DISABLED';

-- name: GetSlackCard :one
SELECT * FROM pc.slack_cards
WHERE org_id = sqlc.arg(org_id) AND request_id = sqlc.arg(request_id) AND channel_record_id = sqlc.arg(channel_record_id);

-- name: ClaimSlackCard :execrows
-- Claims the one card of a request in a channel before it is posted (D88):
-- 0 rows means another delivery claimed it first.
INSERT INTO pc.slack_cards (org_id, request_id, channel_record_id, slack_channel, state)
VALUES (sqlc.arg(org_id), sqlc.arg(request_id), sqlc.arg(channel_record_id), sqlc.arg(slack_channel), 'POSTING')
ON CONFLICT (org_id, request_id, channel_record_id) DO NOTHING;

-- name: SetSlackCardPosted :execrows
-- Stores the ts Slack answered for a claimed card.
UPDATE pc.slack_cards SET ts = sqlc.arg(ts), state = sqlc.arg(state), updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND request_id = sqlc.arg(request_id) AND channel_record_id = sqlc.arg(channel_record_id)
  AND state = 'POSTING';

-- name: MarkSlackCardUnknown :execrows
-- A claimed card whose post may or may not have reached Slack: never
-- posted again.
UPDATE pc.slack_cards SET state = 'UNKNOWN', updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND request_id = sqlc.arg(request_id) AND channel_record_id = sqlc.arg(channel_record_id)
  AND state = 'POSTING';

-- name: ReleaseSlackCard :execrows
-- Releases a claim whose post Slack refused: nothing was posted.
DELETE FROM pc.slack_cards
WHERE org_id = sqlc.arg(org_id) AND request_id = sqlc.arg(request_id) AND channel_record_id = sqlc.arg(channel_record_id)
  AND state = 'POSTING';

-- name: SlackCardsToClose :many
-- Open cards whose request is final, oldest first, for the reconciler
-- (D88): bounded.
SELECT c.request_id, c.channel_record_id
FROM pc.slack_cards c
JOIN pc.approval_requests r ON r.org_id = c.org_id AND r.id = c.request_id
WHERE c.org_id = sqlc.arg(org_id) AND c.state = 'OPEN'
  AND r.state IN ('APPROVED', 'CONSUMED', 'DECLINED', 'EXPIRED', 'INVALIDATED', 'SUPERSEDED')
ORDER BY c.updated_at
LIMIT sqlc.arg(batch);

-- name: ActiveSlackAppChannels :many
SELECT a.channel_record_id, a.slack_channel, c.secret
FROM pc.slack_app_channels a
JOIN pc.notification_channels c ON c.org_id = a.org_id AND c.id = a.channel_record_id
WHERE a.org_id = sqlc.arg(org_id) AND a.state = 'ACTIVE' AND c.state <> 'DISABLED'
ORDER BY a.channel_record_id
LIMIT sqlc.arg(batch);

-- name: MarkSlackSharedExternally :execrows
-- Slack reports the channel shared outside the workspace: it waits for a
-- new activation (D88).
UPDATE pc.slack_app_channels SET state = 'PENDING_ACTIVATION', shared_externally_at = now()
WHERE org_id = sqlc.arg(org_id) AND channel_record_id = sqlc.arg(channel_record_id) AND state = 'ACTIVE';

-- name: SetSlackCardState :exec
UPDATE pc.slack_cards SET state = sqlc.arg(state), updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND request_id = sqlc.arg(request_id) AND channel_record_id = sqlc.arg(channel_record_id);

-- name: AddSlackCardEscalation :one
UPDATE pc.slack_cards SET escalations = least(escalations + 1, 100), updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND request_id = sqlc.arg(request_id) AND channel_record_id = sqlc.arg(channel_record_id)
RETURNING escalations;

-- name: SlackCardFacts :one
-- What a card may show about a request (D23): its kind, the definition's
-- reversibility, its state, creation and deadline, its operation id, the
-- agent's name and its environment's name. Never the rendered approval
-- title, which holds parameter values (D88 H1). Nothing else is read.
SELECT r.id, r.subject_kind, r.state, r.deadline_at, r.created_at,
       coalesce(r.display -> 'consequence' ->> 'reversibility', '')::text AS reversibility,
       r.operation,
       coalesce(a.name, '')::text AS agent_name, coalesce(e.name, '')::text AS environment_name
FROM pc.approval_requests r
LEFT JOIN pc.agents a ON a.org_id = r.org_id AND a.id = r.agent_id
LEFT JOIN pc.environments e ON e.org_id = a.org_id AND e.id = a.environment_id
WHERE r.org_id = sqlc.arg(org_id) AND r.id = sqlc.arg(id);
