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

-- name: LatestSlackCard :one
-- A request's newest card in a channel (a request that returned to
-- PENDING may have a CLOSED card and a newer one, D104).
SELECT * FROM pc.slack_cards
WHERE org_id = sqlc.arg(org_id) AND request_id = sqlc.arg(request_id) AND channel_record_id = sqlc.arg(channel_record_id)
ORDER BY created_at DESC, card_id DESC
LIMIT 1;

-- name: GetSlackCardByID :one
SELECT * FROM pc.slack_cards WHERE org_id = sqlc.arg(org_id) AND card_id = sqlc.arg(card_id);

-- name: ClaimSlackCard :execrows
-- Claims a request's live card in a channel before it is posted (D88):
-- 0 rows means another delivery claimed it first.
INSERT INTO pc.slack_cards (org_id, card_id, request_id, channel_record_id, slack_channel, state)
VALUES (sqlc.arg(org_id), sqlc.arg(card_id), sqlc.arg(request_id), sqlc.arg(channel_record_id), sqlc.arg(slack_channel), 'POSTING')
ON CONFLICT (org_id, request_id, channel_record_id) WHERE state IN ('POSTING', 'OPEN', 'UNKNOWN') DO NOTHING;

-- name: SetSlackCardPosted :execrows
-- Stores the ts Slack answered for a claimed card, also when a concurrent
-- delivery already marked the claim UNKNOWN (D104): the returned ts wins.
UPDATE pc.slack_cards SET ts = sqlc.arg(ts), state = sqlc.arg(state), updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND card_id = sqlc.arg(card_id) AND state IN ('POSTING', 'UNKNOWN');

-- name: MarkSlackCardUnknown :execrows
-- A claimed card whose post may or may not have reached Slack: never
-- posted again.
UPDATE pc.slack_cards SET state = 'UNKNOWN', updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND card_id = sqlc.arg(card_id) AND state = 'POSTING';

-- name: ReleaseSlackCard :execrows
-- Releases a claim whose post Slack refused: nothing was posted.
DELETE FROM pc.slack_cards
WHERE org_id = sqlc.arg(org_id) AND card_id = sqlc.arg(card_id) AND state = 'POSTING';

-- name: SlackCardsToClose :many
-- Open cards of active channels whose request is final and whose backoff
-- has passed, fewest failed tries first, then least recently tried, for
-- the reconciler (D88, D104, D117): bounded, so unclosable cards move to
-- the back and never starve the batch.
SELECT c.card_id, c.request_id, c.channel_record_id
FROM pc.slack_cards c
JOIN pc.approval_requests r ON r.org_id = c.org_id AND r.id = c.request_id
JOIN pc.slack_app_channels a ON a.org_id = c.org_id AND a.channel_record_id = c.channel_record_id
JOIN pc.notification_channels n ON n.org_id = c.org_id AND n.id = c.channel_record_id
WHERE c.org_id = sqlc.arg(org_id) AND c.state = 'OPEN' AND a.state = 'ACTIVE' AND n.state <> 'DISABLED'
  AND (c.close_after IS NULL OR c.close_after <= now())
  AND r.state IN ('APPROVED', 'CONSUMED', 'DECLINED', 'EXPIRED', 'INVALIDATED', 'SUPERSEDED')
ORDER BY c.close_attempts + least(c.close_retries, 1000), c.updated_at, c.card_id
LIMIT sqlc.arg(batch);

-- name: DeferSlackCardClose :exec
-- A close that failed for a reason worth retrying (429, a timeout, a 5xx):
-- the card waits with backoff (1 min doubling to 1 h, at least wait
-- seconds) and is never orphaned for it (D117).
UPDATE pc.slack_cards
SET close_retries = least(close_retries + 1, 100000), updated_at = now(),
    close_after = now() + make_interval(secs => greatest(least(60 * power(2, least(close_retries, 6)), 3600), sqlc.arg(wait_seconds)::int)::int)
WHERE org_id = sqlc.arg(org_id) AND card_id = sqlc.arg(card_id) AND state = 'OPEN';

-- name: FailSlackCardClose :one
-- Counts a close Slack will not recover from; the fifth makes the card
-- ORPHANED (D104, D117).
UPDATE pc.slack_cards
SET close_attempts = close_attempts + 1, updated_at = now(),
    state = CASE WHEN close_attempts + 1 >= 5 THEN 'ORPHANED' ELSE state END
WHERE org_id = sqlc.arg(org_id) AND card_id = sqlc.arg(card_id) AND state = 'OPEN'
RETURNING state;

-- name: ActiveSlackAppChannels :many
-- Active channels, least recently checked first: each run checks a bounded
-- number, and over runs every channel is checked (D117).
SELECT a.channel_record_id, a.slack_channel, c.secret
FROM pc.slack_app_channels a
JOIN pc.notification_channels c ON c.org_id = a.org_id AND c.id = a.channel_record_id
WHERE a.org_id = sqlc.arg(org_id) AND a.state = 'ACTIVE' AND c.state <> 'DISABLED'
ORDER BY a.last_checked_at NULLS FIRST, a.channel_record_id
LIMIT sqlc.arg(batch);

-- name: MarkSlackChannelChecked :exec
UPDATE pc.slack_app_channels SET last_checked_at = now()
WHERE org_id = sqlc.arg(org_id) AND channel_record_id = sqlc.arg(channel_record_id) AND state = 'ACTIVE';

-- name: MarkSlackSharedExternally :execrows
-- Slack reports the channel shared outside the workspace: it waits for a
-- new activation (D88).
UPDATE pc.slack_app_channels SET state = 'PENDING_ACTIVATION', shared_externally_at = now()
WHERE org_id = sqlc.arg(org_id) AND channel_record_id = sqlc.arg(channel_record_id) AND state = 'ACTIVE';

-- name: SetSlackCardState :exec
-- An ORPHANED card a later update reached is OPEN or CLOSED again (D117).
UPDATE pc.slack_cards SET state = sqlc.arg(state), updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND card_id = sqlc.arg(card_id) AND state IN ('OPEN', 'CLOSED', 'ORPHANED');

-- name: ClaimSlackEscalation :execrows
-- Claims escalation reply number seen + 1 before it is posted (D104).
UPDATE pc.slack_cards SET escalations = escalations + 1, updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND card_id = sqlc.arg(card_id) AND state = 'OPEN' AND escalations = sqlc.arg(seen)
  AND escalations < 100;

-- name: ReleaseSlackEscalation :execrows
-- Releases an escalation claim whose reply Slack refused.
UPDATE pc.slack_cards SET escalations = escalations - 1, updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND card_id = sqlc.arg(card_id) AND escalations = sqlc.arg(claimed);

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

-- name: NoteChannelFailureCode :exec
-- Shows a problem in a channel's delivery health without counting it as a
-- failed delivery: the auto-pause clock is left alone (D117).
UPDATE pc.notification_channels SET last_failure_code = sqlc.arg(code), last_failure_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);
