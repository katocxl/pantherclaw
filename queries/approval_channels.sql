-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Approval channels (G0 M20 D256; migration 00244): Slack DMs to eligible
-- deciders through a confirmed chat identity link, and Teams cards.

-- The org's slack_app channel that sends DMs, when it is active.
-- name: SlackDMChannel :one
SELECT s.channel_record_id, s.team_id, s.activated_at, s.allowed_email_domains, c.secret
FROM pc.slack_app_channels s
JOIN pc.notification_channels c ON c.org_id = s.org_id AND c.id = s.channel_record_id
WHERE s.org_id = sqlc.arg(org_id) AND s.direct_messages AND s.state = 'ACTIVE' AND c.state = 'ACTIVE';

-- The people among users with a confirmed Slack link in team.
-- name: ConfirmedSlackLinks :many
SELECT id, user_id, external_user_id, email FROM pc.chat_identity_links
WHERE org_id = sqlc.arg(org_id) AND provider = 'slack' AND team_id = sqlc.arg(team_id) AND state = 'CONFIRMED'
  AND user_id = ANY (sqlc.arg(users)::uuid[]);

-- Whether the waitlist router recorded user as an eligible decider of the
-- approval request (HR-529).
-- name: RoutedDecider :one
SELECT EXISTS (
    SELECT 1 FROM pc.waitlist_routes r
    JOIN pc.waitlist_entries e ON e.org_id = r.org_id AND e.id = r.entry_id
    WHERE r.org_id = sqlc.arg(org_id) AND r.kind = 'decider' AND r.user_id = sqlc.arg(user_id)
      AND e.subject_type = 'approval_request' AND e.subject_id = sqlc.arg(request_id));

-- A DM is claimed before it is posted; a second claim inserts nothing.
-- name: ClaimSlackDM :execrows
INSERT INTO pc.slack_direct_messages (org_id, id, request_id, user_id, channel_record_id)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(request_id), sqlc.arg(user_id), sqlc.arg(channel_record_id))
ON CONFLICT (org_id, request_id, user_id) DO NOTHING;

-- name: GetSlackDM :one
SELECT * FROM pc.slack_direct_messages WHERE org_id = sqlc.arg(org_id) AND request_id = sqlc.arg(request_id) AND user_id = sqlc.arg(user_id);

-- name: SetSlackDMPosted :execrows
UPDATE pc.slack_direct_messages SET im_channel = sqlc.arg(im_channel), ts = sqlc.arg(ts), state = 'POSTED', updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'POSTING';

-- name: MarkSlackDMUnknown :execrows
UPDATE pc.slack_direct_messages SET state = 'UNKNOWN', updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'POSTING';

-- name: ReleaseSlackDM :execrows
DELETE FROM pc.slack_direct_messages WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'POSTING';

-- name: InsertChatIdentityLink :one
INSERT INTO pc.chat_identity_links (org_id, id, user_id, provider, team_id, external_user_id, email, proposed_by)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(user_id), sqlc.arg(provider), sqlc.arg(team_id), sqlc.arg(external_user_id),
    sqlc.arg(email), sqlc.arg(proposed_by))
RETURNING *;

-- name: GetChatIdentityLink :one
SELECT * FROM pc.chat_identity_links WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: UserChatIdentityLinks :many
SELECT * FROM pc.chat_identity_links WHERE org_id = sqlc.arg(org_id) AND user_id = sqlc.arg(user_id) ORDER BY created_at DESC, id
LIMIT 20;

-- The guard of 00244 sets the time and refuses any other move.
-- name: SetChatIdentityLinkState :execrows
UPDATE pc.chat_identity_links SET state = sqlc.arg(state)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND user_id = sqlc.arg(user_id) AND state = sqlc.arg(from_state);

-- The person's email and their account, whose email_verified says whether
-- the sign-in asserted it (D265).
-- name: UserEmail :one
SELECT email, account_id FROM pc.users WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'ACTIVE';

-- Slack no longer confirms a confirmed link (D265); the guard sets the time.
-- name: MarkChatIdentityLinkStale :execrows
UPDATE pc.chat_identity_links SET state = 'STALE'
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'CONFIRMED';

-- name: InsertTeamsAppChannel :exec
INSERT INTO pc.teams_app_channels (org_id, channel_record_id, tenant_id, team_id, teams_channel, app_id, service_url)
VALUES (sqlc.arg(org_id), sqlc.arg(channel_record_id), sqlc.arg(tenant_id), sqlc.arg(team_id), sqlc.arg(teams_channel),
    sqlc.arg(app_id), sqlc.arg(service_url));

-- name: GetTeamsAppChannel :one
SELECT a.*, c.secret, c.state AS channel_state, c.name AS channel_name
FROM pc.teams_app_channels a
JOIN pc.notification_channels c ON c.org_id = a.org_id AND c.id = a.channel_record_id
WHERE a.org_id = sqlc.arg(org_id) AND a.channel_record_id = sqlc.arg(channel_record_id);

-- The guard of 00244 sets the time and refuses a channel that is not
-- internal; a channel activated or changed meanwhile is not activated.
-- name: ActivateTeamsAppChannel :execrows
UPDATE pc.teams_app_channels
SET state = 'ACTIVE', membership_type = 'internal', activated_by = sqlc.arg(activated_by),
    activated_credential = sqlc.arg(activated_credential), last_checked_at = now()
WHERE org_id = sqlc.arg(org_id) AND channel_record_id = sqlc.arg(channel_record_id) AND state = 'PENDING_ACTIVATION'
  AND updated_at = sqlc.arg(seen_updated_at);

-- name: MarkTeamsAppChannelShared :execrows
UPDATE pc.teams_app_channels SET membership_type = 'shared', shared_at = now(), last_checked_at = now()
WHERE org_id = sqlc.arg(org_id) AND channel_record_id = sqlc.arg(channel_record_id) AND state = 'PENDING_ACTIVATION';

-- An active channel whose members are no longer all internal returns to
-- PENDING_ACTIVATION (D277); the guard clears its activation.
-- name: PauseSharedTeamsAppChannel :execrows
UPDATE pc.teams_app_channels
SET state = 'PENDING_ACTIVATION', membership_type = 'shared', shared_at = now(), last_checked_at = now()
WHERE org_id = sqlc.arg(org_id) AND channel_record_id = sqlc.arg(channel_record_id) AND state = 'ACTIVE';

-- name: ClaimTeamsCard :execrows
INSERT INTO pc.teams_cards (org_id, card_id, request_id, channel_record_id)
VALUES (sqlc.arg(org_id), sqlc.arg(card_id), sqlc.arg(request_id), sqlc.arg(channel_record_id))
ON CONFLICT (org_id, request_id, channel_record_id) DO NOTHING;

-- name: GetTeamsCard :one
SELECT * FROM pc.teams_cards
WHERE org_id = sqlc.arg(org_id) AND request_id = sqlc.arg(request_id) AND channel_record_id = sqlc.arg(channel_record_id);

-- name: SetTeamsCardPosted :execrows
UPDATE pc.teams_cards SET activity_id = sqlc.arg(activity_id), state = 'POSTED', updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND card_id = sqlc.arg(card_id) AND state = 'POSTING';

-- name: MarkTeamsCardUnknown :execrows
UPDATE pc.teams_cards SET state = 'UNKNOWN', updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND card_id = sqlc.arg(card_id) AND state = 'POSTING';

-- name: ReleaseTeamsCard :execrows
DELETE FROM pc.teams_cards WHERE org_id = sqlc.arg(org_id) AND card_id = sqlc.arg(card_id) AND state = 'POSTING';
