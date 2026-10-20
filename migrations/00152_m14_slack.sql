-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Slack approval cards (G0 M14 D22, D23; PN-017.3, F164-F167, HR-313..315).
-- A slack_app notification channel posts minimal approval cards to one
-- Slack channel with a bot token (the channel's encrypted secret, 00150)
-- and updates them in place. Its configuration lives here: the Slack
-- channel id and the data level never change once stored (a different
-- channel is a new notification channel), and the workspace and bot ids
-- come from Slack's auth.test, never from the caller. A configuration is
-- inserted PENDING_ACTIVATION and becomes ACTIVE only with a person's fresh
-- WebAuthn step-up (activated_by, activated_credential) on its page. A new
-- bot token (UpdateChannel) puts it back to PENDING_ACTIVATION and clears
-- the activation, so every token is confirmed with a key before it posts
-- (G0 M14 D66). The reconciler (D88) also returns it to PENDING_ACTIVATION
-- when Slack reports the channel shared outside the workspace
-- (shared_externally_at). The workspace never changes once known: a token
-- of another workspace is a new channel.
--
-- slack_cards keeps at most one live card per approval request and slack_app
-- channel (D88): a delivery claims the row (POSTING) before it posts, so a
-- retry never posts twice; the Slack message ts chat.update needs is stored
-- once Slack answers (OPEN, CLOSED), and a post whose answer was lost is
-- UNKNOWN and never reposted (the approval page is authoritative, F167).
-- It counts the escalation replies too. A card is decided
-- nothing by: Slack has no inbound endpoint in PantherClaw (HR-313), and
-- card state never reaches an authorization decision (HR-039).

-- +goose Up
CREATE TABLE pc.slack_app_channels (
    org_id                    uuid        NOT NULL REFERENCES pc.orgs (id),
    channel_record_id         uuid        NOT NULL,
    slack_channel             text        NOT NULL CHECK (slack_channel ~ '^[CG][A-Z0-9]{8,12}$'),
    data_level                text        NOT NULL DEFAULT 'MINIMAL' CHECK (data_level IN ('MINIMAL', 'SUMMARY')),
    state                     text        NOT NULL DEFAULT 'PENDING_ACTIVATION' CHECK (state IN ('PENDING_ACTIVATION', 'ACTIVE')),
    team_id                   text        CHECK (team_id IS NULL OR team_id ~ '^T[A-Z0-9]{4,30}$'),
    bot_id                    text        CHECK (bot_id IS NULL OR bot_id ~ '^B[A-Z0-9]{4,30}$'),
    created_at                timestamptz NOT NULL DEFAULT now(),
    activated_by              uuid,
    activated_credential      uuid,
    activated_at              timestamptz,
    token_replaced_by         text        CHECK (token_replaced_by IS NULL OR char_length(token_replaced_by) BETWEEN 1 AND 128),
    token_replaced_at         timestamptz,
    shared_externally_at      timestamptz,
    updated_at                timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, channel_record_id),
    FOREIGN KEY (org_id, channel_record_id) REFERENCES pc.notification_channels (org_id, id),
    FOREIGN KEY (org_id, activated_by) REFERENCES pc.users (org_id, id),
    FOREIGN KEY (org_id, activated_credential) REFERENCES pc.webauthn_credentials (org_id, id),
    CHECK ((activated_at IS NULL) = (activated_by IS NULL) AND (activated_by IS NULL) = (activated_credential IS NULL)),
    CHECK ((token_replaced_at IS NULL) = (token_replaced_by IS NULL)),
    CHECK ((state = 'ACTIVE') = (activated_at IS NOT NULL)),
    CHECK (state = 'PENDING_ACTIVATION' OR (team_id IS NOT NULL AND bot_id IS NOT NULL))
);

-- The Slack channel, the data level and the creation never change. A
-- configuration is inserted PENDING_ACTIVATION; it becomes ACTIVE only with
-- a person and a key (activated_at is the database's time), and it returns
-- to PENDING_ACTIVATION only with a new bot token, which clears the
-- activation, or when Slack reports it shared outside the workspace. An
-- active configuration keeps its activation, workspace and bot; the
-- workspace never changes once known (HR-315, D66, D88).
-- +goose StatementBegin
CREATE FUNCTION pc.slack_app_channel_guard() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pc, pg_temp
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.state IS DISTINCT FROM 'PENDING_ACTIVATION' OR NEW.activated_by IS NOT NULL OR NEW.token_replaced_by IS NOT NULL THEN
            RAISE EXCEPTION 'a slack_app channel is inserted PENDING_ACTIVATION' USING ERRCODE = 'check_violation';
        END IF;
        NEW.created_at := now();
        RETURN NEW;
    END IF;
    IF NEW.slack_channel IS DISTINCT FROM OLD.slack_channel OR NEW.data_level IS DISTINCT FROM OLD.data_level
            OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'a slack_app channel''s Slack channel and data level never change' USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.team_id IS NOT NULL AND NEW.team_id IS DISTINCT FROM OLD.team_id THEN
        RAISE EXCEPTION 'a slack_app channel stays in its Slack workspace' USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.state = 'PENDING_ACTIVATION' AND NEW.state = 'ACTIVE' THEN
        IF NEW.activated_by IS NULL OR NEW.activated_credential IS NULL THEN
            RAISE EXCEPTION 'a slack_app channel is activated by a person with a key' USING ERRCODE = 'check_violation';
        END IF;
        NEW.activated_at := now();
    ELSIF OLD.state = 'ACTIVE' AND NEW.state = 'ACTIVE' THEN
        IF NEW.activated_by IS DISTINCT FROM OLD.activated_by OR NEW.activated_credential IS DISTINCT FROM OLD.activated_credential
                OR NEW.activated_at IS DISTINCT FROM OLD.activated_at OR NEW.team_id IS DISTINCT FROM OLD.team_id
                OR NEW.bot_id IS DISTINCT FROM OLD.bot_id OR NEW.token_replaced_at IS DISTINCT FROM OLD.token_replaced_at
                OR NEW.token_replaced_by IS DISTINCT FROM OLD.token_replaced_by
                OR NEW.shared_externally_at IS DISTINCT FROM OLD.shared_externally_at THEN
            RAISE EXCEPTION 'an active slack_app channel keeps its activation' USING ERRCODE = 'check_violation';
        END IF;
    ELSIF NEW.state = 'PENDING_ACTIVATION' THEN
        IF OLD.state = 'ACTIVE' AND NEW.shared_externally_at IS NOT DISTINCT FROM OLD.shared_externally_at
                AND (NEW.token_replaced_at IS NOT DISTINCT FROM OLD.token_replaced_at OR NEW.token_replaced_by IS NULL) THEN
            RAISE EXCEPTION 'a slack_app channel returns to PENDING_ACTIVATION only with a new bot token or when shared externally' USING ERRCODE = 'check_violation';
        END IF;
        NEW.activated_by := NULL;
        NEW.activated_credential := NULL;
        NEW.activated_at := NULL;
    END IF;
    NEW.updated_at := now();
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER slack_app_channels_guard BEFORE INSERT OR UPDATE ON pc.slack_app_channels
    FOR EACH ROW EXECUTE FUNCTION pc.slack_app_channel_guard();

CREATE TABLE pc.slack_cards (
    org_id            uuid        NOT NULL REFERENCES pc.orgs (id),
    card_id           uuid        NOT NULL,
    request_id        uuid        NOT NULL,
    channel_record_id uuid        NOT NULL,
    slack_channel     text        NOT NULL CHECK (slack_channel ~ '^[CG][A-Z0-9]{8,12}$'),
    ts                text        CHECK (ts IS NULL OR ts ~ '^[0-9]{10}\.[0-9]{6}$'),
    state             text        NOT NULL DEFAULT 'POSTING'
                                  CHECK (state IN ('POSTING', 'OPEN', 'CLOSED', 'UNKNOWN', 'ORPHANED')),
    escalations       integer     NOT NULL DEFAULT 0 CHECK (escalations BETWEEN 0 AND 100),
    close_attempts    integer     NOT NULL DEFAULT 0 CHECK (close_attempts BETWEEN 0 AND 5),
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, card_id),
    FOREIGN KEY (org_id, request_id) REFERENCES pc.approval_requests (org_id, id),
    FOREIGN KEY (org_id, channel_record_id) REFERENCES pc.slack_app_channels (org_id, channel_record_id),
    CHECK ((ts IS NOT NULL) = (state IN ('OPEN', 'CLOSED', 'ORPHANED')))
);
-- At most one live card per request and channel (D88): a request that
-- returns to PENDING gets a new card once its old one is CLOSED (D104).
CREATE UNIQUE INDEX slack_cards_live ON pc.slack_cards (org_id, request_id, channel_record_id)
    WHERE state IN ('POSTING', 'OPEN', 'UNKNOWN');
CREATE INDEX slack_cards_request ON pc.slack_cards (org_id, request_id, channel_record_id, created_at);
CREATE INDEX slack_cards_channel ON pc.slack_cards (org_id, channel_record_id);
-- The reconciler's batch: open cards, least recently tried first.
CREATE INDEX slack_cards_open ON pc.slack_cards (org_id, updated_at) WHERE state = 'OPEN';

-- +goose StatementBegin
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['slack_app_channels', 'slack_cards']
    LOOP
        EXECUTE format('ALTER TABLE pc.%I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE pc.%I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format($p$CREATE POLICY tenant_isolation ON pc.%I
            USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
            WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))$p$, t);
    END LOOP;
END
$$;
-- +goose StatementEnd

GRANT SELECT, INSERT ON pc.slack_app_channels, pc.slack_cards TO pc_app;
GRANT UPDATE (state, team_id, bot_id, activated_by, activated_credential, activated_at, token_replaced_by, token_replaced_at,
    shared_externally_at, updated_at) ON pc.slack_app_channels TO pc_app;
GRANT UPDATE (ts, state, escalations, close_attempts, updated_at) ON pc.slack_cards TO pc_app;
-- A claim whose post Slack refused (nothing was posted) is released.
GRANT DELETE ON pc.slack_cards TO pc_app;
GRANT SELECT ON pc.slack_app_channels, pc.slack_cards TO pc_audit_ro;

-- +goose Down
DROP TABLE pc.slack_cards;
DROP TABLE pc.slack_app_channels;
DROP FUNCTION pc.slack_app_channel_guard();
