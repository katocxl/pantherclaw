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
-- inserted PENDING and becomes ACTIVE only with a person's fresh WebAuthn
-- step-up (activated_by, activated_credential); a token replacement is
-- recorded the same way (token_replaced_by, token_replaced_credential).
--
-- slack_cards keeps one card per approval request and slack_app channel:
-- the Slack message ts chat.update needs, whether the card is OPEN or
-- CLOSED, and how many escalation replies it has. A card is decided
-- nothing by: Slack has no inbound endpoint in PantherClaw (HR-313), and
-- card state never reaches an authorization decision (HR-039).

-- +goose Up
CREATE TABLE pc.slack_app_channels (
    org_id                    uuid        NOT NULL REFERENCES pc.orgs (id),
    channel_record_id         uuid        NOT NULL,
    slack_channel             text        NOT NULL CHECK (slack_channel ~ '^[CG][A-Z0-9]{8,12}$'),
    data_level                text        NOT NULL DEFAULT 'MINIMAL' CHECK (data_level IN ('MINIMAL', 'SUMMARY')),
    state                     text        NOT NULL DEFAULT 'PENDING' CHECK (state IN ('PENDING', 'ACTIVE')),
    team_id                   text        CHECK (team_id IS NULL OR team_id ~ '^T[A-Z0-9]{4,30}$'),
    bot_id                    text        CHECK (bot_id IS NULL OR bot_id ~ '^B[A-Z0-9]{4,30}$'),
    created_at                timestamptz NOT NULL DEFAULT now(),
    activated_by              uuid,
    activated_credential      uuid,
    activated_at              timestamptz,
    token_replaced_by         uuid,
    token_replaced_credential uuid,
    token_replaced_at         timestamptz,
    updated_at                timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, channel_record_id),
    FOREIGN KEY (org_id, channel_record_id) REFERENCES pc.notification_channels (org_id, id),
    FOREIGN KEY (org_id, activated_by) REFERENCES pc.users (org_id, id),
    FOREIGN KEY (org_id, activated_credential) REFERENCES pc.webauthn_credentials (org_id, id),
    FOREIGN KEY (org_id, token_replaced_by) REFERENCES pc.users (org_id, id),
    FOREIGN KEY (org_id, token_replaced_credential) REFERENCES pc.webauthn_credentials (org_id, id),
    CHECK ((activated_at IS NULL) = (activated_by IS NULL) AND (activated_by IS NULL) = (activated_credential IS NULL)),
    CHECK ((token_replaced_at IS NULL) = (token_replaced_by IS NULL)
           AND (token_replaced_by IS NULL) = (token_replaced_credential IS NULL)),
    CHECK ((state = 'ACTIVE') = (activated_at IS NOT NULL)),
    CHECK (state = 'PENDING' OR (team_id IS NOT NULL AND bot_id IS NOT NULL))
);

-- The Slack channel, the data level and the creation never change; a
-- configuration is inserted PENDING, activated once with a person and a
-- key, and never returns to PENDING (HR-315).
-- +goose StatementBegin
CREATE FUNCTION pc.slack_app_channel_guard() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pc, pg_temp
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.state IS DISTINCT FROM 'PENDING' OR NEW.activated_by IS NOT NULL OR NEW.token_replaced_by IS NOT NULL THEN
            RAISE EXCEPTION 'a slack_app channel is inserted PENDING' USING ERRCODE = 'check_violation';
        END IF;
        NEW.created_at := now();
        RETURN NEW;
    END IF;
    IF NEW.slack_channel IS DISTINCT FROM OLD.slack_channel OR NEW.data_level IS DISTINCT FROM OLD.data_level
            OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'a slack_app channel''s Slack channel and data level never change' USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.state = 'ACTIVE' AND NEW.state IS DISTINCT FROM 'ACTIVE' THEN
        RAISE EXCEPTION 'an active slack_app channel cannot return to PENDING' USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.activated_by IS NOT NULL AND (NEW.activated_by IS DISTINCT FROM OLD.activated_by
            OR NEW.activated_credential IS DISTINCT FROM OLD.activated_credential
            OR NEW.activated_at IS DISTINCT FROM OLD.activated_at) THEN
        RAISE EXCEPTION 'a slack_app channel is activated once' USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.activated_by IS NULL AND NEW.activated_by IS NOT NULL THEN
        NEW.activated_at := now();
    END IF;
    IF NEW.token_replaced_by IS NOT NULL AND (NEW.token_replaced_by IS DISTINCT FROM OLD.token_replaced_by
            OR NEW.token_replaced_credential IS DISTINCT FROM OLD.token_replaced_credential
            OR NEW.token_replaced_at IS DISTINCT FROM OLD.token_replaced_at) THEN
        NEW.token_replaced_at := now();
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
    request_id        uuid        NOT NULL,
    channel_record_id uuid        NOT NULL,
    slack_channel     text        NOT NULL CHECK (slack_channel ~ '^[CG][A-Z0-9]{8,12}$'),
    ts                text        NOT NULL CHECK (ts ~ '^[0-9]{10}\.[0-9]{6}$'),
    state             text        NOT NULL DEFAULT 'OPEN' CHECK (state IN ('OPEN', 'CLOSED')),
    escalations       integer     NOT NULL DEFAULT 0 CHECK (escalations BETWEEN 0 AND 100),
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, request_id, channel_record_id),
    FOREIGN KEY (org_id, request_id) REFERENCES pc.approval_requests (org_id, id),
    FOREIGN KEY (org_id, channel_record_id) REFERENCES pc.slack_app_channels (org_id, channel_record_id)
);
CREATE INDEX slack_cards_channel ON pc.slack_cards (org_id, channel_record_id);

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
GRANT UPDATE (state, team_id, bot_id, activated_by, activated_credential, activated_at, token_replaced_by,
    token_replaced_credential, token_replaced_at, updated_at) ON pc.slack_app_channels TO pc_app;
GRANT UPDATE (ts, state, escalations, updated_at) ON pc.slack_cards TO pc_app;
GRANT SELECT ON pc.slack_app_channels, pc.slack_cards TO pc_audit_ro;

-- +goose Down
DROP TABLE pc.slack_cards;
DROP TABLE pc.slack_app_channels;
DROP FUNCTION pc.slack_app_channel_guard();
