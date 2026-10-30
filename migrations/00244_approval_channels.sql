-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Approval channels: Slack direct messages and Microsoft Teams cards (G0
-- M20 D256; F161, PN-017.3, HR-313..315, HR-529, T-228).
--
-- Slack DMs. A person's Slack identity is linked from Slack's
-- users.lookupByEmail, only for a verified email on one of the
-- organization's domains, and is used only once that person confirmed it in
-- the console (PROPOSED -> CONFIRMED; either may be REVOKED; a link Slack no
-- longer confirms before a DM becomes STALE, D265). The bot token
-- of the organization's one slack_app channel that allows direct messages
-- sends them (direct_messages is fixed when the channel is created, like
-- its data level, so it was confirmed with the channel's activation). A DM
-- goes only to an eligible decider the waitlist router recorded for the
-- request (pc.waitlist_routes), carries the card fields and a link only,
-- and is posted at most once per request and person: a delivery claims the
-- row (POSTING) before it posts, and a post whose answer was lost is
-- UNKNOWN and never posted again.
--
-- Teams cards. A teams_app notification channel posts link-only Adaptive
-- Cards to one Teams channel through the organization's bot. Its client
-- secret is the channel's encrypted secret. Like slack_app (00152) it is
-- inserted PENDING_ACTIVATION, becomes ACTIVE only with a person's fresh
-- WebAuthn step-up, keeps its Teams channel, tenant and bot, and is never
-- ACTIVE for a shared or private channel: only a standard channel of the
-- organization's own tenant. A card is posted at most once per request and
-- channel, with the same claim.
--
-- Nothing comes back from Slack or Teams into a decision (HR-313, HR-158,
-- HR-039): there is no inbound endpoint for either.

-- +goose Up
-- squawk: each CHECK only widens a value list; goose runs each migration in
-- one transaction, and NOT VALID then VALIDATE keeps the lock short.
ALTER TABLE pc.notification_channels
    DROP CONSTRAINT notification_channels_kind_check,
    ADD CONSTRAINT notification_channels_kind_check
        CHECK (kind IN ('log', 'email', 'slack', 'webhook', 'slack_app', 'teams_app')) NOT VALID,
    DROP CONSTRAINT notification_channels_secret_kind,
    ADD CONSTRAINT notification_channels_secret_kind
        CHECK ((kind IN ('slack', 'webhook', 'slack_app', 'teams_app')) = (secret IS NOT NULL)) NOT VALID;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.notification_channels VALIDATE CONSTRAINT notification_channels_kind_check;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.notification_channels VALIDATE CONSTRAINT notification_channels_secret_kind;

-- A DM is a delivery to one person through a slack_app channel's bot.
ALTER TABLE pc.deliveries
    DROP CONSTRAINT deliveries_kind_check,
    ADD CONSTRAINT deliveries_kind_check
        CHECK (kind IN ('log', 'email', 'slack', 'webhook', 'slack_app', 'slack_dm', 'teams_app')) NOT VALID,
    DROP CONSTRAINT deliveries_check1,
    ADD CONSTRAINT deliveries_check1 CHECK ((kind IN ('email', 'slack_dm')) = (recipient_user_id IS NOT NULL)) NOT VALID;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.deliveries VALIDATE CONSTRAINT deliveries_kind_check;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.deliveries VALIDATE CONSTRAINT deliveries_check1;

-- Whether a slack_app channel's bot also sends approval DMs, and the email
-- domains a person's Slack link may use (D265: at most 20 lowercase exact
-- domains, no wildcards, at least one for a DM channel). Both are set at
-- creation only (pc_app has no UPDATE on them) and confirmed by the
-- channel's activation; a change is a new channel. One DM channel per org.
ALTER TABLE pc.slack_app_channels
    ADD COLUMN direct_messages boolean NOT NULL DEFAULT false,
    ADD COLUMN allowed_email_domains text[] NOT NULL DEFAULT '{}',
    -- squawk-ignore constraint-missing-not-valid
    ADD CONSTRAINT slack_app_channels_email_domains CHECK (
        cardinality(allowed_email_domains) <= 20
        AND (cardinality(allowed_email_domains) >= 1) = direct_messages
        AND array_position(allowed_email_domains, NULL) IS NULL
        AND (cardinality(allowed_email_domains) = 0 OR array_to_string(allowed_email_domains, ',')
             ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?([.][a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+(,[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?([.][a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+)*$'));
-- squawk-ignore require-concurrent-index-creation
CREATE UNIQUE INDEX slack_app_channels_dm ON pc.slack_app_channels (org_id) WHERE direct_messages;

CREATE TABLE pc.chat_identity_links (
    org_id           uuid        NOT NULL REFERENCES pc.orgs (id),
    id               uuid        NOT NULL,
    user_id          uuid        NOT NULL,
    provider         text        NOT NULL CHECK (provider IN ('slack')),
    team_id          text        NOT NULL CHECK (team_id ~ '^T[A-Z0-9]{4,30}$'),
    external_user_id text        NOT NULL CHECK (external_user_id ~ '^[UW][A-Z0-9]{4,30}$'),
    -- The verified email Slack matched, on one of the DM channel's domains.
    email            text        NOT NULL CHECK (char_length(email) BETWEEN 3 AND 320),
    -- STALE: before a DM, Slack no longer answered the email with this full
    -- member (D265); the link sends nothing more.
    state            text        NOT NULL DEFAULT 'PROPOSED' CHECK (state IN ('PROPOSED', 'CONFIRMED', 'STALE', 'REVOKED')),
    proposed_by      text        NOT NULL CHECK (char_length(proposed_by) BETWEEN 1 AND 300),
    created_at       timestamptz NOT NULL DEFAULT now(),
    confirmed_at     timestamptz,
    stale_at         timestamptz,
    revoked_at       timestamptz,
    updated_at       timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, user_id) REFERENCES pc.users (org_id, id),
    CHECK ((state = 'CONFIRMED') = (confirmed_at IS NOT NULL AND stale_at IS NULL AND revoked_at IS NULL)),
    CHECK ((state = 'STALE') = (stale_at IS NOT NULL AND revoked_at IS NULL)),
    CHECK ((state = 'REVOKED') = (revoked_at IS NOT NULL))
);
-- One live link per person and provider, and per Slack user.
CREATE UNIQUE INDEX chat_identity_links_user ON pc.chat_identity_links (org_id, user_id, provider)
    WHERE state IN ('PROPOSED', 'CONFIRMED');
CREATE UNIQUE INDEX chat_identity_links_external ON pc.chat_identity_links (org_id, provider, team_id, external_user_id)
    WHERE state IN ('PROPOSED', 'CONFIRMED');

-- A link is inserted PROPOSED; it moves PROPOSED -> CONFIRMED, a live link
-- to STALE, and any to REVOKED; never back.
-- +goose StatementBegin
CREATE FUNCTION pc.chat_identity_link_guard() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pc, pg_temp
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.state IS DISTINCT FROM 'PROPOSED' THEN
            RAISE EXCEPTION 'a chat identity link is inserted PROPOSED' USING ERRCODE = 'check_violation';
        END IF;
        NEW.created_at := now();
        NEW.updated_at := now();
        RETURN NEW;
    END IF;
    IF NOT ((OLD.state = 'PROPOSED' AND NEW.state IN ('CONFIRMED', 'STALE', 'REVOKED'))
            OR (OLD.state = 'CONFIRMED' AND NEW.state IN ('STALE', 'REVOKED'))
            OR (OLD.state = 'STALE' AND NEW.state = 'REVOKED')) THEN
        RAISE EXCEPTION 'a chat identity link cannot go from % to %', OLD.state, NEW.state USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.state = 'CONFIRMED' THEN
        NEW.confirmed_at := now();
    ELSIF NEW.state = 'STALE' THEN
        NEW.stale_at := now();
    ELSE
        NEW.revoked_at := now();
    END IF;
    NEW.updated_at := now();
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER chat_identity_links_guard BEFORE INSERT OR UPDATE ON pc.chat_identity_links
    FOR EACH ROW EXECUTE FUNCTION pc.chat_identity_link_guard();

CREATE TABLE pc.slack_direct_messages (
    org_id            uuid        NOT NULL REFERENCES pc.orgs (id),
    id                uuid        NOT NULL,
    request_id        uuid        NOT NULL,
    user_id           uuid        NOT NULL,
    channel_record_id uuid        NOT NULL,
    im_channel        text        CHECK (im_channel IS NULL OR im_channel ~ '^D[A-Z0-9]{8,12}$'),
    ts                text        CHECK (ts IS NULL OR ts ~ '^[0-9]{10}\.[0-9]{6}$'),
    state             text        NOT NULL DEFAULT 'POSTING' CHECK (state IN ('POSTING', 'POSTED', 'UNKNOWN')),
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, request_id) REFERENCES pc.approval_requests (org_id, id),
    FOREIGN KEY (org_id, user_id) REFERENCES pc.users (org_id, id),
    FOREIGN KEY (org_id, channel_record_id) REFERENCES pc.slack_app_channels (org_id, channel_record_id),
    CHECK ((state = 'POSTED') = (ts IS NOT NULL AND im_channel IS NOT NULL))
);
CREATE UNIQUE INDEX slack_direct_messages_once ON pc.slack_direct_messages (org_id, request_id, user_id);

CREATE TABLE pc.teams_app_channels (
    org_id               uuid        NOT NULL REFERENCES pc.orgs (id),
    channel_record_id    uuid        NOT NULL,
    -- The Entra tenant, the team (its General channel id), the channel and
    -- the bot's Entra application id. None changes once stored.
    tenant_id            uuid        NOT NULL,
    team_id              text        NOT NULL CHECK (team_id ~ '^19:[A-Za-z0-9_-]{1,128}@thread[.](tacv2|skype)$'),
    teams_channel        text        NOT NULL CHECK (teams_channel ~ '^19:[A-Za-z0-9_-]{1,128}@thread\.(tacv2|skype)$'),
    app_id               uuid        NOT NULL,
    -- The Bot Framework service URL the bot posts to.
    service_url          text        NOT NULL CHECK (char_length(service_url) BETWEEN 9 AND 512 AND service_url LIKE 'https://%'),
    state                text        NOT NULL DEFAULT 'PENDING_ACTIVATION' CHECK (state IN ('PENDING_ACTIVATION', 'ACTIVE')),
    -- What Teams reported when the channel was checked: standard, private
    -- or shared. Only a standard channel is ever ACTIVE.
    membership_type      text        CHECK (membership_type IS NULL OR membership_type IN ('standard', 'private', 'shared')),
    created_at           timestamptz NOT NULL DEFAULT now(),
    activated_by         uuid,
    activated_credential uuid,
    activated_at         timestamptz,
    secret_replaced_by   text        CHECK (secret_replaced_by IS NULL OR char_length(secret_replaced_by) BETWEEN 1 AND 128),
    secret_replaced_at   timestamptz,
    shared_at            timestamptz,
    last_checked_at      timestamptz,
    updated_at           timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, channel_record_id),
    FOREIGN KEY (org_id, channel_record_id) REFERENCES pc.notification_channels (org_id, id),
    FOREIGN KEY (org_id, activated_by) REFERENCES pc.users (org_id, id),
    FOREIGN KEY (org_id, activated_credential) REFERENCES pc.webauthn_credentials (org_id, id),
    CHECK ((activated_at IS NULL) = (activated_by IS NULL) AND (activated_by IS NULL) = (activated_credential IS NULL)),
    CHECK ((secret_replaced_at IS NULL) = (secret_replaced_by IS NULL)),
    CHECK ((state = 'ACTIVE') = (activated_at IS NOT NULL)),
    CHECK (state = 'PENDING_ACTIVATION' OR membership_type = 'standard')
);

-- The Teams channel, tenant, team, bot and creation never change. A
-- configuration is inserted PENDING_ACTIVATION; it becomes ACTIVE only
-- with a person and a key, and returns to PENDING_ACTIVATION only with a
-- new client secret or when Teams reports the channel shared.
-- +goose StatementBegin
CREATE FUNCTION pc.teams_app_channel_guard() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pc, pg_temp
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.state IS DISTINCT FROM 'PENDING_ACTIVATION' OR NEW.activated_by IS NOT NULL OR NEW.secret_replaced_by IS NOT NULL THEN
            RAISE EXCEPTION 'a teams_app channel is inserted PENDING_ACTIVATION' USING ERRCODE = 'check_violation';
        END IF;
        NEW.created_at := now();
        NEW.updated_at := now();
        RETURN NEW;
    END IF;
    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id OR NEW.team_id IS DISTINCT FROM OLD.team_id
            OR NEW.teams_channel IS DISTINCT FROM OLD.teams_channel OR NEW.app_id IS DISTINCT FROM OLD.app_id
            OR NEW.service_url IS DISTINCT FROM OLD.service_url OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'a teams_app channel''s Teams channel, tenant and bot never change' USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.state = 'PENDING_ACTIVATION' AND NEW.state = 'ACTIVE' THEN
        IF NEW.activated_by IS NULL OR NEW.activated_credential IS NULL THEN
            RAISE EXCEPTION 'a teams_app channel is activated by a person with a key' USING ERRCODE = 'check_violation';
        END IF;
        NEW.activated_at := now();
    ELSIF OLD.state = 'ACTIVE' AND NEW.state = 'ACTIVE' THEN
        IF NEW.activated_by IS DISTINCT FROM OLD.activated_by OR NEW.activated_credential IS DISTINCT FROM OLD.activated_credential
                OR NEW.activated_at IS DISTINCT FROM OLD.activated_at OR NEW.membership_type IS DISTINCT FROM OLD.membership_type
                OR NEW.secret_replaced_at IS DISTINCT FROM OLD.secret_replaced_at
                OR NEW.secret_replaced_by IS DISTINCT FROM OLD.secret_replaced_by
                OR NEW.shared_at IS DISTINCT FROM OLD.shared_at THEN
            RAISE EXCEPTION 'an active teams_app channel keeps its activation' USING ERRCODE = 'check_violation';
        END IF;
    ELSIF NEW.state = 'PENDING_ACTIVATION' THEN
        IF OLD.state = 'ACTIVE' AND NEW.shared_at IS NOT DISTINCT FROM OLD.shared_at
                AND (NEW.secret_replaced_at IS NOT DISTINCT FROM OLD.secret_replaced_at OR NEW.secret_replaced_by IS NULL) THEN
            RAISE EXCEPTION 'a teams_app channel returns to PENDING_ACTIVATION only with a new client secret or when shared' USING ERRCODE = 'check_violation';
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
CREATE TRIGGER teams_app_channels_guard BEFORE INSERT OR UPDATE ON pc.teams_app_channels
    FOR EACH ROW EXECUTE FUNCTION pc.teams_app_channel_guard();

CREATE TABLE pc.teams_cards (
    org_id            uuid        NOT NULL REFERENCES pc.orgs (id),
    card_id           uuid        NOT NULL,
    request_id        uuid        NOT NULL,
    channel_record_id uuid        NOT NULL,
    activity_id       text        CHECK (activity_id IS NULL OR (char_length(activity_id) <= 256 AND activity_id ~ '^[A-Za-z0-9:;@._|-]+$')),
    state             text        NOT NULL DEFAULT 'POSTING' CHECK (state IN ('POSTING', 'POSTED', 'UNKNOWN')),
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, card_id),
    FOREIGN KEY (org_id, request_id) REFERENCES pc.approval_requests (org_id, id),
    FOREIGN KEY (org_id, channel_record_id) REFERENCES pc.teams_app_channels (org_id, channel_record_id),
    CHECK ((state = 'POSTED') = (activity_id IS NOT NULL))
);
CREATE UNIQUE INDEX teams_cards_once ON pc.teams_cards (org_id, request_id, channel_record_id);

-- +goose StatementBegin
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['chat_identity_links', 'slack_direct_messages', 'teams_app_channels', 'teams_cards']
    LOOP
        EXECUTE format('ALTER TABLE pc.%I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE pc.%I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('CREATE TRIGGER org_write_guard BEFORE INSERT OR UPDATE ON pc.%I FOR EACH ROW EXECUTE FUNCTION pc.org_write_guard()', t);
        EXECUTE format($p$CREATE POLICY tenant_isolation ON pc.%I
            USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
            WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))$p$, t);
    END LOOP;
END
$$;
-- +goose StatementEnd

GRANT SELECT, INSERT ON pc.chat_identity_links, pc.slack_direct_messages, pc.teams_app_channels, pc.teams_cards TO pc_app;
GRANT UPDATE (state, confirmed_at, stale_at, revoked_at, updated_at) ON pc.chat_identity_links TO pc_app;
GRANT UPDATE (im_channel, ts, state, updated_at) ON pc.slack_direct_messages TO pc_app;
GRANT UPDATE (state, membership_type, activated_by, activated_credential, activated_at, secret_replaced_by, secret_replaced_at,
    shared_at, last_checked_at, updated_at) ON pc.teams_app_channels TO pc_app;
GRANT UPDATE (activity_id, state, updated_at) ON pc.teams_cards TO pc_app;
-- A claim whose post was refused (nothing was posted) is released.
GRANT DELETE ON pc.slack_direct_messages, pc.teams_cards TO pc_app;
GRANT SELECT ON pc.chat_identity_links, pc.slack_direct_messages, pc.teams_app_channels, pc.teams_cards TO pc_audit_ro;

-- +goose Down
DROP TABLE pc.teams_cards;
DROP TABLE pc.teams_app_channels;
DROP FUNCTION pc.teams_app_channel_guard();
DROP TABLE pc.slack_direct_messages;
DROP TABLE pc.chat_identity_links;
DROP FUNCTION pc.chat_identity_link_guard();
DROP INDEX pc.slack_app_channels_dm;
ALTER TABLE pc.slack_app_channels DROP CONSTRAINT slack_app_channels_email_domains, DROP COLUMN allowed_email_domains,
    DROP COLUMN direct_messages;
-- DM and Teams deliveries, and teams_app channels, go before their kinds
-- do. RLS is forced even for the owner, so it is lifted for these deletes
-- only, inside this migration's transaction.
ALTER TABLE pc.deliveries NO FORCE ROW LEVEL SECURITY;
ALTER TABLE pc.notification_channels NO FORCE ROW LEVEL SECURITY;
DELETE FROM pc.deliveries WHERE kind IN ('slack_dm', 'teams_app');
DELETE FROM pc.deliveries d USING pc.notification_channels c
 WHERE d.org_id = c.org_id AND d.channel_id = c.id AND c.kind = 'teams_app';
DELETE FROM pc.notification_channels WHERE kind = 'teams_app';
ALTER TABLE pc.notification_channels FORCE ROW LEVEL SECURITY;
ALTER TABLE pc.deliveries FORCE ROW LEVEL SECURITY;
ALTER TABLE pc.deliveries
    DROP CONSTRAINT deliveries_check1,
    ADD CONSTRAINT deliveries_check1 CHECK ((kind = 'email') = (recipient_user_id IS NOT NULL)),
    DROP CONSTRAINT deliveries_kind_check,
    ADD CONSTRAINT deliveries_kind_check CHECK (kind IN ('log', 'email', 'slack', 'webhook', 'slack_app'));
ALTER TABLE pc.notification_channels
    DROP CONSTRAINT notification_channels_secret_kind,
    ADD CONSTRAINT notification_channels_secret_kind CHECK ((kind IN ('slack', 'webhook', 'slack_app')) = (secret IS NOT NULL)),
    DROP CONSTRAINT notification_channels_kind_check,
    ADD CONSTRAINT notification_channels_kind_check CHECK (kind IN ('log', 'email', 'slack', 'webhook', 'slack_app'));
