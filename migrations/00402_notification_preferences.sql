-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Notification preferences per person (G0 M36 D1065; HR-792). How a
-- person gets approval notices: IMMEDIATE (the default) or one DIGEST every
-- 15, 30 or 60 minutes, and quiet hours (HH:MM to HH:MM in an IANA time
-- zone) during which their own emails, direct messages and pushes wait.
-- Routing and escalation to other people never change. One row per person,
-- set by that person only.

-- +goose Up
CREATE TABLE pc.notification_preferences (
    org_id            uuid        NOT NULL REFERENCES pc.orgs (id),
    user_id           uuid        NOT NULL,
    approval_delivery text        NOT NULL DEFAULT 'IMMEDIATE' CHECK (approval_delivery IN ('IMMEDIATE', 'DIGEST')),
    digest_minutes    smallint    NOT NULL DEFAULT 15 CHECK (digest_minutes IN (15, 30, 60)),
    quiet_start       text        CHECK (quiet_start ~ '^([01][0-9]|2[0-3]):[0-5][0-9]$'),
    quiet_end         text        CHECK (quiet_end ~ '^([01][0-9]|2[0-3]):[0-5][0-9]$'),
    time_zone         text        CHECK (char_length(time_zone) BETWEEN 1 AND 64),
    updated_at        timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, user_id),
    FOREIGN KEY (org_id, user_id) REFERENCES pc.users (org_id, id),
    CONSTRAINT notification_preferences_quiet CHECK ((quiet_start IS NULL) = (quiet_end IS NULL)
                                                     AND (quiet_start IS NULL OR quiet_start <> quiet_end))
);

ALTER TABLE pc.notification_preferences ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.notification_preferences FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.notification_preferences
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));
CREATE TRIGGER org_write_guard BEFORE INSERT OR UPDATE ON pc.notification_preferences
    FOR EACH ROW EXECUTE FUNCTION pc.org_write_guard();
GRANT SELECT, INSERT, UPDATE ON pc.notification_preferences TO pc_app;
GRANT SELECT ON pc.notification_preferences TO pc_audit_ro;
-- +goose StatementBegin
DO $$ BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'pc_deleter') THEN
        GRANT SELECT, DELETE ON pc.notification_preferences TO pc_deleter;
    END IF;
END $$;
-- +goose StatementEnd

-- +goose Down
DROP TABLE pc.notification_preferences;
