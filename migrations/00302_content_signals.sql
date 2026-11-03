-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
-- Content signals (G0 M27 D507, D512; HR-647, HR-650). The org's mode, and
-- what WATCHING would have held, by reason, so an org sees the cost before
-- it steps up to ACTIVE. Neither table holds any content or finding value.
-- No settings row means OFF.
-- +goose Up
CREATE TABLE pc.content_signal_settings (
    org_id     uuid        NOT NULL REFERENCES pc.orgs (id),
    mode       text        NOT NULL DEFAULT 'OFF' CHECK (mode IN ('OFF', 'WATCHING', 'ACTIVE')),
    updated_by text        CHECK (char_length(updated_by) BETWEEN 1 AND 128),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id)
);

CREATE TABLE pc.content_signal_would_holds (
    org_id   uuid        NOT NULL REFERENCES pc.orgs (id),
    reason   text        NOT NULL CHECK (reason ~ '^[a-z_]{1,32}$'),
    count    bigint      NOT NULL DEFAULT 0 CHECK (count >= 0),
    first_at timestamptz NOT NULL DEFAULT now(),
    last_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, reason)
);

ALTER TABLE pc.content_signal_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.content_signal_settings FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.content_signal_settings
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));
CREATE TRIGGER org_write_guard BEFORE INSERT OR UPDATE ON pc.content_signal_settings
    FOR EACH ROW EXECUTE FUNCTION pc.org_write_guard();

ALTER TABLE pc.content_signal_would_holds ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.content_signal_would_holds FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.content_signal_would_holds
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));
CREATE TRIGGER org_write_guard BEFORE INSERT OR UPDATE ON pc.content_signal_would_holds
    FOR EACH ROW EXECUTE FUNCTION pc.org_write_guard();

GRANT SELECT, INSERT ON pc.content_signal_settings, pc.content_signal_would_holds TO pc_app;
GRANT UPDATE (mode, updated_by, updated_at) ON pc.content_signal_settings TO pc_app;
GRANT UPDATE (count, last_at) ON pc.content_signal_would_holds TO pc_app;

-- +goose Down
DROP TABLE pc.content_signal_would_holds;
DROP TABLE pc.content_signal_settings;
