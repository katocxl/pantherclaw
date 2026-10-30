-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
-- Gateway alert state (G0 M18 D151, HR-470, HR-471): what the per-org
-- fleet sweep has alerted for each gateway, so a silence episode alerts
-- once when it starts and once when it ends, and a version below the
-- org's minimum alerts once per version. silent_since is the last report
-- before the silence; below_minimum_version is the parsed version alerted
-- ('unknown' when it does not parse).
-- +goose Up
CREATE TABLE pc.gateway_alert_state (
    org_id                    uuid        NOT NULL REFERENCES pc.orgs (id),
    gateway_id                uuid        NOT NULL,
    silent_since              timestamptz,
    silent_notified_at        timestamptz,
    below_minimum_version     text        CHECK (char_length(below_minimum_version) BETWEEN 1 AND 72),
    below_minimum_notified_at timestamptz,
    PRIMARY KEY (org_id, gateway_id),
    FOREIGN KEY (org_id, gateway_id) REFERENCES pc.gateways (org_id, id) ON DELETE CASCADE,
    CHECK ((silent_since IS NULL) = (silent_notified_at IS NULL)),
    CHECK ((below_minimum_version IS NULL) = (below_minimum_notified_at IS NULL))
);

ALTER TABLE pc.gateway_alert_state ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.gateway_alert_state FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.gateway_alert_state
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));
CREATE TRIGGER org_write_guard BEFORE INSERT OR UPDATE ON pc.gateway_alert_state
    FOR EACH ROW EXECUTE FUNCTION pc.org_write_guard();

GRANT SELECT, INSERT ON pc.gateway_alert_state TO pc_app;
GRANT UPDATE (silent_since, silent_notified_at, below_minimum_version, below_minimum_notified_at) ON pc.gateway_alert_state TO pc_app;
GRANT SELECT ON pc.gateway_alert_state TO pc_audit_ro;
-- +goose StatementBegin
DO $$ BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'pc_deleter') THEN
        GRANT SELECT, DELETE ON pc.gateway_alert_state TO pc_deleter;
    END IF;
END $$;
-- +goose StatementEnd

-- +goose Down
DROP TABLE pc.gateway_alert_state;
