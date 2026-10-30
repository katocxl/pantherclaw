-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
-- Gateway fleet policy (G0 M18 D151, HR-470): one row per org with an
-- advisory minimum gateway version and how long a gateway may go without a
-- status report before it is alerted as silent. The minimum version is
-- flagged and alerted, never enforced: gateways report their version
-- themselves. An org without a row has no minimum and the default 300 s.
-- +goose Up
CREATE TABLE pc.gateway_fleet_policy (
    org_id                uuid        NOT NULL REFERENCES pc.orgs (id),
    minimum_version       text        CHECK (char_length(minimum_version) BETWEEN 1 AND 64),
    silence_after_seconds int         NOT NULL DEFAULT 300 CHECK (silence_after_seconds BETWEEN 120 AND 86400),
    updated_by            text        NOT NULL CHECK (char_length(updated_by) BETWEEN 1 AND 100),
    updated_at            timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id)
);

ALTER TABLE pc.gateway_fleet_policy ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.gateway_fleet_policy FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.gateway_fleet_policy
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));
CREATE TRIGGER org_write_guard BEFORE INSERT OR UPDATE ON pc.gateway_fleet_policy
    FOR EACH ROW EXECUTE FUNCTION pc.org_write_guard();

GRANT SELECT, INSERT ON pc.gateway_fleet_policy TO pc_app;
GRANT UPDATE (minimum_version, silence_after_seconds, updated_by, updated_at) ON pc.gateway_fleet_policy TO pc_app;
GRANT SELECT ON pc.gateway_fleet_policy TO pc_audit_ro;
-- +goose StatementBegin
DO $$ BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'pc_deleter') THEN
        GRANT SELECT, DELETE ON pc.gateway_fleet_policy TO pc_deleter;
    END IF;
END $$;
-- +goose StatementEnd

-- +goose Down
DROP TABLE pc.gateway_fleet_policy;
