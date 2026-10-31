-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
-- PantherClaw Hub anti-rollback state (G0 M23 D102, HR-562): the highest Hub
-- index each organization accepted. An older index, or another one under the
-- same version, is refused per organization.
-- +goose Up
CREATE TABLE pc.hub_state (
    org_id        uuid        PRIMARY KEY REFERENCES pc.orgs (id),
    index_version bigint      NOT NULL CHECK (index_version >= 1),
    index_digest  text        NOT NULL CHECK (index_digest ~ '^[0-9a-f]{64}$'),
    updated_at    timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE pc.hub_state ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.hub_state FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.hub_state
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));
CREATE TRIGGER org_write_guard BEFORE INSERT OR UPDATE ON pc.hub_state
    FOR EACH ROW EXECUTE FUNCTION pc.org_write_guard();

GRANT SELECT, INSERT ON pc.hub_state TO pc_app;
GRANT UPDATE (index_version, index_digest, updated_at) ON pc.hub_state TO pc_app;
GRANT SELECT ON pc.hub_state TO pc_audit_ro;
-- +goose StatementBegin
DO $$ BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'pc_deleter') THEN
        GRANT SELECT, DELETE ON pc.hub_state TO pc_deleter;
    END IF;
END $$;
-- +goose StatementEnd

-- +goose Down
DROP TABLE pc.hub_state;
