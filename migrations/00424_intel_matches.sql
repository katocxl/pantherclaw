-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Indicator matches (G0 M38 D1104; FQ38-2; HR-819). One row per indicator
-- an org's object matched, written with audit intel.matched when the org
-- consumes the feed. object_type and object_ref name what matched (a
-- connection's upstream server, an inventory item, a run's content); mode
-- is the org's consume mode at the time. A match holds or alerts and never
-- refuses. Insert-only.

-- +goose Up
CREATE TABLE pc.intel_matches (
    org_id        uuid        NOT NULL REFERENCES pc.orgs (id),
    id            uuid        NOT NULL,
    indicator_id  text        NOT NULL CHECK (indicator_id ~ '^[a-z0-9][a-z0-9._-]{0,63}$'),
    kind          text        NOT NULL CHECK (kind IN ('mcp_server', 'tool_description', 'injection_text')),
    object_type   text        NOT NULL CHECK (object_type IN ('connection', 'inventory_item', 'run', 'transaction')),
    object_ref    text        NOT NULL CHECK (char_length(object_ref) BETWEEN 1 AND 256),
    connection_id uuid,
    tool          text        CHECK (tool IS NULL OR char_length(tool) BETWEEN 1 AND 128),
    mode          text        NOT NULL CHECK (mode IN ('HOLD', 'ALERT_ONLY')),
    at            timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, id)
);
CREATE INDEX intel_matches_connection ON pc.intel_matches (org_id, connection_id, at DESC) WHERE connection_id IS NOT NULL;
CREATE INDEX intel_matches_at ON pc.intel_matches (org_id, at DESC);

ALTER TABLE pc.intel_matches ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.intel_matches FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.intel_matches
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));
CREATE TRIGGER org_write_guard BEFORE INSERT OR UPDATE ON pc.intel_matches
    FOR EACH ROW EXECUTE FUNCTION pc.org_write_guard();

GRANT SELECT, INSERT ON pc.intel_matches TO pc_app;
GRANT SELECT ON pc.intel_matches TO pc_audit_ro;
-- +goose StatementBegin
DO $$ BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'pc_deleter') THEN
        GRANT SELECT, DELETE ON pc.intel_matches TO pc_deleter;
    END IF;
END $$;
-- +goose StatementEnd

-- +goose Down
DROP TABLE pc.intel_matches;
