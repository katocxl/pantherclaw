-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Contributed indicators (G0 M38 D1105; HR-818, HR-820, HR-821). An org
-- with share on contributes an indicator made from a confirmed finding;
-- only its hash or shingles are kept, computed here, with the day it was
-- made and never a finer time. The operator's export reads QUEUED rows and
-- marks them EXPORTED, and writes no org id, account or time finer than a
-- day. Who contributed is in the org's audit (intel.contributed), not here.

-- +goose Up
CREATE TABLE pc.intel_contributions (
    org_id      uuid    NOT NULL REFERENCES pc.orgs (id),
    id          uuid    NOT NULL,
    kind        text    NOT NULL CHECK (kind IN ('mcp_server', 'tool_description', 'injection_text')),
    sha256      text    CHECK (sha256 IS NULL OR sha256 ~ '^[0-9a-f]{64}$'),
    shingles    text[]  NOT NULL DEFAULT '{}' CHECK (cardinality(shingles) <= 64),
    severity    text    NOT NULL CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH')),
    techniques  text[]  NOT NULL DEFAULT '{}' CHECK (cardinality(techniques) <= 16),
    created_day date    NOT NULL DEFAULT current_date,
    state       text    NOT NULL DEFAULT 'QUEUED' CHECK (state IN ('QUEUED', 'EXPORTED')),
    PRIMARY KEY (org_id, id),
    CHECK ((kind = 'injection_text') = (sha256 IS NULL)),
    CHECK ((kind = 'injection_text') = (cardinality(shingles) > 0))
);
CREATE INDEX intel_contributions_queued ON pc.intel_contributions (org_id) WHERE state = 'QUEUED';

ALTER TABLE pc.intel_contributions ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.intel_contributions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.intel_contributions
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));
CREATE TRIGGER org_write_guard BEFORE INSERT OR UPDATE ON pc.intel_contributions
    FOR EACH ROW EXECUTE FUNCTION pc.org_write_guard();

-- +goose StatementBegin
-- Only QUEUED -> EXPORTED, and nothing else changes.
CREATE FUNCTION pc.intel_contributions_guard() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF NOT (OLD.state = 'QUEUED' AND NEW.state = 'EXPORTED')
       OR (NEW.org_id, NEW.id, NEW.kind, NEW.sha256, NEW.shingles, NEW.severity, NEW.techniques, NEW.created_day)
          IS DISTINCT FROM (OLD.org_id, OLD.id, OLD.kind, OLD.sha256, OLD.shingles, OLD.severity, OLD.techniques, OLD.created_day) THEN
        RAISE EXCEPTION 'intel contribution: only QUEUED to EXPORTED' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER intel_contributions_guard BEFORE UPDATE ON pc.intel_contributions
    FOR EACH ROW EXECUTE FUNCTION pc.intel_contributions_guard();

GRANT SELECT, INSERT ON pc.intel_contributions TO pc_app;
GRANT UPDATE (state) ON pc.intel_contributions TO pc_app;
GRANT SELECT ON pc.intel_contributions TO pc_audit_ro;
-- +goose StatementBegin
DO $$ BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'pc_deleter') THEN
        GRANT SELECT, DELETE ON pc.intel_contributions TO pc_deleter;
    END IF;
END $$;
-- +goose StatementEnd

-- +goose Down
DROP TABLE pc.intel_contributions;
DROP FUNCTION pc.intel_contributions_guard();
