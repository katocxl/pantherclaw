-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Threat map (G0 M28 D716, D719; F972, F973; HR-680, HR-687).
--
-- detection_rule_state.last_input_at is when input matching a rule last
-- arrived: the engine sets it to the newest occurred_at among a batch's
-- matching events, in the transaction that advances the cursor, and never
-- moves it back. The Detect lane reads it to tell a listening rule from one
-- that hears nothing (D716).
--
-- threat_map_snapshots keeps one evaluation per org, scope, framework and
-- day (Business). scope_key is '' for the org or 'env:<uuid>'. states holds
-- one compact code string per matrix technique ("P D R T S"); counts holds
-- the per tactic counts by status. A daily job writes today's row, compares
-- it with the newest earlier one to report lanes that dropped, and deletes
-- rows older than 400 days (D719).

-- +goose Up
ALTER TABLE pc.detection_rule_state ADD COLUMN last_input_at timestamptz;

CREATE TABLE pc.threat_map_snapshots (
    org_id          uuid        NOT NULL REFERENCES pc.orgs (id),
    scope_key       text        NOT NULL CHECK (scope_key = '' OR scope_key ~ '^env:[0-9a-f-]{36}$'),
    framework       text        NOT NULL CHECK (framework IN ('atlas', 'attack-enterprise')),
    day             date        NOT NULL,
    evaluated_at    timestamptz NOT NULL,
    catalog_version text        NOT NULL CHECK (char_length(catalog_version) BETWEEN 1 AND 64),
    catalog_digest  text        NOT NULL CHECK (catalog_digest ~ '^[0-9a-f]{64}$'),
    mapping_digest  text        NOT NULL CHECK (mapping_digest ~ '^[0-9a-f]{64}$'),
    states          jsonb       NOT NULL CHECK (jsonb_typeof(states) = 'object' AND octet_length(states::text) <= 1048576),
    counts          jsonb       NOT NULL CHECK (jsonb_typeof(counts) = 'object' AND octet_length(counts::text) <= 1048576),
    PRIMARY KEY (org_id, scope_key, framework, day)
);

ALTER TABLE pc.threat_map_snapshots ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.threat_map_snapshots FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.threat_map_snapshots
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));
CREATE TRIGGER org_write_guard BEFORE INSERT OR UPDATE ON pc.threat_map_snapshots
    FOR EACH ROW EXECUTE FUNCTION pc.org_write_guard();

-- The job upserts today's row and deletes rows older than 400 days.
GRANT SELECT, INSERT, DELETE ON pc.threat_map_snapshots TO pc_app;
GRANT UPDATE (evaluated_at, catalog_version, catalog_digest, mapping_digest, states, counts)
    ON pc.threat_map_snapshots TO pc_app;
GRANT SELECT ON pc.threat_map_snapshots TO pc_audit_ro;
-- +goose StatementBegin
DO $$ BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'pc_deleter') THEN
        GRANT SELECT, DELETE ON pc.threat_map_snapshots TO pc_deleter;
    END IF;
END $$;
-- +goose StatementEnd

-- +goose Down
DROP TABLE pc.threat_map_snapshots;
ALTER TABLE pc.detection_rule_state DROP COLUMN last_input_at;
