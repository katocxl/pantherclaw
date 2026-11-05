-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Discovery of agents deployed in cloud agent runtimes, and daily scans
-- (G0 M34 D997; HR-768):
-- - discoveries and SaaS scan runs gain the sources aws_agentcore,
--   vertex_agent_engine and azure_foundry. Like the SaaS sources, each is
--   keyed by scan_key and holds no key.
-- - a scan run's tenant may hold a "/" (a Vertex <project>/<location>).
-- - a scan run gains the origin schedule: a daily scan a schedule started,
--   which holds a connection and a lease as a gateway scan does.
-- - pc.saas_scan_schedules lists the connections and tenants a person asked
--   to be scanned daily, one per (org, source, connection, tenant). The daily
--   job starts
--   one scan per schedule, initiated by the schedule's person, and records
--   when it last started one.
-- The unnamed checks of 00294 on the source and the origin are found by
-- their text, as 00294 found the verification purpose checks; any other
-- shape fails the migration.

-- +goose Up
-- squawk: each CHECK only widens a value list; goose runs each migration
-- in one transaction, and NOT VALID then VALIDATE keeps the lock short.
ALTER TABLE pc.discoveries
    DROP CONSTRAINT discoveries_source,
    DROP CONSTRAINT discoveries_source_key,
    ADD CONSTRAINT discoveries_source CHECK (source IN ('gateway', 'scan', 'github_scan', 'ci_scan', 'copilot_studio', 'chatgpt_enterprise',
                                                       'aws_agentcore', 'vertex_agent_engine', 'azure_foundry')) NOT VALID,
    ADD CONSTRAINT discoveries_source_key CHECK (
        (source = 'gateway' AND key_jkt IS NOT NULL AND public_jwk IS NOT NULL AND scan_key IS NULL)
        OR (source IN ('scan', 'github_scan', 'ci_scan', 'copilot_studio', 'chatgpt_enterprise',
                       'aws_agentcore', 'vertex_agent_engine', 'azure_foundry')
            AND scan_key IS NOT NULL AND key_jkt IS NULL AND public_jwk IS NULL)) NOT VALID;
-- Discoveries are few (open ones are capped per source and org, HR-148), so
-- validating them holds the lock briefly.
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.discoveries VALIDATE CONSTRAINT discoveries_source;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.discoveries VALIDATE CONSTRAINT discoveries_source_key;

-- +goose StatementBegin
DO $$
DECLARE
    c record;
    n integer := 0;
BEGIN
    -- 00294's source and origin column checks and its two table checks on
    -- the origin: exactly four, each naming a source or the origin.
    FOR c IN SELECT conname, pg_get_constraintdef(oid) AS def FROM pg_constraint
             WHERE conrelid = 'pc.saas_scan_runs'::regclass AND contype = 'c'
               AND (pg_get_constraintdef(oid) LIKE '%origin%' OR pg_get_constraintdef(oid) LIKE '%source%') LOOP
        IF c.def NOT LIKE '%chatgpt_enterprise%' AND c.def NOT LIKE '%''gateway''%' THEN
            RAISE EXCEPTION '00382: unexpected check % on pc.saas_scan_runs: %', c.conname, c.def;
        END IF;
        EXECUTE format('ALTER TABLE pc.saas_scan_runs DROP CONSTRAINT %I', c.conname);
        n := n + 1;
    END LOOP;
    IF n <> 4 THEN
        RAISE EXCEPTION '00382: found % source and origin checks on pc.saas_scan_runs, not 4', n;
    END IF;
END
$$;
-- +goose StatementEnd
ALTER TABLE pc.saas_scan_runs
    ADD CONSTRAINT saas_scan_runs_source_check CHECK (source IN ('copilot_studio', 'chatgpt_enterprise',
                                                                 'aws_agentcore', 'vertex_agent_engine', 'azure_foundry')) NOT VALID,
    ADD CONSTRAINT saas_scan_runs_origin_check CHECK (origin IN ('import', 'gateway', 'schedule')) NOT VALID,
    -- A gateway's or a schedule's scan holds a connection and a lease; an
    -- import holds neither.
    ADD CONSTRAINT saas_scan_runs_connection CHECK ((origin IN ('gateway', 'schedule')) = (connection_id IS NOT NULL)) NOT VALID,
    ADD CONSTRAINT saas_scan_runs_lease CHECK (origin IN ('gateway', 'schedule') OR verification_id IS NULL) NOT VALID,
    -- A Vertex tenant is <project>/<location> (D997a).
    DROP CONSTRAINT saas_scan_runs_tenant_check,
    ADD CONSTRAINT saas_scan_runs_tenant_check CHECK (tenant ~ '^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$') NOT VALID;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.saas_scan_runs VALIDATE CONSTRAINT saas_scan_runs_tenant_check;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.saas_scan_runs VALIDATE CONSTRAINT saas_scan_runs_source_check;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.saas_scan_runs VALIDATE CONSTRAINT saas_scan_runs_origin_check;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.saas_scan_runs VALIDATE CONSTRAINT saas_scan_runs_connection;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.saas_scan_runs VALIDATE CONSTRAINT saas_scan_runs_lease;

CREATE TABLE pc.saas_scan_schedules (
    org_id          uuid        NOT NULL REFERENCES pc.orgs (id),
    source          text        NOT NULL CHECK (source IN ('copilot_studio', 'chatgpt_enterprise',
                                                           'aws_agentcore', 'vertex_agent_engine', 'azure_foundry')),
    connection_id   uuid        NOT NULL,
    -- The tenant each scan covers, as saas_scan_runs.tenant (D997a).
    tenant          text        NOT NULL CHECK (tenant ~ '^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$'),
    -- The person who asked for it; each daily scan is started as them.
    created_by      text        NOT NULL CHECK (char_length(created_by) BETWEEN 1 AND 128),
    created_at      timestamptz NOT NULL DEFAULT now(),
    last_started_at timestamptz,
    PRIMARY KEY (org_id, source, connection_id, tenant),
    FOREIGN KEY (org_id, connection_id) REFERENCES pc.connections (org_id, id)
);

ALTER TABLE pc.saas_scan_schedules ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.saas_scan_schedules FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.saas_scan_schedules
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));
CREATE TRIGGER org_write_guard BEFORE INSERT OR UPDATE ON pc.saas_scan_schedules
    FOR EACH ROW EXECUTE FUNCTION pc.org_write_guard();

GRANT SELECT, INSERT, DELETE ON pc.saas_scan_schedules TO pc_app;
GRANT UPDATE (created_by, last_started_at) ON pc.saas_scan_schedules TO pc_app;
GRANT SELECT ON pc.saas_scan_schedules TO pc_audit_ro;
-- +goose StatementBegin
DO $$ BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'pc_deleter') THEN
        GRANT SELECT, DELETE ON pc.saas_scan_schedules TO pc_deleter;
    END IF;
END $$;
-- +goose StatementEnd

-- +goose Down
DROP TABLE pc.saas_scan_schedules;
-- Rows only this migration allows go first. Row security is lifted for these
-- deletes only, inside this migration's transaction.
ALTER TABLE pc.observations NO FORCE ROW LEVEL SECURITY;
ALTER TABLE pc.verifications NO FORCE ROW LEVEL SECURITY;
ALTER TABLE pc.saas_scan_runs NO FORCE ROW LEVEL SECURITY;
ALTER TABLE pc.discoveries NO FORCE ROW LEVEL SECURITY;
CREATE TEMPORARY TABLE m34_down_leases ON COMMIT DROP AS
    SELECT org_id, verification_id FROM pc.saas_scan_runs
    WHERE (source IN ('aws_agentcore', 'vertex_agent_engine', 'azure_foundry') OR origin = 'schedule') AND verification_id IS NOT NULL;
DELETE FROM pc.saas_scan_runs WHERE source IN ('aws_agentcore', 'vertex_agent_engine', 'azure_foundry') OR origin = 'schedule';
DELETE FROM pc.observations o USING m34_down_leases l WHERE o.org_id = l.org_id AND o.verification_id = l.verification_id;
DELETE FROM pc.verifications v USING m34_down_leases l WHERE v.org_id = l.org_id AND v.id = l.verification_id;
DELETE FROM pc.discoveries WHERE source IN ('aws_agentcore', 'vertex_agent_engine', 'azure_foundry');
ALTER TABLE pc.discoveries FORCE ROW LEVEL SECURITY;
ALTER TABLE pc.saas_scan_runs FORCE ROW LEVEL SECURITY;
ALTER TABLE pc.verifications FORCE ROW LEVEL SECURITY;
ALTER TABLE pc.observations FORCE ROW LEVEL SECURITY;
ALTER TABLE pc.saas_scan_runs
    DROP CONSTRAINT saas_scan_runs_lease,
    DROP CONSTRAINT saas_scan_runs_connection,
    DROP CONSTRAINT saas_scan_runs_origin_check,
    DROP CONSTRAINT saas_scan_runs_source_check,
    ADD CONSTRAINT saas_scan_runs_source_check CHECK (source IN ('copilot_studio', 'chatgpt_enterprise')),
    ADD CONSTRAINT saas_scan_runs_origin_check CHECK (origin IN ('import', 'gateway')),
    ADD CONSTRAINT saas_scan_runs_connection CHECK ((origin = 'gateway') = (connection_id IS NOT NULL)),
    ADD CONSTRAINT saas_scan_runs_lease CHECK (origin = 'gateway' OR verification_id IS NULL),
    DROP CONSTRAINT saas_scan_runs_tenant_check,
    ADD CONSTRAINT saas_scan_runs_tenant_check CHECK (tenant ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$');
ALTER TABLE pc.discoveries
    DROP CONSTRAINT discoveries_source_key,
    DROP CONSTRAINT discoveries_source,
    ADD CONSTRAINT discoveries_source CHECK (source IN ('gateway', 'scan', 'github_scan', 'ci_scan', 'copilot_studio', 'chatgpt_enterprise')),
    ADD CONSTRAINT discoveries_source_key CHECK (
        (source = 'gateway' AND key_jkt IS NOT NULL AND public_jwk IS NOT NULL AND scan_key IS NULL)
        OR (source IN ('scan', 'github_scan', 'ci_scan', 'copilot_studio', 'chatgpt_enterprise')
            AND scan_key IS NOT NULL AND key_jkt IS NULL AND public_jwk IS NULL));
