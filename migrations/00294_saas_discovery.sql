-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
-- M26 SaaS agent discovery (N6, G0 M26 D407; HR-635..639):
-- - pc.agents.external marks an agent that lives in a SaaS tenant. It stays
--   DISCOVERED for good: it is never claimed, so it never holds a key, a
--   token or a grant. A person may name its owner, and only that.
-- - discoveries gain the sources copilot_studio and chatgpt_enterprise. The
--   key is one tenant's thing, so an import and a gateway scan of it are one
--   discovery.
-- - pc.saas_scan_runs records what each import or scan read and what it did
--   not, so "not scanned" is never taken for "none found".
-- - verifications gain the purpose saas_scan, a gateway's lease to collect.
-- +goose Up
ALTER TABLE pc.agents ADD COLUMN external boolean NOT NULL DEFAULT false;
ALTER TABLE pc.agents
    DROP CONSTRAINT agents_claimed_is_complete,
    ADD CONSTRAINT agents_claimed_is_complete CHECK (
        (claimed_at IS NULL AND team_id IS NULL AND environment_id IS NULL AND execution_context IS NULL
            AND (external OR (owner_user_id IS NULL AND backup_owner_user_id IS NULL)))
        OR (claimed_at IS NOT NULL AND team_id IS NOT NULL AND environment_id IS NOT NULL
            AND owner_user_id IS NOT NULL AND execution_context IS NOT NULL)) NOT VALID,
    ADD CONSTRAINT agents_external_never_claimed CHECK (NOT external OR claimed_at IS NULL) NOT VALID;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.agents VALIDATE CONSTRAINT agents_claimed_is_complete;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.agents VALIDATE CONSTRAINT agents_external_never_claimed;

ALTER TABLE pc.discoveries
    DROP CONSTRAINT discoveries_source,
    DROP CONSTRAINT discoveries_source_key,
    ADD CONSTRAINT discoveries_source CHECK (source IN ('gateway', 'scan', 'github_scan', 'ci_scan', 'copilot_studio', 'chatgpt_enterprise')) NOT VALID,
    ADD CONSTRAINT discoveries_source_key CHECK (
        (source = 'gateway' AND key_jkt IS NOT NULL AND public_jwk IS NOT NULL AND scan_key IS NULL)
        OR (source IN ('scan', 'github_scan', 'ci_scan', 'copilot_studio', 'chatgpt_enterprise')
            AND scan_key IS NOT NULL AND key_jkt IS NULL AND public_jwk IS NULL)) NOT VALID;
-- Discoveries are few (open ones are capped per source and org, HR-148), so
-- validating them holds the lock briefly.
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.discoveries VALIDATE CONSTRAINT discoveries_source;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.discoveries VALIDATE CONSTRAINT discoveries_source_key;

CREATE TABLE pc.saas_scan_runs (
    org_id          uuid        NOT NULL REFERENCES pc.orgs (id),
    id              uuid        NOT NULL,
    source          text        NOT NULL CHECK (source IN ('copilot_studio', 'chatgpt_enterprise')),
    origin          text        NOT NULL CHECK (origin IN ('import', 'gateway')),
    tenant          text        NOT NULL CHECK (tenant ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'),
    connection_id   uuid,
    verification_id uuid,
    state           text        NOT NULL DEFAULT 'PENDING' CHECK (state IN ('PENDING', 'RUNNING', 'DONE', 'FAILED')),
    counts          jsonb       NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(counts) = 'object' AND octet_length(counts::text) <= 4096),
    scanned         text[]      NOT NULL DEFAULT '{}' CHECK (cardinality(scanned) <= 16),
    not_scanned     jsonb       NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(not_scanned) = 'object' AND octet_length(not_scanned::text) <= 16384),
    started_by      text        NOT NULL CHECK (char_length(started_by) BETWEEN 1 AND 128),
    created_at      timestamptz NOT NULL DEFAULT now(),
    finished_at     timestamptz,
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, connection_id) REFERENCES pc.connections (org_id, id),
    FOREIGN KEY (org_id, verification_id) REFERENCES pc.verifications (org_id, id),
    CHECK ((state IN ('DONE', 'FAILED')) = (finished_at IS NOT NULL)),
    -- A gateway's scan holds a connection and a lease; an import holds neither.
    CHECK ((origin = 'gateway') = (connection_id IS NOT NULL)),
    CHECK (origin = 'gateway' OR verification_id IS NULL)
);
CREATE INDEX saas_scan_runs_recent ON pc.saas_scan_runs (org_id, source, tenant, created_at DESC);

-- A run only moves forward, a finished run never changes, and a run keeps
-- its lease, as an organization scan's does.
-- +goose StatementBegin
CREATE FUNCTION pc.saas_scan_runs_forward() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.state IN ('DONE', 'FAILED') THEN
        RAISE EXCEPTION 'SaaS scan run % is finished', OLD.id USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.state = 'PENDING' AND OLD.state <> 'PENDING' THEN
        RAISE EXCEPTION 'SaaS scan run % only moves forward', OLD.id USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.verification_id IS NOT NULL AND NEW.verification_id IS DISTINCT FROM OLD.verification_id THEN
        RAISE EXCEPTION 'SaaS scan run % keeps its lease', OLD.id USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER saas_scan_runs_forward BEFORE UPDATE ON pc.saas_scan_runs
    FOR EACH ROW EXECUTE FUNCTION pc.saas_scan_runs_forward();

ALTER TABLE pc.saas_scan_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.saas_scan_runs FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.saas_scan_runs
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));

GRANT SELECT, INSERT ON pc.saas_scan_runs TO pc_app;
GRANT UPDATE (state, counts, scanned, not_scanned, finished_at) ON pc.saas_scan_runs TO pc_app;
GRANT SELECT ON pc.saas_scan_runs TO pc_audit_ro;

-- The two checks that list the purposes gain saas_scan from their own lists,
-- first, as 00243 did; any other shape fails the migration.
-- +goose StatementBegin
DO $$
DECLARE
    c        record;
    purposes text;
    n        integer := 0;
BEGIN
    FOR c IN SELECT conname, pg_get_constraintdef(oid) AS def FROM pg_constraint
             WHERE conrelid = 'pc.verifications'::regclass AND contype = 'c'
               AND pg_get_constraintdef(oid) LIKE '%purpose%' AND pg_get_constraintdef(oid) NOT LIKE '%window_start%'
               AND pg_get_constraintdef(oid) NOT LIKE '%definition_digest%' LOOP
        SELECT string_agg(quote_literal(m.v[1]), ', ' ORDER BY m.i) INTO purposes
          FROM regexp_matches(c.def, '''([a-z_]+)''', 'g') WITH ORDINALITY AS m (v, i);
        IF purposes IS NULL OR purposes LIKE '%saas_scan%' THEN
            RAISE EXCEPTION '00294: unexpected check % on pc.verifications: %', c.conname, c.def;
        END IF;
        purposes := '''saas_scan'', ' || purposes;
        IF c.def LIKE '%transaction_id IS NULL%' THEN
            EXECUTE format('ALTER TABLE pc.verifications DROP CONSTRAINT %I, ADD CONSTRAINT %I CHECK ((purpose IN (%s)) = (transaction_id IS NULL)) NOT VALID',
                           c.conname, c.conname, purposes);
        ELSIF c.def LIKE '%follow_up%' THEN
            EXECUTE format('ALTER TABLE pc.verifications DROP CONSTRAINT %I, ADD CONSTRAINT %I CHECK (purpose IN (%s)) NOT VALID',
                           c.conname, c.conname, purposes);
        ELSE
            RAISE EXCEPTION '00294: unexpected check % on pc.verifications: %', c.conname, c.def;
        END IF;
        EXECUTE format('ALTER TABLE pc.verifications VALIDATE CONSTRAINT %I', c.conname);
        n := n + 1;
    END LOOP;
    IF n <> 2 THEN
        RAISE EXCEPTION '00294: found % purpose checks on pc.verifications, not 2', n;
    END IF;
END
$$;
-- +goose StatementEnd

-- +goose Down
DROP TABLE pc.saas_scan_runs;
DROP FUNCTION pc.saas_scan_runs_forward();
-- Rows only this migration allows go first. Row security is lifted for these
-- deletes only, inside this migration's transaction.
ALTER TABLE pc.observations NO FORCE ROW LEVEL SECURITY;
ALTER TABLE pc.verifications NO FORCE ROW LEVEL SECURITY;
ALTER TABLE pc.discoveries NO FORCE ROW LEVEL SECURITY;
DELETE FROM pc.observations o USING pc.verifications v
 WHERE o.org_id = v.org_id AND o.verification_id = v.id AND v.purpose = 'saas_scan';
DELETE FROM pc.verifications WHERE purpose = 'saas_scan';
DELETE FROM pc.discoveries WHERE source IN ('copilot_studio', 'chatgpt_enterprise');
ALTER TABLE pc.discoveries FORCE ROW LEVEL SECURITY;
ALTER TABLE pc.verifications FORCE ROW LEVEL SECURITY;
ALTER TABLE pc.observations FORCE ROW LEVEL SECURITY;
-- +goose StatementBegin
DO $$
DECLARE
    c        record;
    purposes text;
BEGIN
    FOR c IN SELECT conname, pg_get_constraintdef(oid) AS def FROM pg_constraint
             WHERE conrelid = 'pc.verifications'::regclass AND contype = 'c' AND pg_get_constraintdef(oid) LIKE '%saas_scan%' LOOP
        SELECT string_agg(quote_literal(m.v[1]), ', ' ORDER BY m.i) INTO purposes
          FROM regexp_matches(c.def, '''([a-z_]+)''', 'g') WITH ORDINALITY AS m (v, i)
         WHERE m.v[1] <> 'saas_scan';
        IF c.def LIKE '%transaction_id IS NULL%' THEN
            EXECUTE format('ALTER TABLE pc.verifications DROP CONSTRAINT %I, ADD CONSTRAINT %I CHECK ((purpose IN (%s)) = (transaction_id IS NULL))',
                           c.conname, c.conname, purposes);
        ELSE
            EXECUTE format('ALTER TABLE pc.verifications DROP CONSTRAINT %I, ADD CONSTRAINT %I CHECK (purpose IN (%s))',
                           c.conname, c.conname, purposes);
        END IF;
    END LOOP;
END
$$;
-- +goose StatementEnd
ALTER TABLE pc.discoveries
    DROP CONSTRAINT discoveries_source_key,
    DROP CONSTRAINT discoveries_source,
    ADD CONSTRAINT discoveries_source CHECK (source IN ('gateway', 'scan', 'github_scan', 'ci_scan')),
    ADD CONSTRAINT discoveries_source_key CHECK (
        (source = 'gateway' AND key_jkt IS NOT NULL AND public_jwk IS NOT NULL AND scan_key IS NULL)
        OR (source IN ('scan', 'github_scan', 'ci_scan') AND scan_key IS NOT NULL AND key_jkt IS NULL AND public_jwk IS NULL));
-- External agents have no discovery left; their rows go with their column.
ALTER TABLE pc.agents NO FORCE ROW LEVEL SECURITY;
ALTER TABLE pc.agent_changes NO FORCE ROW LEVEL SECURITY;
ALTER TABLE pc.waitlist_entries NO FORCE ROW LEVEL SECURITY;
DELETE FROM pc.waitlist_entries w USING pc.agents a WHERE w.org_id = a.org_id AND w.agent_id = a.id AND a.external;
DELETE FROM pc.agent_changes c USING pc.agents a WHERE c.org_id = a.org_id AND c.agent_id = a.id AND a.external;
DELETE FROM pc.agents WHERE external;
ALTER TABLE pc.waitlist_entries FORCE ROW LEVEL SECURITY;
ALTER TABLE pc.agent_changes FORCE ROW LEVEL SECURITY;
ALTER TABLE pc.agents FORCE ROW LEVEL SECURITY;
ALTER TABLE pc.agents
    DROP CONSTRAINT agents_external_never_claimed,
    DROP CONSTRAINT agents_claimed_is_complete,
    ADD CONSTRAINT agents_claimed_is_complete CHECK (
        (claimed_at IS NULL AND team_id IS NULL AND environment_id IS NULL AND owner_user_id IS NULL
            AND backup_owner_user_id IS NULL AND execution_context IS NULL)
        OR (claimed_at IS NOT NULL AND team_id IS NOT NULL AND environment_id IS NOT NULL
            AND owner_user_id IS NOT NULL AND execution_context IS NOT NULL));
ALTER TABLE pc.agents DROP COLUMN external;
