-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Verified org deletion (G0 M13 D22, D34, F2, ADR-0035; HR-390..392,
-- T-176).
--
-- An org is set DELETED first, and a DELETED org never becomes anything
-- else: every sign-in, API key, gateway and workload of it fails closed
-- from then on (HR-392). Its rows are then removed by pc_deleter, a login
-- role of its own (`db bootstrap --deleter-password-file`) used only by
-- the worker's data.delete_org job: SELECT and DELETE on every org table
-- (the tables under the tenant_isolation policy), and on pc.orgs only the
-- scrub of the org's row to a tombstone (id, state DELETED, deleted_at;
-- its name becomes "deleted", its slug and creating account go).
-- It never bypasses RLS: it works one org at a time with app.org_id set,
-- and only for an org that is already DELETED (HR-391). When the role does
-- not exist yet, this migration grants nothing; `db bootstrap
-- --deleter-password-file` grants the same later.
--
-- The append-only and guard triggers that refuse deletes (cases and case
-- entries, automation test cases) let pc_deleter delete, and removing a
-- GitHub installation by pc_deleter writes no coverage invalidation into
-- the org being emptied. Nothing else changes for any other role.
--
-- deletion_records keeps, in the platform org, the signed record of each
-- deleted org (HR-390): what was removed, how it was verified, and until
-- when backups may still hold it.

-- +goose Up
-- The new column is NULL in every row, so the check holds at once; orgs is
-- a small table.
ALTER TABLE pc.orgs
    ADD COLUMN deleted_at timestamptz,
    -- squawk-ignore constraint-missing-not-valid
    ADD CONSTRAINT orgs_deleted CHECK (state = 'DELETED' OR deleted_at IS NULL);

-- +goose StatementBegin
CREATE FUNCTION pc.org_state_guard() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pc, pg_temp
AS $$
BEGIN
    IF TG_OP = 'UPDATE' AND OLD.state = 'DELETED' AND NEW.state IS DISTINCT FROM 'DELETED' THEN
        RAISE EXCEPTION 'a deleted org stays deleted' USING ERRCODE = 'check_violation';
    END IF;
    IF TG_OP = 'UPDATE' AND OLD.deleted_at IS NOT NULL AND NEW.deleted_at IS DISTINCT FROM OLD.deleted_at THEN
        RAISE EXCEPTION 'an org''s deletion time never changes' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.state = 'DELETED' AND NEW.deleted_at IS NULL THEN
        NEW.deleted_at := now();
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER orgs_state_guard BEFORE INSERT OR UPDATE ON pc.orgs
    FOR EACH ROW EXECUTE FUNCTION pc.org_state_guard();

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION pc.case_entry_immutable()
 RETURNS trigger
 LANGUAGE plpgsql
 SET search_path TO 'pc', 'pg_temp'
AS $function$
BEGIN
    -- The org's deletion removes its cases (G0 M13 D34, HR-391).
    IF TG_OP = 'DELETE' AND current_user = 'pc_deleter' THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'case entries are append-only' USING ERRCODE = 'insufficient_privilege';
END
$function$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION pc.automation_test_case_guard()
 RETURNS trigger
 LANGUAGE plpgsql
 SET search_path TO 'pg_catalog', 'pc'
AS $function$
DECLARE
    v_org     uuid := CASE WHEN TG_OP = 'DELETE' THEN OLD.org_id ELSE NEW.org_id END;
    v_version uuid := CASE WHEN TG_OP = 'DELETE' THEN OLD.version_id ELSE NEW.version_id END;
    v_state   text;
BEGIN
    -- The org's deletion removes every test case (G0 M13 D34, HR-391).
    IF TG_OP = 'DELETE' AND current_user = 'pc_deleter' THEN
        RETURN OLD;
    END IF;
    IF TG_OP = 'UPDATE' THEN
        RAISE EXCEPTION 'automation test cases are replaced, never updated' USING ERRCODE = 'check_violation';
    END IF;
    SELECT v.state INTO v_state FROM pc.automation_versions v WHERE v.org_id = v_org AND v.id = v_version;
    IF v_state IS DISTINCT FROM 'DRAFT' AND v_state IS DISTINCT FROM 'VALIDATED' THEN
        RAISE EXCEPTION 'automation version % is %: its tests no longer change', v_version, v_state
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END
$function$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION pc.coverage_github_installation_changed()
 RETURNS trigger
 LANGUAGE plpgsql
 SET search_path TO 'pc', 'pg_temp'
AS $function$
DECLARE
    -- When the installation was read again, and by whom, changes nothing
    -- it reaches.
    quiet constant text[] := ARRAY['read_at', 'updated_by', 'updated_at'];
    org uuid;
    conn uuid;
BEGIN
    -- The org's deletion invalidates nothing: the org is going (G0 M13 D34).
    IF TG_OP = 'DELETE' AND current_user = 'pc_deleter' THEN
        RETURN NULL;
    END IF;
    IF TG_OP = 'UPDATE' AND (to_jsonb(NEW) - quiet) IS NOT DISTINCT FROM (to_jsonb(OLD) - quiet) THEN
        RETURN NULL;
    END IF;
    IF TG_OP = 'DELETE' THEN
        org := OLD.org_id;
        conn := OLD.connection_id;
    ELSE
        org := NEW.org_id;
        conn := NEW.connection_id;
    END IF;
    INSERT INTO pc.coverage_invalidations (org_id, id, kind, connection_id, subject_id, detail)
    VALUES (org, pc.coverage_uuid_v7(), 'credential', conn, conn,
            CASE TG_OP WHEN 'INSERT' THEN 'GitHub installation recorded'
                       WHEN 'DELETE' THEN 'GitHub installation removed'
                       ELSE 'GitHub installation changed' END);
    RETURN NULL;
END;
$function$;
-- +goose StatementEnd

CREATE TABLE pc.deletion_records (
    -- Always the platform org.
    org_id               uuid        NOT NULL REFERENCES pc.orgs (id),
    id                   uuid        NOT NULL,
    deleted_org_id       uuid        NOT NULL,
    reason               text        NOT NULL CHECK (reason IN ('requested', 'lapse_90d')),
    requested_by_account uuid,
    -- The record as canonical JSON, and signed (compact JWS, receipts key).
    record               jsonb       NOT NULL CHECK (jsonb_typeof(record) = 'object'),
    signed_record        text        NOT NULL CHECK (char_length(signed_record) BETWEEN 1 AND 1048576),
    created_at           timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, deleted_org_id)
);
ALTER TABLE pc.deletion_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.deletion_records FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.deletion_records
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));
-- A record is written once and never changes.
GRANT SELECT, INSERT ON pc.deletion_records TO pc_app;
GRANT SELECT ON pc.deletion_records TO pc_audit_ro;

-- The deleter's grants (also in bootstrap_database.sql): every org table
-- but the platform's own deletion records, and the tombstone of pc.orgs.
-- +goose StatementBegin
DO $$
DECLARE
    t text;
BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'pc_deleter') THEN
        FOR t IN SELECT p.tablename FROM pg_policies p
                 WHERE p.schemaname = 'pc' AND p.policyname = 'tenant_isolation'
                   AND p.tablename NOT IN ('orgs', 'deletion_records')
        LOOP
            EXECUTE format('GRANT SELECT, DELETE ON pc.%I TO pc_deleter', t);
        END LOOP;
        GRANT SELECT ON pc.orgs TO pc_deleter;
        GRANT UPDATE (name, slug, created_by_account, updated_at) ON pc.orgs TO pc_deleter;
    END IF;
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'pc_backup') THEN
        GRANT SELECT ON pc.deletion_records TO pc_backup;
    END IF;
END
$$;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DO $$
DECLARE
    t text;
BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'pc_deleter') THEN
        FOR t IN SELECT p.tablename FROM pg_policies p
                 WHERE p.schemaname = 'pc' AND p.policyname = 'tenant_isolation'
        LOOP
            EXECUTE format('REVOKE ALL ON pc.%I FROM pc_deleter', t);
        END LOOP;
    END IF;
END
$$;
-- +goose StatementEnd
DROP TABLE pc.deletion_records;

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION pc.coverage_github_installation_changed()
 RETURNS trigger
 LANGUAGE plpgsql
 SET search_path TO 'pc', 'pg_temp'
AS $function$
DECLARE
    -- When the installation was read again, and by whom, changes nothing
    -- it reaches.
    quiet constant text[] := ARRAY['read_at', 'updated_by', 'updated_at'];
    org uuid;
    conn uuid;
BEGIN
    IF TG_OP = 'UPDATE' AND (to_jsonb(NEW) - quiet) IS NOT DISTINCT FROM (to_jsonb(OLD) - quiet) THEN
        RETURN NULL;
    END IF;
    IF TG_OP = 'DELETE' THEN
        org := OLD.org_id;
        conn := OLD.connection_id;
    ELSE
        org := NEW.org_id;
        conn := NEW.connection_id;
    END IF;
    INSERT INTO pc.coverage_invalidations (org_id, id, kind, connection_id, subject_id, detail)
    VALUES (org, pc.coverage_uuid_v7(), 'credential', conn, conn,
            CASE TG_OP WHEN 'INSERT' THEN 'GitHub installation recorded'
                       WHEN 'DELETE' THEN 'GitHub installation removed'
                       ELSE 'GitHub installation changed' END);
    RETURN NULL;
END;
$function$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION pc.automation_test_case_guard()
 RETURNS trigger
 LANGUAGE plpgsql
 SET search_path TO 'pg_catalog', 'pc'
AS $function$
DECLARE
    v_org     uuid := CASE WHEN TG_OP = 'DELETE' THEN OLD.org_id ELSE NEW.org_id END;
    v_version uuid := CASE WHEN TG_OP = 'DELETE' THEN OLD.version_id ELSE NEW.version_id END;
    v_state   text;
BEGIN
    IF TG_OP = 'UPDATE' THEN
        RAISE EXCEPTION 'automation test cases are replaced, never updated' USING ERRCODE = 'check_violation';
    END IF;
    SELECT v.state INTO v_state FROM pc.automation_versions v WHERE v.org_id = v_org AND v.id = v_version;
    IF v_state IS DISTINCT FROM 'DRAFT' AND v_state IS DISTINCT FROM 'VALIDATED' THEN
        RAISE EXCEPTION 'automation version % is %: its tests no longer change', v_version, v_state
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END
$function$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION pc.case_entry_immutable()
 RETURNS trigger
 LANGUAGE plpgsql
 SET search_path TO 'pc', 'pg_temp'
AS $function$
BEGIN
    RAISE EXCEPTION 'case entries are append-only' USING ERRCODE = 'insufficient_privilege';
END
$function$;
-- +goose StatementEnd

DROP TRIGGER orgs_state_guard ON pc.orgs;
DROP FUNCTION pc.org_state_guard();
ALTER TABLE pc.orgs
    DROP CONSTRAINT orgs_deleted,
    DROP COLUMN deleted_at;
