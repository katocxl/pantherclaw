-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
-- M13 D41/D52/D54: a platform-owned recovery journal and a tenant write barrier.
-- +goose Up
CREATE TABLE pc.org_deletion_journal (
    org_id uuid NOT NULL REFERENCES pc.orgs (id)
        CHECK (org_id = '00000000-0000-7000-8000-000000000001'::uuid),
    id uuid NOT NULL,
    deleted_org_id uuid NOT NULL,
    snapshot jsonb NOT NULL CHECK (jsonb_typeof(snapshot) = 'object'),
    signed_intent text NOT NULL CHECK (char_length(signed_intent) BETWEEN 1 AND 1048576),
    complete boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, id)
);
CREATE UNIQUE INDEX org_deletion_replay ON pc.org_deletion_journal
    (org_id, deleted_org_id, (snapshot->'record'->>'reapplied_from'))
    WHERE snapshot->'record'->>'reapplied_from' IS NOT NULL;
ALTER TABLE pc.org_deletion_journal ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.org_deletion_journal FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.org_deletion_journal
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));
GRANT SELECT, INSERT ON pc.org_deletion_journal TO pc_app;
GRANT UPDATE (complete) ON pc.org_deletion_journal TO pc_app;
CREATE TABLE pc.account_deletion_events (
    org_id uuid NOT NULL REFERENCES pc.orgs (id)
        CHECK (org_id = '00000000-0000-7000-8000-000000000001'::uuid),
    id uuid NOT NULL,
    account_id uuid NOT NULL,
    kind text NOT NULL CHECK (kind IN ('account.deletion_started','account.deleted')),
    record_digest bytea NOT NULL CHECK (octet_length(record_digest)=32),
    PRIMARY KEY (org_id,id),
    UNIQUE (org_id,account_id,kind,record_digest)
);
ALTER TABLE pc.account_deletion_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.account_deletion_events FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.account_deletion_events
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));
GRANT SELECT, INSERT ON pc.account_deletion_events TO pc_app;
-- Bootstrap's future-table rule grants tenant SELECT/DELETE to the deleter;
-- the platform org is explicitly refused by the deletion use case.
-- +goose StatementBegin
DO $$ BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'pc_deleter') THEN
        GRANT SELECT, DELETE ON pc.org_deletion_journal,pc.account_deletion_events TO pc_deleter;
    END IF;
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'pc_backup') THEN
        GRANT SELECT ON pc.org_deletion_journal,pc.account_deletion_events TO pc_backup;
    END IF;
END $$;
-- +goose StatementEnd
ALTER TABLE pc.automations ALTER CONSTRAINT automations_enabled_version_fk DEFERRABLE INITIALLY IMMEDIATE;
-- A retention writer needs only these columns for the invoker guard. RLS
-- remains forced: no new global purpose, policy or SECURITY DEFINER.
GRANT SELECT (id, state) ON pc.orgs TO pc_retention;
-- +goose StatementBegin
CREATE FUNCTION pc.org_write_guard() RETURNS trigger LANGUAGE plpgsql
SET search_path = pg_catalog, pc AS $$
DECLARE current_state text;
BEGIN
    PERFORM pg_advisory_xact_lock_shared(hashtextextended('pc.org.write/' || NEW.org_id::text, 0));
    SELECT state INTO current_state FROM pc.orgs WHERE id = NEW.org_id;
    IF current_state IS NULL OR current_state = 'DELETED' THEN
        RAISE EXCEPTION 'organisation does not permit writes' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END $$;
-- +goose StatementEnd
GRANT EXECUTE ON FUNCTION pc.org_write_guard() TO pc_app, pc_retention;
-- Every existing tenant table is covered, including legal holds. The catalog
-- test makes future tables opt into the same barrier before they can land.
-- +goose StatementBegin
DO $$ DECLARE t text; BEGIN
    FOR t IN SELECT tablename FROM pg_policies
        WHERE schemaname = 'pc' AND policyname = 'tenant_isolation' AND tablename <> 'orgs'
    LOOP
        EXECUTE format('CREATE TRIGGER org_write_guard BEFORE INSERT OR UPDATE ON pc.%I FOR EACH ROW EXECUTE FUNCTION pc.org_write_guard()', t);
    END LOOP;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE FUNCTION pc.org_delete_barrier() RETURNS trigger LANGUAGE plpgsql
SET search_path = pg_catalog, pc AS $$
BEGIN
    IF NEW.state = 'DELETED' AND OLD.state IS DISTINCT FROM 'DELETED' THEN
        PERFORM pg_advisory_xact_lock(hashtextextended('pc.org.write/' || NEW.id::text, 0));
    END IF;
    RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER orgs_delete_barrier BEFORE UPDATE ON pc.orgs FOR EACH ROW EXECUTE FUNCTION pc.org_delete_barrier();
-- +goose Down
DROP TRIGGER orgs_delete_barrier ON pc.orgs;
DROP FUNCTION pc.org_delete_barrier();
-- +goose StatementBegin
DO $$ DECLARE t text; BEGIN
    FOR t IN SELECT tablename FROM pg_policies WHERE schemaname = 'pc' AND policyname = 'tenant_isolation' AND tablename <> 'orgs'
    LOOP
        EXECUTE format('DROP TRIGGER IF EXISTS org_write_guard ON pc.%I', t);
    END LOOP;
END $$;
-- +goose StatementEnd
DROP FUNCTION pc.org_write_guard();
REVOKE SELECT (id, state) ON pc.orgs FROM pc_retention;
ALTER TABLE pc.automations ALTER CONSTRAINT automations_enabled_version_fk NOT DEFERRABLE;
DROP TABLE pc.org_deletion_journal;
DROP TABLE pc.account_deletion_events;
