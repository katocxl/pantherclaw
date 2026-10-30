-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Per-database setup, run by the owner / superuser connected to the target
-- database after the roles exist. Idempotent.

-- Only our roles may connect; nobody may create objects outside schema pc.
DO $$
BEGIN
    EXECUTE format('REVOKE ALL ON DATABASE %I FROM PUBLIC', current_database());
    EXECUTE format('GRANT CONNECT ON DATABASE %I TO pc_migrator, pc_app, pc_audit_ro, pc_retention', current_database());
END
$$;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;

CREATE SCHEMA IF NOT EXISTS pc AUTHORIZATION pc_migrator;
ALTER SCHEMA pc OWNER TO pc_migrator;
REVOKE ALL ON SCHEMA pc FROM PUBLIC;
GRANT USAGE ON SCHEMA pc TO pc_app, pc_audit_ro, pc_lister, pc_retention;
-- A new function owner needs CREATE on the schema (ALTER FUNCTION … OWNER TO
-- pc_lister). pc_lister cannot log in, so only pc_migrator can use this.
GRANT CREATE ON SCHEMA pc TO pc_lister;

-- No implicit privileges: every migration grants exactly what each role needs.
ALTER DEFAULT PRIVILEGES FOR ROLE pc_migrator IN SCHEMA pc REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE pc_migrator IN SCHEMA pc REVOKE ALL ON SEQUENCES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE pc_migrator IN SCHEMA pc REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

-- The backup role, when `db bootstrap --backup-password-file` created it
-- (G0 M13 D21, HR-378): connect, read every table and sequence of schema pc
-- (now and as pc_migrator creates them), nothing else.
DO $$
BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'pc_backup') THEN
        EXECUTE format('GRANT CONNECT ON DATABASE %I TO pc_backup', current_database());
        GRANT USAGE ON SCHEMA pc TO pc_backup;
        GRANT SELECT ON ALL TABLES IN SCHEMA pc TO pc_backup;
        GRANT SELECT ON ALL SEQUENCES IN SCHEMA pc TO pc_backup;
        ALTER DEFAULT PRIVILEGES FOR ROLE pc_migrator IN SCHEMA pc GRANT SELECT ON TABLES TO pc_backup;
        ALTER DEFAULT PRIVILEGES FOR ROLE pc_migrator IN SCHEMA pc GRANT SELECT ON SEQUENCES TO pc_backup;
    END IF;
END
$$;

-- The deleter role, when `db bootstrap --deleter-password-file` created it
-- (G0 M13 D34, HR-391): connect, and SELECT and DELETE on every org table
-- (the tables under the tenant_isolation policy) but the platform's
-- deletion records, and only the tombstone columns of pc.orgs. It never
-- bypasses RLS. Tables created later get the same from their migrations
-- or from running this bootstrap again; the deletion job refuses to start
-- while any org table lacks them.
DO $$
DECLARE
    t text;
BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'pc_deleter') THEN
        EXECUTE format('GRANT CONNECT ON DATABASE %I TO pc_deleter', current_database());
        GRANT USAGE ON SCHEMA pc TO pc_deleter;
        FOR t IN SELECT p.tablename FROM pg_policies p
                 WHERE p.schemaname = 'pc' AND p.policyname = 'tenant_isolation'
                   AND p.tablename NOT IN ('orgs', 'deletion_records')
        LOOP
            EXECUTE format('GRANT SELECT, DELETE ON pc.%I TO pc_deleter', t);
        END LOOP;
        IF to_regclass('pc.orgs') IS NOT NULL THEN
            GRANT SELECT ON pc.orgs TO pc_deleter;
            GRANT UPDATE (name, slug, created_by_account, updated_at) ON pc.orgs TO pc_deleter;
        END IF;
    END IF;
END
$$;

-- The keystore role, when `db bootstrap --keystore-password-file` created
-- it (G0 M18 D171, HR-487): connect, SELECT on pc.keys and pc.deks, and
-- UPDATE of only their wrapped key and kek_id columns (the both-columns
-- trigger of migration 00224 applies). The tenant_isolation policies
-- bind it like pc_app. Here for a role created after migration 00224.
DO $$
BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'pc_keystore') THEN
        EXECUTE format('GRANT CONNECT ON DATABASE %I TO pc_keystore', current_database());
        GRANT USAGE ON SCHEMA pc TO pc_keystore;
        IF to_regprocedure('pc.keystore_rewrap_guard()') IS NOT NULL THEN
            GRANT SELECT, UPDATE (wrapped_private_key, kek_id) ON pc.keys TO pc_keystore;
            GRANT SELECT, UPDATE (wrapped_key, kek_id) ON pc.deks TO pc_keystore;
            GRANT SELECT (id, state) ON pc.orgs TO pc_keystore;
            GRANT EXECUTE ON FUNCTION pc.org_write_guard() TO pc_keystore;
        END IF;
    END IF;
END
$$;
