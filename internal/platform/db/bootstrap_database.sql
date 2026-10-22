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
