-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Cluster-wide roles (G0 M1 decision 1). Run once by the database owner /
-- superuser through `pantherclaw-server db bootstrap`; idempotent. Passwords
-- are set separately as SCRAM verifiers, never as plaintext statements.
--
--   pc_migrator  DDL only; owns schema pc and every object in it.
--   pc_app       DML for the server; never superuser, never BYPASSRLS (HR-055).
--   pc_audit_ro  read-only access to evidence.
--   pc_retention removes expired evidence bodies; used only by the worker's
--                retention job (G0 M7 design decision 9, HR-198).
--   pc_lister    NOLOGIN, BYPASSRLS; owns only the audited cross-org lister.

DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'pc_migrator') THEN
        CREATE ROLE pc_migrator;
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'pc_app') THEN
        CREATE ROLE pc_app;
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'pc_audit_ro') THEN
        CREATE ROLE pc_audit_ro;
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'pc_lister') THEN
        CREATE ROLE pc_lister;
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'pc_retention') THEN
        CREATE ROLE pc_retention;
    END IF;
END
$$;

ALTER ROLE pc_migrator LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS INHERIT;
ALTER ROLE pc_app      LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT;
ALTER ROLE pc_audit_ro LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT;
ALTER ROLE pc_lister   NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION BYPASSRLS NOINHERIT;
ALTER ROLE pc_retention LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT;

-- pc_migrator must be able to hand the lister function to pc_lister and
-- replace it later. pc_migrator already owns every table, so this grants it
-- nothing it could not do anyway.
GRANT pc_lister TO pc_migrator WITH INHERIT TRUE, SET TRUE;
