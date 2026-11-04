-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Snowflake connections (G0 M31 D962; HR-726). Connection kind snowflake:
-- a Snowflake account the gateway reads over the Snowflake SQL API with
-- statements it builds itself from the reviewed manifest, as for postgres.
-- Its base URL is the account's host; its credential is a
-- snowflake_keypair (00351), from which the gateway signs a key-pair JWT
-- per call.
--
-- pc.snowflake_connections keeps each snowflake connection's account,
-- warehouse, database and schema, fixed once the connection exists (the
-- service refuses a change with SNOWFLAKE_ENDPOINT_IMMUTABLE), and its
-- manifest as pc.postgres_connections keeps one: config is what the
-- gateway serves; proposed waits for a person with connection.manage to
-- confirm it with a fresh security-key step-up. A first manifest and every
-- widening change are proposed; a narrowing change applies at once. Until
-- a first manifest is confirmed the connection serves nothing.

-- +goose Up
-- squawk: the new CHECK only widens the old one; NOT VALID then VALIDATE
-- keeps the lock short, and goose runs the migration in one transaction.
ALTER TABLE pc.connections
    DROP CONSTRAINT connections_kind_check,
    ADD CONSTRAINT connections_kind_check
        CHECK (kind IN ('http', 'mcp', 'local', 'mcp_container', 'postgres', 'a2a', 'model', 'vectorstore', 'snowflake')) NOT VALID;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.connections VALIDATE CONSTRAINT connections_kind_check;
-- A snowflake connection has a base URL (its account's host), so
-- connections_base_url_kind stays as 00341 made it.

CREATE TABLE pc.snowflake_connections (
    org_id               uuid        NOT NULL REFERENCES pc.orgs (id),
    connection_id        uuid        NOT NULL,
    account              text        NOT NULL CHECK (account ~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,254}(\.[A-Za-z0-9_-]{1,64}){0,2}$'),
    warehouse            text        NOT NULL CHECK (warehouse ~ '^[a-z_][a-z0-9_]{0,62}$'),
    database_name        text        NOT NULL CHECK (database_name ~ '^[a-z_][a-z0-9_]{0,62}$'),
    schema_name          text        NOT NULL CHECK (schema_name ~ '^[a-z_][a-z0-9_]{0,62}$'),
    config               jsonb       CHECK (jsonb_typeof(config) = 'object' AND octet_length(config::text) <= 262144),
    -- sha256 of the canonical config, which audit records name.
    digest               bytea       CHECK (octet_length(digest) = 32),
    proposed             jsonb       CHECK (jsonb_typeof(proposed) = 'object' AND octet_length(proposed::text) <= 262144),
    proposed_digest      bytea       CHECK (octet_length(proposed_digest) = 32),
    proposed_at          timestamptz,
    confirmed_by         uuid,
    confirmed_credential uuid,
    confirmed_at         timestamptz,
    updated_at           timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, connection_id),
    FOREIGN KEY (org_id, connection_id) REFERENCES pc.connections (org_id, id),
    FOREIGN KEY (org_id, confirmed_by) REFERENCES pc.users (org_id, id),
    CHECK ((config IS NULL) = (digest IS NULL)),
    CHECK ((proposed IS NULL) = (proposed_digest IS NULL)),
    CHECK ((proposed IS NULL) = (proposed_at IS NULL)),
    CHECK (config IS NOT NULL OR proposed IS NOT NULL),
    CHECK ((confirmed_by IS NULL) = (confirmed_at IS NULL) AND (confirmed_by IS NULL) = (confirmed_credential IS NULL))
);

ALTER TABLE pc.snowflake_connections ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.snowflake_connections FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.snowflake_connections
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));

-- The account, warehouse, database and schema are fixed: pc_app may update
-- only the manifest columns.
GRANT SELECT, INSERT ON pc.snowflake_connections TO pc_app;
GRANT UPDATE (config, digest, proposed, proposed_digest, proposed_at, confirmed_by, confirmed_credential, confirmed_at, updated_at)
    ON pc.snowflake_connections TO pc_app;
GRANT SELECT ON pc.snowflake_connections TO pc_audit_ro;

-- +goose Down
-- The rollback refuses while a snowflake connection exists, and never
-- deletes one: the old CHECK has no place for it.
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT FROM pc.connections WHERE kind = 'snowflake') THEN
        RAISE EXCEPTION '00350 down: snowflake connections exist; delete them first';
    END IF;
END
$$;
-- +goose StatementEnd
DROP TABLE pc.snowflake_connections;
ALTER TABLE pc.connections
    DROP CONSTRAINT connections_kind_check,
    ADD CONSTRAINT connections_kind_check
        CHECK (kind IN ('http', 'mcp', 'local', 'mcp_container', 'postgres', 'a2a', 'model', 'vectorstore'));
