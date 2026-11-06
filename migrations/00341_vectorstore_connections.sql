-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Vectorstore connections (G0 M30 D922-D925a; HR-704, HR-705). Connection
-- kind vectorstore: a pgvector retrieval index in the customer's database,
-- one table the admin created from `pclaw connections vectorstore ddl` (the
-- gateway never runs DDL). Like a postgres connection it has no base URL,
-- and its password is the connection's header-less static credential.
--
-- pc.vectorstore_connections keeps each vectorstore connection's settings,
-- written by the vectorstore kind store in the transaction that creates or
-- changes the connection: the endpoint, fixed once the connection exists
-- (the service refuses a change with VECTORSTORE_ENDPOINT_IMMUTABLE,
-- D925a), the table and its shape, and the agents that may write without a
-- person (D924).

-- +goose Up
-- squawk: each new CHECK only widens the old one; NOT VALID then VALIDATE
-- keeps the lock short, and goose runs the migration in one transaction.
ALTER TABLE pc.connections
    DROP CONSTRAINT connections_kind_check,
    ADD CONSTRAINT connections_kind_check
        CHECK (kind IN ('http', 'mcp', 'local', 'mcp_container', 'postgres', 'a2a', 'model', 'vectorstore')) NOT VALID;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.connections VALIDATE CONSTRAINT connections_kind_check;
ALTER TABLE pc.connections
    DROP CONSTRAINT connections_base_url_kind,
    ADD CONSTRAINT connections_base_url_kind
        CHECK ((kind IN ('local', 'mcp_container', 'postgres', 'vectorstore')) = (base_url IS NULL)) NOT VALID;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.connections VALIDATE CONSTRAINT connections_base_url_kind;

CREATE TABLE pc.vectorstore_connections (
    org_id           uuid        NOT NULL REFERENCES pc.orgs (id),
    connection_id    uuid        NOT NULL,
    host             text        NOT NULL CHECK (host ~ '^[A-Za-z0-9]([A-Za-z0-9.:-]{0,251}[A-Za-z0-9])?$'),
    port             int         NOT NULL CHECK (port BETWEEN 1 AND 65535),
    database         text        NOT NULL CHECK (database ~ '^[a-z_][a-z0-9_]{0,62}$'),
    db_user          text        NOT NULL CHECK (db_user ~ '^[a-z_][a-z0-9_]{0,62}$'),
    sslmode          text        NOT NULL CHECK (sslmode IN ('verify-full', 'require')),
    ca_pem           text        CHECK (octet_length(ca_pem) <= 16384),
    internal         boolean     NOT NULL DEFAULT false,
    schema_name      text        NOT NULL CHECK (schema_name ~ '^[a-z_][a-z0-9_]{0,62}$'),
    table_name       text        NOT NULL CHECK (table_name ~ '^[a-z_][a-z0-9_]{0,62}$'),
    dimensions       int         NOT NULL CHECK (dimensions BETWEEN 1 AND 12288),
    distance         text        NOT NULL CHECK (distance IN ('cosine', 'l2', 'inner_product')),
    writer_agent_ids uuid[]      NOT NULL DEFAULT '{}' CHECK (cardinality(writer_agent_ids) <= 64),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, connection_id),
    FOREIGN KEY (org_id, connection_id) REFERENCES pc.connections (org_id, id),
    -- require only for an internal database with a pinned CA (as postgres).
    CONSTRAINT vectorstore_connections_sslmode CHECK (sslmode = 'verify-full' OR (internal AND ca_pem IS NOT NULL))
);

ALTER TABLE pc.vectorstore_connections ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.vectorstore_connections FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.vectorstore_connections
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));
CREATE TRIGGER org_write_guard BEFORE INSERT OR UPDATE ON pc.vectorstore_connections
    FOR EACH ROW EXECUTE FUNCTION pc.org_write_guard();

-- The endpoint columns are fixed (D925a): pc_app may update only the
-- table's shape and the writer list.
GRANT SELECT, INSERT ON pc.vectorstore_connections TO pc_app;
GRANT UPDATE (schema_name, table_name, dimensions, distance, writer_agent_ids, updated_at)
    ON pc.vectorstore_connections TO pc_app;
GRANT SELECT ON pc.vectorstore_connections TO pc_audit_ro;
-- +goose StatementBegin
DO $$ BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'pc_deleter') THEN
        GRANT SELECT, DELETE ON pc.vectorstore_connections TO pc_deleter;
    END IF;
END $$;
-- +goose StatementEnd

-- +goose Down
-- The rollback refuses while a vectorstore connection exists, and never
-- deletes one: the old CHECKs have no place for it.
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT FROM pc.connections WHERE kind = 'vectorstore') THEN
        RAISE EXCEPTION '00341 down: vectorstore connections exist; delete them first';
    END IF;
END
$$;
-- +goose StatementEnd
DROP TABLE pc.vectorstore_connections;
ALTER TABLE pc.connections
    DROP CONSTRAINT connections_base_url_kind,
    ADD CONSTRAINT connections_base_url_kind
        CHECK ((kind IN ('local', 'mcp_container', 'postgres')) = (base_url IS NULL));
ALTER TABLE pc.connections
    DROP CONSTRAINT connections_kind_check,
    ADD CONSTRAINT connections_kind_check
        CHECK (kind IN ('http', 'mcp', 'local', 'mcp_container', 'postgres', 'a2a', 'model'));
