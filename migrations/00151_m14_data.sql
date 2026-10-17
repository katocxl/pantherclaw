-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- M14 data (coordinator decisions D15 and D64). A postgres connection's
-- configuration: where the gateway reaches the database (host, port,
-- database, role, TLS mode, pinned CA, internal) and the manifest of the
-- tables and columns an agent may read, with their types, data classes,
-- scope columns and limits. One row per connection, kept by the postgres
-- kind adapter in the transaction that creates or changes the connection;
-- the role's password is the connection's sealed credential and is never
-- here.

-- +goose Up
CREATE TABLE pc.postgres_connections (
    org_id        uuid        NOT NULL REFERENCES pc.orgs (id),
    connection_id uuid        NOT NULL,
    config        jsonb       NOT NULL CHECK (jsonb_typeof(config) = 'object' AND octet_length(config::text) <= 262144),
    -- sha256 of the canonical config, which audit records name.
    digest        bytea       NOT NULL CHECK (octet_length(digest) = 32),
    updated_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, connection_id),
    FOREIGN KEY (org_id, connection_id) REFERENCES pc.connections (org_id, id)
);

ALTER TABLE pc.postgres_connections ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.postgres_connections FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.postgres_connections
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));

GRANT SELECT, INSERT ON pc.postgres_connections TO pc_app;
GRANT UPDATE (config, digest, updated_at) ON pc.postgres_connections TO pc_app;
GRANT SELECT ON pc.postgres_connections TO pc_audit_ro;

-- +goose Down
DROP TABLE pc.postgres_connections;
