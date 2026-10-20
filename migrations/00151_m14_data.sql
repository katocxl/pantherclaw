-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- M14 data (coordinator decisions D15, D64, D84). A postgres connection's
-- configuration: where the gateway reaches the database (host, port,
-- database, role, TLS mode, pinned CA, internal) and the manifest of the
-- tables and columns an agent may read, with their types, data classes,
-- scope columns and limits. One row per connection, kept by the postgres
-- kind store in the transaction that creates or changes the connection;
-- the role's password is the connection's sealed credential and is never
-- here.
--
-- config is what the gateway serves; proposed waits for a person with
-- connection.manage to confirm it with a fresh security-key step-up. A new
-- connection's first configuration and every widening change are
-- proposed; a narrowing change applies at once (and voids a pending
-- proposal). Until a first configuration is confirmed the connection
-- serves nothing.

-- +goose Up
CREATE TABLE pc.postgres_connections (
    org_id               uuid        NOT NULL REFERENCES pc.orgs (id),
    connection_id        uuid        NOT NULL,
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

ALTER TABLE pc.postgres_connections ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.postgres_connections FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.postgres_connections
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));

GRANT SELECT, INSERT ON pc.postgres_connections TO pc_app;
GRANT UPDATE (config, digest, proposed, proposed_digest, proposed_at, confirmed_by, confirmed_credential, confirmed_at, updated_at)
    ON pc.postgres_connections TO pc_app;
GRANT SELECT ON pc.postgres_connections TO pc_audit_ro;

-- A postgres connection's password goes in no header and to no HTTP host
-- (D84): a static credential may have neither, and nothing else changes.
-- squawk: the new CHECK only widens the old pair; NOT VALID then VALIDATE
-- keeps the lock short.
ALTER TABLE pc.credentials
    DROP CONSTRAINT credentials_allowed_hosts_check,
    DROP CONSTRAINT credentials_header_check,
    ADD CONSTRAINT credentials_placement CHECK (
        (header ~ '^[A-Za-z0-9-]{1,64}$' AND cardinality(allowed_hosts) BETWEEN 1 AND 16)
        OR (header = '' AND scheme IS NULL AND cardinality(allowed_hosts) = 0 AND kind = 'static')) NOT VALID;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.credentials VALIDATE CONSTRAINT credentials_placement;

-- +goose Down
ALTER TABLE pc.credentials
    DROP CONSTRAINT credentials_placement,
    ADD CONSTRAINT credentials_allowed_hosts_check CHECK (cardinality(allowed_hosts) BETWEEN 1 AND 16) NOT VALID,
    ADD CONSTRAINT credentials_header_check CHECK (header ~ '^[A-Za-z0-9-]{1,64}$') NOT VALID;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.credentials VALIDATE CONSTRAINT credentials_allowed_hosts_check;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.credentials VALIDATE CONSTRAINT credentials_header_check;
DROP TABLE pc.postgres_connections;
