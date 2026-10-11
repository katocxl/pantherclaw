-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Connectors (G0 M9 track C slice C1; HR-084, HR-216, decision 5). A
-- connection of kind mcp_container is a third-party stdio MCP server that
-- a customer-hosted gateway runs in a hardened container. It has no base
-- URL and holds no credential: its egress goes through an edge to the
-- gateway, which maps each request through the egress connection named in
-- its spec and places that connection's credential (design decision 18).
--
-- connector_specs keeps every version of a connector's spec, keyed by the
-- connection revision it was set at; the connection's current spec is the
-- latest. Specs are inserted, never changed: a new spec is a weakening
-- change of the connection (HR-183). Whether a gateway is PantherClaw-
-- hosted is not stored: it comes from the server's configuration only
-- (design decision 7, as built). A new spec invalidates the connector's
-- coverage (HR-211).

-- +goose Up
ALTER TABLE pc.connections DROP CONSTRAINT connections_kind_check;
ALTER TABLE pc.connections ADD CONSTRAINT connections_kind_check
    CHECK (kind IN ('http', 'mcp', 'local', 'mcp_container'));

-- The base URL check of 00041 was named by Postgres; find it by its text.
-- +goose StatementBegin
DO $$
DECLARE
    c text;
BEGIN
    SELECT conname INTO STRICT c FROM pg_constraint
    WHERE conrelid = 'pc.connections'::regclass AND contype = 'c'
      AND pg_get_constraintdef(oid) = 'CHECK (((kind = ''local''::text) = (base_url IS NULL)))';
    EXECUTE format('ALTER TABLE pc.connections RENAME CONSTRAINT %I TO connections_base_url_kind', c);
END
$$;
-- +goose StatementEnd
ALTER TABLE pc.connections DROP CONSTRAINT connections_base_url_kind;
ALTER TABLE pc.connections ADD CONSTRAINT connections_base_url_kind
    CHECK ((kind IN ('local', 'mcp_container')) = (base_url IS NULL));
-- A connector reaches nothing itself and holds no credential.
ALTER TABLE pc.connections ADD CONSTRAINT connections_connector_shape
    CHECK (kind <> 'mcp_container' OR (access_mode = 'none' AND cardinality(allowed_hosts) = 0
        AND cardinality(agent_hosts) = 0 AND credential_header IS NULL));

CREATE TABLE pc.connector_specs (
    org_id                  uuid        NOT NULL REFERENCES pc.orgs (id),
    connection_id           uuid        NOT NULL,
    -- The connection revision this spec was set at.
    revision                integer     NOT NULL CHECK (revision > 0),
    -- Pinned by digest: repo@sha256:<hex>, or a local image id.
    image                   text        NOT NULL CHECK (image ~ '^([a-z0-9][a-z0-9._/:-]{0,254}@)?sha256:[0-9a-f]{64}$'),
    -- The program and its arguments, run as given (no shell).
    command                 text[]      NOT NULL CHECK (cardinality(command) BETWEEN 1 AND 32
        AND array_position(command, NULL) IS NULL),
    -- Non-secret environment values (name to value).
    environment             jsonb       NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(environment) = 'object'
        AND octet_length(environment::text) <= 65536),
    -- Names the gateway sets to a placeholder: the credential is placed on
    -- the mediated egress, never in the container.
    credential_placeholders text[]      NOT NULL DEFAULT '{}' CHECK (cardinality(credential_placeholders) <= 16),
    -- The http connection through which its egress is mediated; none means
    -- no egress at all.
    egress_connection_id    uuid,
    memory_mib              integer     NOT NULL CHECK (memory_mib BETWEEN 64 AND 8192),
    milli_cpus              integer     NOT NULL CHECK (milli_cpus BETWEEN 100 AND 8000),
    pids                    integer     NOT NULL CHECK (pids BETWEEN 32 AND 4096),
    created_by              text        NOT NULL CHECK (char_length(created_by) BETWEEN 1 AND 100),
    created_at              timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, connection_id, revision),
    FOREIGN KEY (org_id, connection_id) REFERENCES pc.connections (org_id, id),
    FOREIGN KEY (org_id, egress_connection_id) REFERENCES pc.connections (org_id, id),
    CHECK (egress_connection_id IS DISTINCT FROM connection_id)
);

ALTER TABLE pc.connector_specs ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.connector_specs FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.connector_specs
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));

-- Specs are inserted, never changed or deleted; the time is the database's.
GRANT SELECT ON pc.connector_specs TO pc_app, pc_audit_ro;
GRANT INSERT (org_id, connection_id, revision, image, command, environment, credential_placeholders, egress_connection_id,
    memory_mib, milli_cpus, pids, created_by) ON pc.connector_specs TO pc_app;

-- A new spec changes what the connector runs and reaches, but on the
-- connection row only its revision moves, which 00087 keeps quiet: record
-- the change here (HR-211).
-- +goose StatementBegin
CREATE FUNCTION pc.coverage_connector_spec_changed() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pc, pg_temp
AS $$
BEGIN
    INSERT INTO pc.coverage_invalidations (org_id, id, kind, connection_id, subject_id, detail)
    VALUES (NEW.org_id, pc.coverage_uuid_v7(), 'connection', NEW.connection_id, NEW.connection_id, 'connector spec changed');
    RETURN NULL;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER connector_specs_coverage AFTER INSERT ON pc.connector_specs
    FOR EACH ROW EXECUTE FUNCTION pc.coverage_connector_spec_changed();

-- +goose Down
DROP TRIGGER connector_specs_coverage ON pc.connector_specs;
DROP FUNCTION pc.coverage_connector_spec_changed();
DROP TABLE pc.connector_specs;
ALTER TABLE pc.connections DROP CONSTRAINT connections_connector_shape;
ALTER TABLE pc.connections DROP CONSTRAINT connections_base_url_kind;
ALTER TABLE pc.connections ADD CONSTRAINT connections_check CHECK ((kind = 'local') = (base_url IS NULL));
ALTER TABLE pc.connections DROP CONSTRAINT connections_kind_check;
ALTER TABLE pc.connections ADD CONSTRAINT connections_kind_check CHECK (kind IN ('http', 'mcp', 'local'));
