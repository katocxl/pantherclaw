-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
-- The org's approved MCP server catalog (G0 M24 D220, D221; F872, HR-585).
-- A server names what it matches: a URL host with an optional path prefix,
-- an image digest or a package reference, compared exactly. A mode row
-- appears when something first needs one; no row means WATCH.
-- +goose Up
CREATE TABLE pc.mcp_servers (
    org_id          uuid        NOT NULL REFERENCES pc.orgs (id),
    id              uuid        NOT NULL,
    name            text        NOT NULL CHECK (name ~ '^[a-z0-9][a-z0-9._-]{0,127}$'),
    title           text        NOT NULL CHECK (char_length(title) BETWEEN 1 AND 200),
    status          text        NOT NULL DEFAULT 'PROPOSED' CHECK (status IN ('PROPOSED', 'APPROVED', 'DENIED', 'REVOKED')),
    transport       text        NOT NULL CHECK (transport IN ('http', 'stdio', 'container')),
    package_ref     text        CHECK (char_length(package_ref) BETWEEN 1 AND 256),
    url_host        text        CHECK (char_length(url_host) BETWEEN 1 AND 261),
    url_path_prefix text        CHECK (char_length(url_path_prefix) BETWEEN 1 AND 512),
    image_digest    text        CHECK (image_digest ~ '^sha256:[0-9a-f]{64}$'),
    -- UNTRUSTED: the proposer's text, shown as plain text.
    notes           text        NOT NULL DEFAULT '' CHECK (char_length(notes) <= 2000),
    decided_by      text        CHECK (char_length(decided_by) BETWEEN 1 AND 128),
    decided_at      timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, name),
    -- A server that matches nothing could be approved and do nothing.
    CHECK (package_ref IS NOT NULL OR url_host IS NOT NULL OR image_digest IS NOT NULL),
    CHECK (url_path_prefix IS NULL OR url_host IS NOT NULL),
    CHECK ((status = 'PROPOSED') = (decided_at IS NULL)),
    CHECK ((decided_by IS NULL) = (decided_at IS NULL))
);
CREATE INDEX mcp_servers_status ON pc.mcp_servers (org_id, status);

CREATE TABLE pc.mcp_catalog_settings (
    org_id     uuid        NOT NULL REFERENCES pc.orgs (id),
    mode       text        NOT NULL DEFAULT 'WATCH' CHECK (mode IN ('OFF', 'WATCH', 'ENFORCE')),
    updated_by text        CHECK (char_length(updated_by) BETWEEN 1 AND 128),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id)
);

ALTER TABLE pc.mcp_servers ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.mcp_servers FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.mcp_servers
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));
CREATE TRIGGER org_write_guard BEFORE INSERT OR UPDATE ON pc.mcp_servers
    FOR EACH ROW EXECUTE FUNCTION pc.org_write_guard();

ALTER TABLE pc.mcp_catalog_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.mcp_catalog_settings FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.mcp_catalog_settings
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));
CREATE TRIGGER org_write_guard BEFORE INSERT OR UPDATE ON pc.mcp_catalog_settings
    FOR EACH ROW EXECUTE FUNCTION pc.org_write_guard();

GRANT SELECT, INSERT ON pc.mcp_servers, pc.mcp_catalog_settings TO pc_app;
GRANT UPDATE (status, decided_by, decided_at) ON pc.mcp_servers TO pc_app;
GRANT UPDATE (mode, updated_by, updated_at) ON pc.mcp_catalog_settings TO pc_app;
GRANT SELECT ON pc.mcp_servers, pc.mcp_catalog_settings TO pc_audit_ro;
-- +goose StatementBegin
DO $$ BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'pc_deleter') THEN
        GRANT SELECT, DELETE ON pc.mcp_servers, pc.mcp_catalog_settings TO pc_deleter;
    END IF;
END $$;
-- +goose StatementEnd

-- The action of a revoke is scoped to its server (D224). Its controls stay on
-- connections, so containment_controls does not change.
ALTER TABLE pc.response_actions
    DROP CONSTRAINT response_actions_scope_type_check,
    ADD CONSTRAINT response_actions_scope_type_check CHECK (scope_type IN ('agent', 'run', 'grant', 'connection', 'resource', 'principal',
                                                                           'credential', 'transaction', 'mcp_server')) NOT VALID;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.response_actions VALIDATE CONSTRAINT response_actions_scope_type_check;

-- +goose Down
ALTER TABLE pc.response_actions
    DROP CONSTRAINT response_actions_scope_type_check,
    ADD CONSTRAINT response_actions_scope_type_check CHECK (scope_type IN ('agent', 'run', 'grant', 'connection', 'resource', 'principal',
                                                                           'credential', 'transaction'));
DROP TABLE pc.mcp_catalog_settings;
DROP TABLE pc.mcp_servers;
