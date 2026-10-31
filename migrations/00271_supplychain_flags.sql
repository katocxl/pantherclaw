-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
-- F868, F869 supply-chain flags (G0 M24 D211, D212). A gateway now reports each
-- listed tool's input schema, capped at 64 KiB, with its digest. The checks of
-- internal/supplychain run on a new inventory item and on an imported package
-- version, and each hit is a row here. A flag informs a person and decides
-- nothing: it approves nothing and refuses nothing, and the absence of flags
-- means "no known flags" (HR-582). Listed text stays UNTRUSTED (HR-583): detail
-- holds PantherClaw's own note and byte offsets, never the text it points at.
-- +goose Up
ALTER TABLE pc.connection_inventory
    -- UNTRUSTED: the listed input schema as JSON text, kept as listed so a
    -- flag's offsets stay true. Empty when none was reported.
    ADD COLUMN input_schema           text    NOT NULL DEFAULT '' CHECK (octet_length(input_schema) <= 65536),
    ADD COLUMN input_schema_digest    text    NOT NULL DEFAULT '' CHECK (input_schema_digest ~ '^(sha256:[0-9a-f]{64})?$'),
    -- The schema was too long to report: only its digest came.
    ADD COLUMN input_schema_truncated boolean NOT NULL DEFAULT false,
    -- UNTRUSTED: the tool's title, annotations and output schema as a JSON
    -- object, which the checks read too.
    ADD COLUMN listed_extra           text    NOT NULL DEFAULT '' CHECK (octet_length(listed_extra) <= 16384),
    -- UNTRUSTED: what an operator reported from `pclaw mcp inspect --submit`
    -- (D214). Their machine's word, not a check PantherClaw ran.
    ADD COLUMN operator_note          text    NOT NULL DEFAULT '' CHECK (octet_length(operator_note) <= 8192),
    ADD COLUMN operator_note_by       text    CHECK (char_length(operator_note_by) BETWEEN 1 AND 100),
    ADD COLUMN operator_note_at       timestamptz;
GRANT UPDATE (input_schema, input_schema_digest, input_schema_truncated, listed_extra, operator_note, operator_note_by, operator_note_at)
    ON pc.connection_inventory TO pc_app;

-- Tool names approved on other connections, for tool_shadowing.
-- squawk-ignore require-concurrent-index-creation
CREATE INDEX connection_inventory_approved_tools ON pc.connection_inventory (org_id, name) WHERE kind = 'TOOL' AND state = 'COVERED';

CREATE TABLE pc.supplychain_flags (
    org_id             uuid        NOT NULL REFERENCES pc.orgs (id),
    id                 uuid        NOT NULL,
    -- What was flagged: a listed item of a connection, or a tool of an
    -- imported package version.
    connection_id      uuid,
    inventory_id       uuid,
    package_version_id uuid,
    -- The pattern-checked tool name; empty for a resource or template.
    tool               text        NOT NULL DEFAULT '' CHECK (tool ~ '^[A-Za-z0-9_.-]{0,128}$'),
    digest             text        NOT NULL CHECK (digest ~ '^sha256:[0-9a-f]{64}$'),
    check_kind         text        NOT NULL CHECK (check_kind IN ('hidden_instruction', 'injection_pattern', 'tool_shadowing',
                                                                  'overbroad_schema', 'rug_pull', 'provenance_unknown',
                                                                  'schema_unavailable')),
    severity           text        NOT NULL CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH')),
    -- {"note": PantherClaw's own words, "spans": [{"field", "start", "end"}]}.
    detail             jsonb       NOT NULL,
    first_seen         timestamptz NOT NULL DEFAULT now(),
    last_seen          timestamptz NOT NULL DEFAULT now(),
    -- CLEARED: what it was on left review (HR-582: never by the flag itself).
    state              text        NOT NULL DEFAULT 'OPEN' CHECK (state IN ('OPEN', 'CLEARED')),
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, connection_id) REFERENCES pc.connections (org_id, id),
    FOREIGN KEY (org_id, inventory_id) REFERENCES pc.connection_inventory (org_id, id),
    FOREIGN KEY (org_id, package_version_id) REFERENCES pc.package_versions (org_id, id),
    CHECK ((inventory_id IS NOT NULL) = (connection_id IS NOT NULL)),
    CHECK ((inventory_id IS NOT NULL) <> (package_version_id IS NOT NULL))
);
CREATE UNIQUE INDEX supplychain_flags_inventory ON pc.supplychain_flags (org_id, inventory_id, check_kind) WHERE inventory_id IS NOT NULL;
CREATE UNIQUE INDEX supplychain_flags_package ON pc.supplychain_flags (org_id, package_version_id, tool, check_kind)
    WHERE package_version_id IS NOT NULL;
CREATE INDEX supplychain_flags_open ON pc.supplychain_flags (org_id, id) WHERE state = 'OPEN';
CREATE INDEX supplychain_flags_connection ON pc.supplychain_flags (org_id, connection_id, id);

ALTER TABLE pc.supplychain_flags ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.supplychain_flags FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.supplychain_flags
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));
CREATE TRIGGER org_write_guard BEFORE INSERT OR UPDATE ON pc.supplychain_flags
    FOR EACH ROW EXECUTE FUNCTION pc.org_write_guard();

GRANT SELECT, INSERT ON pc.supplychain_flags TO pc_app;
GRANT UPDATE (severity, detail, last_seen, state) ON pc.supplychain_flags TO pc_app;
GRANT SELECT ON pc.supplychain_flags TO pc_audit_ro;
-- +goose StatementBegin
DO $$ BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'pc_deleter') THEN
        GRANT SELECT, DELETE ON pc.supplychain_flags TO pc_deleter;
    END IF;
END $$;
-- +goose StatementEnd

-- +goose Down
DROP TABLE pc.supplychain_flags;
DROP INDEX pc.connection_inventory_approved_tools;
ALTER TABLE pc.connection_inventory
    DROP COLUMN operator_note_at,
    DROP COLUMN operator_note_by,
    DROP COLUMN operator_note,
    DROP COLUMN listed_extra,
    DROP COLUMN input_schema_truncated,
    DROP COLUMN input_schema_digest,
    DROP COLUMN input_schema;
