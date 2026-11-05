-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Shared threat-intel indicators (G0 M38 D1103; FD13, FQ38-2; HR-817,
-- HR-818, HR-820).
--
-- pc.intel_settings is each org's choice: consume OFF (the default), HOLD
-- (a call to a matched server or tool, or a payload carrying matched
-- injection text, waits for a person) or ALERT_ONLY; share (contributing
-- indicators) is off by default. No row is OFF and not shared.
--
-- pc.intel_state and pc.intel_indicators are platform tables without tenant
-- data or org_id, written in a global transaction for the "intel" purpose
-- when a verified feed is imported, and read by every org's matching (no row
-- security: HR-050 covers tenant tables). pc.intel_state is one row: the
-- highest feed version accepted with its payload digest, so an older feed,
-- or another feed under the same version, is refused (HR-817).
-- pc.intel_indicators is the current set, replaced in the same transaction.
-- Indicators hold hashes only, never the text they were made from (HR-818).

-- +goose Up
CREATE TABLE pc.intel_settings (
    org_id     uuid        PRIMARY KEY REFERENCES pc.orgs (id),
    consume    text        NOT NULL DEFAULT 'OFF' CHECK (consume IN ('OFF', 'HOLD', 'ALERT_ONLY')),
    share      boolean     NOT NULL DEFAULT false,
    updated_by text        NOT NULL CHECK (char_length(updated_by) BETWEEN 1 AND 256),
    updated_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE pc.intel_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.intel_settings FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.intel_settings
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));
CREATE TRIGGER org_write_guard BEFORE INSERT OR UPDATE ON pc.intel_settings
    FOR EACH ROW EXECUTE FUNCTION pc.org_write_guard();

GRANT SELECT, INSERT ON pc.intel_settings TO pc_app;
GRANT UPDATE (consume, share, updated_by, updated_at) ON pc.intel_settings TO pc_app;
GRANT SELECT ON pc.intel_settings TO pc_audit_ro;
-- +goose StatementBegin
DO $$ BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'pc_deleter') THEN
        GRANT SELECT, DELETE ON pc.intel_settings TO pc_deleter;
    END IF;
END $$;
-- +goose StatementEnd

CREATE TABLE pc.intel_state (
    id           smallint    PRIMARY KEY CHECK (id = 1),
    feed_version bigint      NOT NULL CHECK (feed_version >= 1),
    feed_digest  text        NOT NULL CHECK (feed_digest ~ '^[0-9a-f]{64}$'),
    kid          text        NOT NULL CHECK (char_length(kid) BETWEEN 1 AND 128),
    issued_at    timestamptz NOT NULL,
    expires_at   timestamptz NOT NULL,
    source       text        NOT NULL CHECK (source IN ('IMPORT', 'FETCH')),
    updated_at   timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE pc.intel_indicators (
    id           text        PRIMARY KEY CHECK (id ~ '^[a-z0-9][a-z0-9._-]{0,63}$'),
    kind         text        NOT NULL CHECK (kind IN ('mcp_server', 'tool_description', 'injection_text')),
    sha256       text        CHECK (sha256 IS NULL OR sha256 ~ '^[0-9a-f]{64}$'),
    shingles     text[]      NOT NULL DEFAULT '{}' CHECK (cardinality(shingles) <= 64),
    severity     text        NOT NULL CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH')),
    techniques   text[]      NOT NULL DEFAULT '{}' CHECK (cardinality(techniques) <= 16),
    first_seen   date        NOT NULL,
    summary      text        NOT NULL CHECK (char_length(summary) <= 280),
    feed_version bigint      NOT NULL CHECK (feed_version >= 1),
    -- injection_text carries shingles; the other kinds one sha256.
    CHECK ((kind = 'injection_text') = (sha256 IS NULL)),
    CHECK ((kind = 'injection_text') = (cardinality(shingles) > 0))
);
CREATE INDEX intel_indicators_sha256 ON pc.intel_indicators (sha256) WHERE sha256 IS NOT NULL;

GRANT SELECT, INSERT, UPDATE ON pc.intel_state TO pc_app;
GRANT SELECT, INSERT, DELETE ON pc.intel_indicators TO pc_app;
GRANT SELECT ON pc.intel_state, pc.intel_indicators TO pc_audit_ro;

-- +goose Down
DROP TABLE pc.intel_indicators;
DROP TABLE pc.intel_state;
DROP TABLE pc.intel_settings;
