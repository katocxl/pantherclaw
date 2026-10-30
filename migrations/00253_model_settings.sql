-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
-- An organization's optional model drafting (G0 M21 D304, D309; G16, F181,
-- F304, HR-541, HR-545). No row means off. The key is the customer's own,
-- envelope-encrypted per org (purpose model_secrets), and nothing returns
-- it; the audit role never reads the column. The caps can only lower the
-- server's: NULL means the server's value.
-- +goose Up
CREATE TABLE pc.model_settings (
    org_id             uuid        NOT NULL REFERENCES pc.orgs (id),
    enabled            boolean     NOT NULL DEFAULT false,
    model              text        NOT NULL DEFAULT 'claude-opus-5-5' CHECK (model ~ '^[a-z0-9][a-z0-9.-]{0,62}$'),
    -- Write-only through the API.
    key_ciphertext     bytea,
    key_set_at         timestamptz,
    key_set_by         uuid,
    calls_per_minute   integer     CHECK (calls_per_minute > 0),
    tokens_per_day     bigint      CHECK (tokens_per_day > 0),
    enabled_at         timestamptz,
    enabled_by         uuid,
    enabled_credential uuid,
    updated_at         timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id),
    -- Drafting is on only with a key; clearing the key turns it off.
    CHECK (NOT enabled OR key_ciphertext IS NOT NULL),
    CHECK ((key_ciphertext IS NULL) = (key_set_at IS NULL)),
    CHECK (NOT enabled OR (enabled_at IS NOT NULL AND enabled_by IS NOT NULL AND enabled_credential IS NOT NULL))
);

ALTER TABLE pc.model_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.model_settings FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.model_settings
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));
CREATE TRIGGER org_write_guard BEFORE INSERT OR UPDATE ON pc.model_settings
    FOR EACH ROW EXECUTE FUNCTION pc.org_write_guard();

GRANT SELECT, INSERT ON pc.model_settings TO pc_app;
GRANT UPDATE (enabled, model, key_ciphertext, key_set_at, key_set_by, calls_per_minute, tokens_per_day, enabled_at,
    enabled_by, enabled_credential, updated_at) ON pc.model_settings TO pc_app;
GRANT SELECT (org_id, enabled, model, key_set_at, key_set_by, calls_per_minute, tokens_per_day, enabled_at, enabled_by,
    enabled_credential, updated_at) ON pc.model_settings TO pc_audit_ro;
-- +goose StatementBegin
DO $$ BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'pc_deleter') THEN
        GRANT SELECT, DELETE ON pc.model_settings TO pc_deleter;
    END IF;
END $$;
-- +goose StatementEnd

-- +goose Down
DROP TABLE pc.model_settings;
