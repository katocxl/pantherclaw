-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Owned accounts (G0 M30 D933, D935; HR-707, HR-708). The cloud accounts,
-- GitHub organizations, email domains, GCP projects and Azure tenants an org
-- names as its own. An action that shares to an account kind whose value is
-- not listed here holds for a person (SHARE_ACCOUNT_NOT_OWNED); an empty
-- list owns nothing, so every such share holds. Adding a row loosens that
-- hold, so it is a protected change applied on confirm; removing one is
-- immediate. Value formats are checked in Go.

-- +goose Up
CREATE TABLE pc.owned_accounts (
    org_id   uuid        NOT NULL REFERENCES pc.orgs (id),
    id       uuid        NOT NULL PRIMARY KEY,
    kind     text        NOT NULL CHECK (kind IN ('aws_account', 'github_org', 'email_domain', 'gcp_project', 'azure_tenant')),
    value    text        NOT NULL CHECK (char_length(value) BETWEEN 1 AND 253),
    added_by text        NOT NULL,
    added_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (org_id, kind, value)
);

ALTER TABLE pc.owned_accounts ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.owned_accounts FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.owned_accounts
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));
CREATE TRIGGER org_write_guard BEFORE INSERT OR UPDATE ON pc.owned_accounts
    FOR EACH ROW EXECUTE FUNCTION pc.org_write_guard();

GRANT SELECT, INSERT, DELETE ON pc.owned_accounts TO pc_app;
GRANT SELECT ON pc.owned_accounts TO pc_audit_ro;
-- +goose StatementBegin
DO $$ BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'pc_deleter') THEN
        GRANT SELECT, DELETE ON pc.owned_accounts TO pc_deleter;
    END IF;
END $$;
-- +goose StatementEnd

-- +goose Down
DROP TABLE pc.owned_accounts;
