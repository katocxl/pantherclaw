-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
-- Calls to an organization's model provider (G0 M21 D304, D309; HR-545) and
-- the drafts they produced. A call holds who asked, for what and how much,
-- never the text sent or returned. Its row is written before the provider is
-- called, so a call that never finished still counts against the caps. A
-- model_drafts row marks a policy or automation version as origin=model; the
-- version tables themselves are unchanged.
-- +goose Up
CREATE TABLE pc.model_calls (
    org_id        uuid        NOT NULL REFERENCES pc.orgs (id),
    id            uuid        NOT NULL,
    actor         text        NOT NULL CHECK (char_length(actor) BETWEEN 1 AND 200),
    task          text        NOT NULL CHECK (task IN ('SEARCH_QUERY', 'POLICY_DRAFT', 'AUTOMATION_DRAFT')),
    model         text        NOT NULL CHECK (model ~ '^[a-z0-9][a-z0-9.-]{0,62}$'),
    -- PENDING until the call ends, then OK or the refusing reason code.
    outcome       text        NOT NULL DEFAULT 'PENDING' CHECK (outcome ~ '^[A-Z][A-Z_]{1,63}$'),
    input_tokens  integer     NOT NULL DEFAULT 0 CHECK (input_tokens >= 0),
    output_tokens integer     NOT NULL DEFAULT 0 CHECK (output_tokens >= 0),
    created_at    timestamptz NOT NULL DEFAULT now(),
    finished_at   timestamptz,
    PRIMARY KEY (org_id, id),
    CHECK ((outcome = 'PENDING') = (finished_at IS NULL))
);
CREATE INDEX model_calls_recent ON pc.model_calls (org_id, created_at DESC);

ALTER TABLE pc.model_calls ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.model_calls FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.model_calls
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));
CREATE TRIGGER org_write_guard BEFORE INSERT OR UPDATE ON pc.model_calls
    FOR EACH ROW EXECUTE FUNCTION pc.org_write_guard();

GRANT SELECT, INSERT ON pc.model_calls TO pc_app;
GRANT UPDATE (outcome, input_tokens, output_tokens, finished_at) ON pc.model_calls TO pc_app;
GRANT SELECT ON pc.model_calls TO pc_audit_ro;

CREATE TABLE pc.model_drafts (
    org_id     uuid        NOT NULL REFERENCES pc.orgs (id),
    version_id uuid        NOT NULL,
    call_id    uuid        NOT NULL,
    kind       text        NOT NULL CHECK (kind IN ('POLICY', 'AUTOMATION')),
    origin     text        NOT NULL DEFAULT 'model' CHECK (origin = 'model'),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, version_id),
    FOREIGN KEY (org_id, call_id) REFERENCES pc.model_calls (org_id, id)
);
CREATE INDEX model_drafts_call ON pc.model_drafts (org_id, call_id);

ALTER TABLE pc.model_drafts ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.model_drafts FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.model_drafts
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));
CREATE TRIGGER org_write_guard BEFORE INSERT OR UPDATE ON pc.model_drafts
    FOR EACH ROW EXECUTE FUNCTION pc.org_write_guard();

GRANT SELECT, INSERT ON pc.model_drafts TO pc_app;
GRANT SELECT ON pc.model_drafts TO pc_audit_ro;
-- +goose StatementBegin
DO $$ BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'pc_deleter') THEN
        GRANT SELECT, DELETE ON pc.model_calls, pc.model_drafts TO pc_deleter;
    END IF;
END $$;
-- +goose StatementEnd

-- +goose Down
DROP TABLE pc.model_drafts;
DROP TABLE pc.model_calls;
