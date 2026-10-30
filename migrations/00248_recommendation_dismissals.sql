-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
-- F343 recommendations (G0 M21 D302, D308): recommendations are computed on
-- read from a closed catalogue, so the only stored state is a person's
-- dismissal of a catalogue entry for the whole org. It stays until undone;
-- each change is audited and in the ledger. recommendation_id names a
-- catalogue entry, which lives in Go, so it has no foreign key.
-- +goose Up
CREATE TABLE pc.recommendation_dismissals (
    org_id            uuid        NOT NULL REFERENCES pc.orgs (id),
    recommendation_id text        NOT NULL CHECK (recommendation_id ~ '^[a-z][a-z_]*(\.[a-z0-9_]+){1,3}$'),
    dismissed_by      text        NOT NULL CHECK (char_length(dismissed_by) BETWEEN 1 AND 128),
    -- UNTRUSTED: the person's reason.
    reason            text        NOT NULL CHECK (char_length(btrim(reason)) BETWEEN 10 AND 1000),
    dismissed_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, recommendation_id)
);

ALTER TABLE pc.recommendation_dismissals ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.recommendation_dismissals FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.recommendation_dismissals
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));
CREATE TRIGGER org_write_guard BEFORE INSERT OR UPDATE ON pc.recommendation_dismissals
    FOR EACH ROW EXECUTE FUNCTION pc.org_write_guard();

GRANT SELECT, INSERT, DELETE ON pc.recommendation_dismissals TO pc_app;
GRANT SELECT ON pc.recommendation_dismissals TO pc_audit_ro;
-- +goose StatementBegin
DO $$ BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'pc_deleter') THEN
        GRANT SELECT, DELETE ON pc.recommendation_dismissals TO pc_deleter;
    END IF;
END $$;
-- +goose StatementEnd

-- +goose Down
DROP TABLE pc.recommendation_dismissals;
