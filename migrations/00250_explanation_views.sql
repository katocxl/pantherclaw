-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Explanation first views (G0 M21 D303, F774 M2). The first time a person
-- with access reads the evidence of a non-ALLOW decision is recorded once,
-- per transaction. It holds no viewer: the metric needs only the time.
-- first_viewed_at is the database's and pc_app may not set it.

-- +goose Up
CREATE TABLE pc.explanation_views (
    org_id          uuid        NOT NULL,
    transaction_id  uuid        NOT NULL,
    first_viewed_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, transaction_id),
    FOREIGN KEY (org_id, transaction_id) REFERENCES pc.transactions (org_id, id)
);

ALTER TABLE pc.explanation_views ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.explanation_views FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.explanation_views
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));

CREATE TRIGGER org_write_guard BEFORE INSERT OR UPDATE ON pc.explanation_views
    FOR EACH ROW EXECUTE FUNCTION pc.org_write_guard();

GRANT SELECT ON pc.explanation_views TO pc_app;
GRANT INSERT (org_id, transaction_id) ON pc.explanation_views TO pc_app;
GRANT SELECT ON pc.explanation_views TO pc_audit_ro;

-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'pc_deleter') THEN
        GRANT SELECT, DELETE ON pc.explanation_views TO pc_deleter;
    END IF;
END
$$;
-- +goose StatementEnd

-- +goose Down
DROP TABLE pc.explanation_views;
