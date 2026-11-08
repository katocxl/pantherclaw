-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Approval deputies (G0 M36 D1064; FQ36-3; HR-790). While a person is
-- away, a hold routed to them is also routed to and noticed by their
-- deputy, only when the deputy is eligible for that request on their own.
-- A deputy window never makes anyone eligible and never approves anything.
-- A window is at most 30 days; a person has at most one live window at a
-- time (the service refuses an overlap under a per-person lock). A row is
-- only ever cancelled.

-- +goose Up
CREATE TABLE pc.approval_deputies (
    org_id       uuid        NOT NULL REFERENCES pc.orgs (id),
    id           uuid        NOT NULL,
    person_id    uuid        NOT NULL,
    deputy_id    uuid        NOT NULL,
    starts_at    timestamptz NOT NULL,
    ends_at      timestamptz NOT NULL,
    created_by   text        NOT NULL CHECK (char_length(created_by) BETWEEN 1 AND 100),
    state        text        NOT NULL DEFAULT 'ACTIVE' CHECK (state IN ('ACTIVE', 'CANCELLED')),
    cancelled_by text        CHECK (char_length(cancelled_by) BETWEEN 1 AND 100),
    cancelled_at timestamptz,
    created_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, person_id) REFERENCES pc.users (org_id, id),
    FOREIGN KEY (org_id, deputy_id) REFERENCES pc.users (org_id, id),
    CONSTRAINT approval_deputies_not_self CHECK (person_id <> deputy_id),
    CONSTRAINT approval_deputies_window CHECK (ends_at > starts_at AND ends_at <= starts_at + interval '30 days'),
    CONSTRAINT approval_deputies_cancelled CHECK ((state = 'CANCELLED') = (cancelled_at IS NOT NULL)
                                                  AND (cancelled_at IS NULL) = (cancelled_by IS NULL))
);
CREATE INDEX approval_deputies_live ON pc.approval_deputies (org_id, person_id, ends_at) WHERE state = 'ACTIVE';
CREATE INDEX approval_deputies_deputy ON pc.approval_deputies (org_id, deputy_id, ends_at) WHERE state = 'ACTIVE';

ALTER TABLE pc.approval_deputies ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.approval_deputies FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.approval_deputies
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));
CREATE TRIGGER org_write_guard BEFORE INSERT OR UPDATE ON pc.approval_deputies
    FOR EACH ROW EXECUTE FUNCTION pc.org_write_guard();
GRANT SELECT, INSERT ON pc.approval_deputies TO pc_app;
-- Only cancelling changes a row.
GRANT UPDATE (state, cancelled_by, cancelled_at) ON pc.approval_deputies TO pc_app;
GRANT SELECT ON pc.approval_deputies TO pc_audit_ro;
-- +goose StatementBegin
DO $$ BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'pc_deleter') THEN
        GRANT SELECT, DELETE ON pc.approval_deputies TO pc_deleter;
    END IF;
END $$;
-- +goose StatementEnd

-- +goose Down
DROP TABLE pc.approval_deputies;
