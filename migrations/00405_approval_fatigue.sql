-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Approval fatigue flags and routing (G0 M36 D1063; HR-791). A job flags a
-- decider whose recent approvals look like rubber-stamping: 30 or more in
-- the last hour (APPROVAL_RATE), a median under 5 seconds from first
-- notice to approve over 10 or more in the last hour (FAST_APPROVALS), or
-- 50 or more in the last 24 hours with no decline (NO_DECLINES). A flag
-- clears 4 hours after it was raised; flags are insert-only. While flagged,
-- and unless the org turned fatigue routing off, the decider is routed and
-- noticed last. A flag never changes who is eligible and never decides.

-- +goose Up
CREATE TABLE pc.approval_fatigue_flags (
    org_id     uuid        NOT NULL REFERENCES pc.orgs (id),
    id         uuid        NOT NULL,
    user_id    uuid        NOT NULL,
    reason     text        NOT NULL CHECK (reason IN ('APPROVAL_RATE', 'FAST_APPROVALS', 'NO_DECLINES')),
    approvals  integer     NOT NULL CHECK (approvals >= 0),
    flagged_at timestamptz NOT NULL DEFAULT now(),
    clears_at  timestamptz NOT NULL,
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, user_id) REFERENCES pc.users (org_id, id),
    CONSTRAINT approval_fatigue_flags_clears CHECK (clears_at = flagged_at + interval '4 hours')
);
CREATE INDEX approval_fatigue_flags_user ON pc.approval_fatigue_flags (org_id, user_id, clears_at DESC);

-- The org's fatigue routing: route (the default, no row) or off.
CREATE TABLE pc.approval_fatigue_settings (
    org_id     uuid        NOT NULL REFERENCES pc.orgs (id),
    routing    text        NOT NULL CHECK (routing IN ('route', 'off')),
    updated_by text        NOT NULL CHECK (char_length(updated_by) BETWEEN 1 AND 100),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id)
);

-- +goose StatementBegin
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['approval_fatigue_flags', 'approval_fatigue_settings'] LOOP
        EXECUTE format('ALTER TABLE pc.%I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE pc.%I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format($p$CREATE POLICY tenant_isolation ON pc.%I
            USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
            WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))$p$, t);
        EXECUTE format('CREATE TRIGGER org_write_guard BEFORE INSERT OR UPDATE ON pc.%I
            FOR EACH ROW EXECUTE FUNCTION pc.org_write_guard()', t);
        EXECUTE format('GRANT SELECT ON pc.%I TO pc_audit_ro', t);
        IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'pc_deleter') THEN
            EXECUTE format('GRANT SELECT, DELETE ON pc.%I TO pc_deleter', t);
        END IF;
    END LOOP;
END
$$;
-- +goose StatementEnd

GRANT SELECT, INSERT ON pc.approval_fatigue_flags TO pc_app;
GRANT SELECT, INSERT, UPDATE ON pc.approval_fatigue_settings TO pc_app;

-- +goose Down
DROP TABLE pc.approval_fatigue_settings;
DROP TABLE pc.approval_fatigue_flags;
