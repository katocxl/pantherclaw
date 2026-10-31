-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Agent milestones (G0 M21 D303, F774 M1). The nightly outcome rollup
-- writes an agent's first enrolment and its first enforced, non-simulated
-- decision here, each once, from the durable rows they came from. Nothing
-- is backfilled: an agent enrolled before the org's collection started has
-- no row and is reported as not measured. pc_app may only insert and read,
-- so a milestone never moves.

-- +goose Up
CREATE TABLE pc.agent_milestones (
    org_id      uuid        NOT NULL REFERENCES pc.orgs (id),
    agent_id    uuid        NOT NULL,
    kind        text        NOT NULL CHECK (kind IN ('enrolled', 'first_enforced')),
    at          timestamptz NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, agent_id, kind),
    FOREIGN KEY (org_id, agent_id) REFERENCES pc.agents (org_id, id)
);

ALTER TABLE pc.agent_milestones ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.agent_milestones FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.agent_milestones
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));

CREATE TRIGGER org_write_guard BEFORE INSERT OR UPDATE ON pc.agent_milestones
    FOR EACH ROW EXECUTE FUNCTION pc.org_write_guard();

GRANT SELECT ON pc.agent_milestones TO pc_app;
GRANT INSERT (org_id, agent_id, kind, at) ON pc.agent_milestones TO pc_app;
GRANT SELECT ON pc.agent_milestones TO pc_audit_ro;

-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'pc_deleter') THEN
        GRANT SELECT, DELETE ON pc.agent_milestones TO pc_deleter;
    END IF;
END
$$;
-- +goose StatementEnd

-- +goose Down
DROP TABLE pc.agent_milestones;
