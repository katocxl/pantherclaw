-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Behaviour profiles (G0 M27 D502, D506; F930; HR-641, HR-643). A job reads
-- an org's own pc.transactions off the decision path, keeps one profile per
-- agent and origin, and raises what looks unusual as labelled inference. No
-- decision reads these tables.
--
-- REAL and SIMULATED never mix (HR-642, HR-222): origin is part of the key,
-- so a real agent's profile holds only real transactions. A profile says what
-- it rests on; an agent with no row is not collected, never zero (HR-537).
-- Profiles hold operation names, connection ids, classes, counts and amounts,
-- never arguments or payloads (HR-056). Each row is overwritten by the next
-- rollup: a profile is a working summary, not evidence.

-- +goose Up
CREATE TABLE pc.behavior_cursors (
    org_id     uuid        NOT NULL REFERENCES pc.orgs (id),
    origin     text        NOT NULL CHECK (origin IN ('REAL', 'SIMULATED')),
    -- Transactions before this time have been compared.
    scanned_to timestamptz NOT NULL,
    started_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, origin)
);

CREATE TABLE pc.behavior_profiles (
    org_id       uuid        NOT NULL,
    agent_id     uuid        NOT NULL,
    origin       text        NOT NULL CHECK (origin IN ('REAL', 'SIMULATED')),
    state        text        NOT NULL CHECK (state IN ('COLLECTED', 'INSUFFICIENT_HISTORY')),
    window_start timestamptz NOT NULL,
    window_end   timestamptz NOT NULL,
    actions      bigint      NOT NULL CHECK (actions >= 0),
    active_days  integer     NOT NULL CHECK (active_days >= 0),
    -- The method's version, and whether the org's history outran its cap.
    method       text        NOT NULL CHECK (char_length(method) BETWEEN 1 AND 32),
    truncated    boolean     NOT NULL DEFAULT false,
    -- Bounded by the method (domain.MaxTools and the like). Lists of plain
    -- values, never free text from an agent.
    body         jsonb       NOT NULL CHECK (octet_length(body::text) <= 262144),
    computed_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, agent_id, origin),
    FOREIGN KEY (org_id, agent_id) REFERENCES pc.agents (org_id, id),
    CHECK (window_end > window_start)
);

-- Signals from behaviour analytics (reflexdomain SourceBehavior, D502).
-- squawk: pc.alerts and pc.cases are checked row by row; as 00140.
ALTER TABLE pc.alerts
    DROP CONSTRAINT alerts_source_check,
    ADD CONSTRAINT alerts_source_check
        CHECK (source IN ('detection', 'response', 'siem', 'signals', 'coverage', 'system', 'automation', 'behavior')) NOT VALID;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.alerts VALIDATE CONSTRAINT alerts_source_check;
ALTER TABLE pc.cases
    DROP CONSTRAINT cases_source_check,
    ADD CONSTRAINT cases_source_check
        CHECK (source IN ('detection', 'response', 'siem', 'signals', 'coverage', 'system', 'manual', 'automation', 'behavior')) NOT VALID;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.cases VALIDATE CONSTRAINT cases_source_check;

-- The job's index on pc.transactions is built concurrently in 00303.

-- +goose StatementBegin
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['behavior_cursors', 'behavior_profiles']
    LOOP
        EXECUTE format('ALTER TABLE pc.%I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE pc.%I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format($p$CREATE POLICY tenant_isolation ON pc.%I
            USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
            WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))$p$, t);
        EXECUTE format('CREATE TRIGGER org_write_guard BEFORE INSERT OR UPDATE ON pc.%I FOR EACH ROW EXECUTE FUNCTION pc.org_write_guard()', t);
    END LOOP;
END
$$;
-- +goose StatementEnd

GRANT SELECT ON pc.behavior_cursors, pc.behavior_profiles TO pc_app;
GRANT INSERT (org_id, origin, scanned_to) ON pc.behavior_cursors TO pc_app;
GRANT UPDATE (scanned_to) ON pc.behavior_cursors TO pc_app;
GRANT INSERT (org_id, agent_id, origin, state, window_start, window_end, actions, active_days, method, truncated, body, computed_at)
    ON pc.behavior_profiles TO pc_app;
GRANT UPDATE (state, window_start, window_end, actions, active_days, method, truncated, body, computed_at)
    ON pc.behavior_profiles TO pc_app;
GRANT SELECT ON pc.behavior_cursors, pc.behavior_profiles TO pc_audit_ro;

-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'pc_deleter') THEN
        GRANT SELECT, DELETE ON pc.behavior_cursors, pc.behavior_profiles TO pc_deleter;
    END IF;
END
$$;
-- +goose StatementEnd

-- +goose Down
-- Behaviour alerts and cases are kept: evidence, events and suppression
-- breaks (00120) and case entries refer to them, and they are part of the
-- record. The older checks come back NOT VALID, so they bind new rows only.
ALTER TABLE pc.cases
    DROP CONSTRAINT cases_source_check,
    ADD CONSTRAINT cases_source_check
        CHECK (source IN ('detection', 'response', 'siem', 'signals', 'coverage', 'system', 'manual', 'automation')) NOT VALID;
ALTER TABLE pc.alerts
    DROP CONSTRAINT alerts_source_check,
    ADD CONSTRAINT alerts_source_check
        CHECK (source IN ('detection', 'response', 'siem', 'signals', 'coverage', 'system', 'automation')) NOT VALID;
DROP TABLE pc.behavior_profiles;
DROP TABLE pc.behavior_cursors;
