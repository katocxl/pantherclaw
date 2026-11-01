-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- The daily posture rollup (G0 M24 D206; HR-581). posture_daily_runs says a
-- day was collected, even with nothing open; a day with no run is
-- NOT_COLLECTED, never zero. closed_count is NULL when the day before has no
-- run, because what closed cannot be known then.

-- +goose Up
CREATE TABLE pc.posture_daily_runs (
    org_id            uuid        NOT NULL REFERENCES pc.orgs (id),
    day               date        NOT NULL,
    -- Sources that had more findings than they may return: the day's counts
    -- are a lower bound.
    truncated_sources text[]      NOT NULL DEFAULT '{}' CHECK (cardinality(truncated_sources) <= 16),
    collected_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, day)
);

CREATE TABLE pc.posture_daily (
    org_id       uuid    NOT NULL REFERENCES pc.orgs (id),
    day          date    NOT NULL,
    kind         text    NOT NULL CHECK (kind ~ '^[a-zA-Z0-9_.]{1,64}$'),
    severity     text    NOT NULL CHECK (severity IN ('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    team_id      uuid,
    open_count   integer NOT NULL CHECK (open_count >= 0),
    closed_count integer CHECK (closed_count >= 0),
    UNIQUE NULLS NOT DISTINCT (org_id, day, kind, severity, team_id),
    FOREIGN KEY (org_id, day) REFERENCES pc.posture_daily_runs (org_id, day),
    FOREIGN KEY (org_id, team_id) REFERENCES pc.teams (org_id, id)
);

-- +goose StatementBegin
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['posture_daily_runs', 'posture_daily']
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

GRANT SELECT ON pc.posture_daily_runs, pc.posture_daily TO pc_app;
GRANT INSERT (org_id, day, truncated_sources) ON pc.posture_daily_runs TO pc_app;
GRANT INSERT (org_id, day, kind, severity, team_id, open_count, closed_count) ON pc.posture_daily TO pc_app;
GRANT SELECT ON pc.posture_daily_runs, pc.posture_daily TO pc_audit_ro;

-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'pc_deleter') THEN
        GRANT SELECT, DELETE ON pc.posture_daily_runs, pc.posture_daily TO pc_deleter;
    END IF;
END
$$;
-- +goose StatementEnd

-- +goose Down
DROP TABLE pc.posture_daily;
DROP TABLE pc.posture_daily_runs;
