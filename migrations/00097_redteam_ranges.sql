-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Adversarial ranges (G0 M12 W5; PN-009; HR-224; T-091; coordinator
-- decision D12, 2026-10-14). A person or service account holding
-- redteam.run starts a range for a range agent (00096) and records each
-- scenario's result. redteam_runs is the range: the scenarios it declared,
-- their set digest, and the policy and package versions the agent ran under
-- when it started. redteam_results are its results, one per scenario,
-- insert-only: the server wrote each verdict from its own records (a step
-- that names a simulated transaction or a signed probe report is observed
-- by the server), so a result is evidence and never changes (HR-055).
-- A range changes once, forward: RUNNING to FINISHED, or to ABANDONED after
-- 24 hours by the janitor sweep. Times are the database's, never the
-- caller's: a transaction counts for a range only if it was created after
-- the range's started_at.

-- +goose Up
CREATE TABLE pc.redteam_runs (
    org_id              uuid        NOT NULL REFERENCES pc.orgs (id),
    id                  uuid        NOT NULL,
    range_agent_id      uuid        NOT NULL,
    -- The person or service account that started the range.
    started_by          text        NOT NULL CHECK (char_length(started_by) BETWEEN 1 AND 100),
    runner_version      text        NOT NULL CHECK (char_length(runner_version) BETWEEN 1 AND 64),
    scenario_set_digest text        NOT NULL CHECK (scenario_set_digest ~ '^[0-9a-f]{64}$'),
    scenarios           jsonb       NOT NULL CHECK (jsonb_typeof(scenarios) = 'array' AND jsonb_array_length(scenarios) BETWEEN 1 AND 200),
    policy_versions     jsonb       NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(policy_versions) = 'array'),
    package_versions    jsonb       NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(package_versions) = 'array'),
    baseline_range_id   uuid,
    state               text        NOT NULL DEFAULT 'RUNNING' CHECK (state IN ('RUNNING', 'FINISHED', 'ABANDONED')),
    started_at          timestamptz NOT NULL DEFAULT clock_timestamp(),
    finished_at         timestamptz,
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, range_agent_id) REFERENCES pc.agents (org_id, id),
    FOREIGN KEY (org_id, baseline_range_id) REFERENCES pc.redteam_runs (org_id, id),
    CONSTRAINT redteam_runs_finished CHECK ((state = 'RUNNING') = (finished_at IS NULL)),
    CONSTRAINT redteam_runs_baseline CHECK (baseline_range_id IS NULL OR baseline_range_id <> id)
);
CREATE INDEX redteam_runs_agent ON pc.redteam_runs (org_id, range_agent_id, id DESC);
CREATE INDEX redteam_runs_org ON pc.redteam_runs (org_id, id DESC);
CREATE INDEX redteam_runs_open ON pc.redteam_runs (org_id, started_at) WHERE state = 'RUNNING';

CREATE TABLE pc.redteam_results (
    org_id           uuid        NOT NULL REFERENCES pc.orgs (id),
    range_id         uuid        NOT NULL,
    scenario_id      text        NOT NULL CHECK (scenario_id ~ '^RT-[0-9]{3}$'),
    scenario_digest  text        NOT NULL CHECK (scenario_digest ~ '^[0-9a-f]{64}$'),
    title            text        NOT NULL DEFAULT '' CHECK (char_length(title) <= 200),
    suite            text        NOT NULL CHECK (suite IN ('coding-agent', 'platform')),
    category         text        NOT NULL CHECK (category IN ('functional', 'boundary', 'recovery', 'explanation')),
    tier             text        NOT NULL CHECK (tier IN ('community', 'business')),
    verdict          text        NOT NULL CHECK (verdict IN ('PASS', 'FAIL', 'ERROR', 'SKIPPED', 'MISSING')),
    -- The runner's verdict when the server's differs.
    claimed_verdict  text        CHECK (claimed_verdict IN ('PASS', 'FAIL', 'ERROR', 'SKIPPED')),
    steps            jsonb       NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(steps) = 'array' AND jsonb_array_length(steps) <= 40),
    -- Who observed the steps: SERVER, CLIENT, MIXED, or NONE (no steps).
    observed_by      text        NOT NULL CHECK (observed_by IN ('SERVER', 'CLIENT', 'MIXED', 'NONE')),
    mismatches       integer     NOT NULL DEFAULT 0 CHECK (mismatches >= 0),
    recorded_at      timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (org_id, range_id, scenario_id),
    FOREIGN KEY (org_id, range_id) REFERENCES pc.redteam_runs (org_id, id),
    CONSTRAINT redteam_results_missing CHECK (verdict <> 'MISSING' OR (observed_by = 'NONE' AND jsonb_array_length(steps) = 0))
);

-- +goose StatementBegin
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['redteam_runs', 'redteam_results']
    LOOP
        EXECUTE format('ALTER TABLE pc.%I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE pc.%I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format($p$CREATE POLICY tenant_isolation ON pc.%I
            USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
            WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))$p$, t);
    END LOOP;
END
$$;
-- +goose StatementEnd

-- A range is for a range agent only (HR-220's mark is held by the database
-- too), and a baseline is a finished range.
-- +goose StatementBegin
CREATE FUNCTION pc.redteam_run_insert() RETURNS trigger
    LANGUAGE plpgsql SET search_path = pc, pg_temp AS $$
BEGIN
    IF NEW.state <> 'RUNNING' OR NOT EXISTS (
        SELECT 1 FROM pc.agents a WHERE a.org_id = NEW.org_id AND a.id = NEW.range_agent_id AND a.range_agent) THEN
        RAISE EXCEPTION 'a range starts running, for a range agent' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.baseline_range_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM pc.redteam_runs b WHERE b.org_id = NEW.org_id AND b.id = NEW.baseline_range_id AND b.state = 'FINISHED') THEN
        RAISE EXCEPTION 'a baseline is a finished range' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER redteam_runs_insert BEFORE INSERT ON pc.redteam_runs
    FOR EACH ROW EXECUTE FUNCTION pc.redteam_run_insert();

-- A range changes once, forward, at the database's time.
-- +goose StatementBegin
CREATE FUNCTION pc.redteam_run_forward() RETURNS trigger
    LANGUAGE plpgsql SET search_path = pc, pg_temp AS $$
BEGIN
    IF OLD.state <> 'RUNNING' OR NEW.state NOT IN ('FINISHED', 'ABANDONED') THEN
        RAISE EXCEPTION 'range % changes once, from RUNNING', OLD.id USING ERRCODE = 'check_violation';
    END IF;
    NEW.finished_at := clock_timestamp();
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER redteam_runs_forward BEFORE UPDATE ON pc.redteam_runs
    FOR EACH ROW EXECUTE FUNCTION pc.redteam_run_forward();

-- A result is recorded while its range runs; a finished range gets only
-- the MISSING results of scenarios never recorded. The scenario is one the
-- range declared, with the digest it declared.
-- +goose StatementBegin
CREATE FUNCTION pc.redteam_result_insert() RETURNS trigger
    LANGUAGE plpgsql SET search_path = pc, pg_temp AS $$
DECLARE
    r pc.redteam_runs;
BEGIN
    SELECT * INTO r FROM pc.redteam_runs WHERE org_id = NEW.org_id AND id = NEW.range_id;
    IF NOT (r.state = 'RUNNING' AND NEW.verdict <> 'MISSING') AND NOT (r.state = 'FINISHED' AND NEW.verdict = 'MISSING') THEN
        RAISE EXCEPTION 'range % takes no such result', NEW.range_id USING ERRCODE = 'check_violation';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM jsonb_array_elements(r.scenarios) s
        WHERE s->>'id' = NEW.scenario_id AND s->>'digest' = NEW.scenario_digest) THEN
        RAISE EXCEPTION 'scenario % was not declared by range %', NEW.scenario_id, NEW.range_id USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER redteam_results_insert BEFORE INSERT ON pc.redteam_results
    FOR EACH ROW EXECUTE FUNCTION pc.redteam_result_insert();

-- pc_app inserts no time: started_at and recorded_at are the database's.
-- Results are evidence (HR-055): inserted, never updated or deleted.
GRANT SELECT ON pc.redteam_runs, pc.redteam_results TO pc_app;
GRANT INSERT (org_id, id, range_agent_id, started_by, runner_version, scenario_set_digest, scenarios, policy_versions,
    package_versions, baseline_range_id) ON pc.redteam_runs TO pc_app;
GRANT UPDATE (state) ON pc.redteam_runs TO pc_app;
GRANT INSERT (org_id, range_id, scenario_id, scenario_digest, title, suite, category, tier, verdict, claimed_verdict, steps,
    observed_by, mismatches) ON pc.redteam_results TO pc_app;
GRANT SELECT ON pc.redteam_runs, pc.redteam_results TO pc_audit_ro;

-- +goose Down
DROP TABLE pc.redteam_results;
DROP TABLE pc.redteam_runs;
DROP FUNCTION pc.redteam_result_insert();
DROP FUNCTION pc.redteam_run_forward();
DROP FUNCTION pc.redteam_run_insert();
