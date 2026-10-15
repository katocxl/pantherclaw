-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Historical policy simulation (G0 M11.1 coordinator decision D15;
-- F187–F192, F287; HR-232, HR-237; Team edition). A person or service
-- account holding policy.simulate asks what a stored policy version would
-- have decided over the org's recorded decisions of a window (at most 30
-- days, inside retention). The worker replays each recorded evaluation,
-- newest first and at most max_evaluations of them, once with the recorded
-- policy and once with the version, and counts the outcome categories per
-- operation, per agent and per day. A simulation only reads the recorded
-- decisions: these two tables are the only rows it writes (HR-232).
--
-- policy_simulation_samples keeps at most 25 decisions per category and
-- operation, as ids, decisions, reason codes and limitation codes: never a
-- recorded input value (HR-237). Drill-down goes through ReplayDecision and
-- its own permission. One simulation per org is QUEUED or RUNNING at a time.
-- Times are the database's.

-- +goose Up
CREATE TABLE pc.policy_simulations (
    org_id            uuid        NOT NULL REFERENCES pc.orgs (id),
    id                uuid        NOT NULL,
    version_id        uuid        NOT NULL,
    -- The version's content digest when the simulation was asked for.
    content_digest    bytea       NOT NULL CHECK (octet_length(content_digest) = 32),
    window_start      timestamptz NOT NULL,
    window_end        timestamptz NOT NULL,
    max_evaluations   integer     NOT NULL DEFAULT 10000 CHECK (max_evaluations BETWEEN 1 AND 50000),
    state             text        NOT NULL DEFAULT 'QUEUED'
                                  CHECK (state IN ('QUEUED', 'RUNNING', 'DONE', 'FAILED', 'CANCELLED')),
    evaluated         integer     NOT NULL DEFAULT 0 CHECK (evaluated >= 0 AND evaluated <= max_evaluations),
    -- Counts by category, by operation and agent, and the approval burden.
    counts            jsonb       NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(counts) = 'object' AND octet_length(counts::text) <= 4096),
    by_workflow       jsonb       NOT NULL DEFAULT '{}'
                                  CHECK (jsonb_typeof(by_workflow) = 'object' AND octet_length(by_workflow::text) <= 1048576),
    burden            jsonb       NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(burden) = 'object' AND octet_length(burden::text) <= 262144),
    -- The worker's keyset position (newest first): the last decision
    -- receipt it counted.
    cursor_created_at timestamptz,
    cursor_txn        uuid,
    cursor_evaluation integer     CHECK (cursor_evaluation BETWEEN 1 AND 64),
    requested_by      text        NOT NULL CHECK (char_length(requested_by) BETWEEN 1 AND 128),
    created_at        timestamptz NOT NULL DEFAULT now(),
    started_at        timestamptz,
    finished_at       timestamptz,
    error             text        CHECK (char_length(error) <= 500),
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, version_id) REFERENCES pc.policy_versions (org_id, id),
    CONSTRAINT policy_simulations_window CHECK (window_end > window_start AND window_end - window_start <= interval '30 days'),
    CONSTRAINT policy_simulations_finished CHECK ((state IN ('QUEUED', 'RUNNING')) = (finished_at IS NULL)),
    CONSTRAINT policy_simulations_cursor CHECK ((cursor_created_at IS NULL) = (cursor_txn IS NULL)
                                                AND (cursor_txn IS NULL) = (cursor_evaluation IS NULL))
);
CREATE UNIQUE INDEX policy_simulations_one_active ON pc.policy_simulations (org_id) WHERE state IN ('QUEUED', 'RUNNING');
CREATE INDEX policy_simulations_org ON pc.policy_simulations (org_id, id DESC);

CREATE TABLE pc.policy_simulation_samples (
    org_id            uuid    NOT NULL,
    simulation_id     uuid    NOT NULL,
    category          text    NOT NULL CHECK (category IN ('UNCHANGED', 'NEWLY_DENIED', 'NEWLY_HELD', 'NEWLY_CONSTRAINED',
                                                           'NEWLY_ALLOWED', 'REASON_CHANGED', 'UNEVALUABLE')),
    transaction_id    uuid    NOT NULL,
    evaluation        integer NOT NULL CHECK (evaluation BETWEEN 1 AND 64),
    agent_id          uuid    NOT NULL,
    operation         text    NOT NULL CHECK (char_length(operation) BETWEEN 1 AND 200),
    original_decision text    NOT NULL DEFAULT '' CHECK (char_length(original_decision) <= 32),
    original_reason   text    NOT NULL DEFAULT '' CHECK (char_length(original_reason) <= 64),
    proposed_decision text    NOT NULL DEFAULT '' CHECK (char_length(proposed_decision) <= 32),
    proposed_reason   text    NOT NULL DEFAULT '' CHECK (char_length(proposed_reason) <= 64),
    -- Comma-separated limitation codes of an unevaluable decision.
    limitation        text    NOT NULL DEFAULT '' CHECK (limitation ~ '^[A-Z0-9_,]{0,200}$'),
    PRIMARY KEY (org_id, simulation_id, transaction_id, evaluation),
    FOREIGN KEY (org_id, simulation_id) REFERENCES pc.policy_simulations (org_id, id)
);
CREATE INDEX policy_simulation_samples_category ON pc.policy_simulation_samples (org_id, simulation_id, category, operation);

-- +goose StatementBegin
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['policy_simulations', 'policy_simulation_samples']
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

-- A simulation starts QUEUED, with nothing counted, over a window that has
-- ended.
-- +goose StatementBegin
CREATE FUNCTION pc.policy_simulation_insert() RETURNS trigger
    LANGUAGE plpgsql SET search_path = pc, pg_temp AS $$
BEGIN
    IF NEW.state <> 'QUEUED' OR NEW.evaluated <> 0 OR NEW.cursor_txn IS NOT NULL OR NEW.window_end > now() THEN
        RAISE EXCEPTION 'a simulation starts queued, over a past window' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER policy_simulations_insert BEFORE INSERT ON pc.policy_simulations
    FOR EACH ROW EXECUTE FUNCTION pc.policy_simulation_insert();

-- A simulation moves forward only: QUEUED to RUNNING or CANCELLED, RUNNING
-- to itself (progress), DONE, FAILED or CANCELLED. Its window, version and
-- bounds never change; the start and finish times are the database's, and
-- a finished simulation never changes again.
-- +goose StatementBegin
CREATE FUNCTION pc.policy_simulation_forward() RETURNS trigger
    LANGUAGE plpgsql SET search_path = pc, pg_temp AS $$
BEGIN
    IF NOT ((OLD.state = 'QUEUED' AND NEW.state IN ('RUNNING', 'CANCELLED'))
         OR (OLD.state = 'RUNNING' AND NEW.state IN ('RUNNING', 'DONE', 'FAILED', 'CANCELLED'))) THEN
        RAISE EXCEPTION 'simulation % cannot go from % to %', OLD.id, OLD.state, NEW.state USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.evaluated < OLD.evaluated THEN
        RAISE EXCEPTION 'simulation % counts forward only', OLD.id USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.state = 'QUEUED' AND NEW.state = 'RUNNING' THEN
        NEW.started_at := clock_timestamp();
    END IF;
    IF NEW.state IN ('DONE', 'FAILED', 'CANCELLED') THEN
        NEW.finished_at := clock_timestamp();
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER policy_simulations_forward BEFORE UPDATE ON pc.policy_simulations
    FOR EACH ROW EXECUTE FUNCTION pc.policy_simulation_forward();

-- Samples are added while the simulation runs, at most 25 per category and
-- operation (HR-237).
-- +goose StatementBegin
CREATE FUNCTION pc.policy_simulation_sample_insert() RETURNS trigger
    LANGUAGE plpgsql SET search_path = pc, pg_temp AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pc.policy_simulations s
                   WHERE s.org_id = NEW.org_id AND s.id = NEW.simulation_id AND s.state = 'RUNNING') THEN
        RAISE EXCEPTION 'simulation % is not running', NEW.simulation_id USING ERRCODE = 'check_violation';
    END IF;
    IF (SELECT count(*) FROM pc.policy_simulation_samples x
        WHERE x.org_id = NEW.org_id AND x.simulation_id = NEW.simulation_id
          AND x.category = NEW.category AND x.operation = NEW.operation) >= 25 THEN
        RAISE EXCEPTION 'simulation % has 25 samples of % for %', NEW.simulation_id, NEW.category, NEW.operation
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER policy_simulation_samples_insert BEFORE INSERT ON pc.policy_simulation_samples
    FOR EACH ROW EXECUTE FUNCTION pc.policy_simulation_sample_insert();

GRANT SELECT ON pc.policy_simulations, pc.policy_simulation_samples TO pc_app;
GRANT INSERT (org_id, id, version_id, content_digest, window_start, window_end, max_evaluations, requested_by)
    ON pc.policy_simulations TO pc_app;
GRANT UPDATE (state, evaluated, counts, by_workflow, burden, cursor_created_at, cursor_txn, cursor_evaluation, error)
    ON pc.policy_simulations TO pc_app;
GRANT INSERT ON pc.policy_simulation_samples TO pc_app;
GRANT SELECT ON pc.policy_simulations, pc.policy_simulation_samples TO pc_audit_ro;

-- +goose Down
DROP TABLE pc.policy_simulation_samples;
DROP TABLE pc.policy_simulations;
DROP FUNCTION pc.policy_simulation_sample_insert();
DROP FUNCTION pc.policy_simulation_forward();
DROP FUNCTION pc.policy_simulation_insert();
