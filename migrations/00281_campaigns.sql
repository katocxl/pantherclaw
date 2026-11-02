-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
-- Attack campaigns against a range twin of the customer's agent (G0 M25 D305,
-- D306, D309, D313; HR-220, HR-466). A campaign names the image it tested by
-- digest and the one model host of its relay. Its steps are written once, by
-- the server, when it finishes: each outcome comes from the server's own
-- transactions, or is labelled as the edge's report. An attempt with nothing
-- behind it is NOT_EXERCISED, a gap. campaign_runs counts each run's model
-- traffic, never its content. Campaigns are not ranges: nothing here enters
-- an assurance pack.
-- +goose Up
CREATE TABLE pc.campaigns (
    org_id              uuid        NOT NULL REFERENCES pc.orgs (id),
    id                  uuid        NOT NULL,
    range_agent_id      uuid        NOT NULL,
    started_by          text        NOT NULL CHECK (char_length(started_by) BETWEEN 1 AND 100),
    runner_version      text        NOT NULL CHECK (char_length(runner_version) BETWEEN 1 AND 64),
    set_digest          text        NOT NULL CHECK (set_digest ~ '^[0-9a-f]{64}$'),
    scenario_ids        text[]      NOT NULL CHECK (cardinality(scenario_ids) BETWEEN 1 AND 10),
    image_digest        text        NOT NULL CHECK (image_digest ~ '^sha256:[0-9a-f]{64}$'),
    model_host          text        NOT NULL CHECK (model_host ~ '^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$'),
    relay_connection_id uuid        NOT NULL,
    scripted            boolean     NOT NULL,
    state               text        NOT NULL DEFAULT 'RUNNING' CHECK (state IN ('RUNNING', 'FINISHED', 'ABANDONED')),
    started_at          timestamptz NOT NULL DEFAULT clock_timestamp(),
    finished_at         timestamptz,
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, range_agent_id) REFERENCES pc.agents (org_id, id),
    FOREIGN KEY (org_id, relay_connection_id) REFERENCES pc.connections (org_id, id),
    CONSTRAINT campaigns_finished CHECK ((state = 'RUNNING') = (finished_at IS NULL))
);
CREATE INDEX campaigns_agent ON pc.campaigns (org_id, range_agent_id, id DESC);
CREATE INDEX campaigns_org ON pc.campaigns (org_id, id DESC);
CREATE INDEX campaigns_finished_at ON pc.campaigns (org_id, finished_at) WHERE state = 'FINISHED';
-- One open campaign per twin: the model route is open only while it is.
CREATE UNIQUE INDEX campaigns_one_open ON pc.campaigns (org_id, range_agent_id) WHERE state = 'RUNNING';
CREATE INDEX campaigns_open ON pc.campaigns (org_id, started_at) WHERE state = 'RUNNING';

CREATE TABLE pc.campaign_steps (
    org_id         uuid        NOT NULL REFERENCES pc.orgs (id),
    campaign_id    uuid        NOT NULL,
    scenario_id    text        NOT NULL CHECK (scenario_id ~ '^RT-14[0-9]$'),
    step_id        text        NOT NULL CHECK (step_id ~ '^[a-z0-9-]{1,40}$'),
    boundary       text        NOT NULL CHECK (boundary ~ '^HR-[0-9]{3}$'),
    expected       text        NOT NULL CHECK (expected IN ('HELD', 'DENIED', 'NOT_ROUTED')),
    outcome        text        NOT NULL CHECK (outcome IN ('HELD', 'DENIED', 'NOT_ROUTED_REPORTED', 'ALLOWED', 'NOT_EXERCISED')),
    basis          text        NOT NULL CHECK (basis IN ('SERVER_RECORD', 'EDGE_REPORT', 'NONE')),
    transaction_id uuid,
    reason         text        NOT NULL DEFAULT '' CHECK (char_length(reason) <= 64),
    route_locator  text        NOT NULL DEFAULT '' CHECK (char_length(route_locator) <= 512),
    recorded_at    timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (org_id, campaign_id, scenario_id, step_id),
    FOREIGN KEY (org_id, campaign_id) REFERENCES pc.campaigns (org_id, id),
    -- An outcome says what it rests on, and only these combinations are true.
    CONSTRAINT campaign_steps_basis CHECK (
        (basis = 'SERVER_RECORD' AND outcome IN ('HELD', 'DENIED', 'ALLOWED') AND transaction_id IS NOT NULL)
        OR (basis = 'EDGE_REPORT' AND outcome = 'NOT_ROUTED_REPORTED' AND transaction_id IS NULL AND route_locator <> '')
        OR (basis = 'NONE' AND outcome = 'NOT_EXERCISED' AND transaction_id IS NULL))
);

CREATE TABLE pc.campaign_runs (
    org_id           uuid        NOT NULL REFERENCES pc.orgs (id),
    campaign_id      uuid        NOT NULL,
    run_id           uuid        NOT NULL,
    scenario_id      text        CHECK (scenario_id ~ '^RT-14[0-9]$'),
    model_host       text        NOT NULL CHECK (char_length(model_host) BETWEEN 1 AND 253),
    requests         bigint      NOT NULL DEFAULT 0 CHECK (requests >= 0),
    bytes_to_model   bigint      NOT NULL DEFAULT 0 CHECK (bytes_to_model >= 0),
    bytes_from_model bigint      NOT NULL DEFAULT 0 CHECK (bytes_from_model >= 0),
    PRIMARY KEY (org_id, campaign_id, run_id),
    FOREIGN KEY (org_id, campaign_id) REFERENCES pc.campaigns (org_id, id),
    FOREIGN KEY (org_id, run_id) REFERENCES pc.runs (org_id, id)
);
CREATE INDEX campaign_runs_run ON pc.campaign_runs (org_id, run_id);

-- +goose StatementBegin
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['campaigns', 'campaign_steps', 'campaign_runs']
    LOOP
        EXECUTE format('ALTER TABLE pc.%I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE pc.%I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format($p$CREATE POLICY tenant_isolation ON pc.%I
            USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
            WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))$p$, t);
        EXECUTE format('CREATE TRIGGER org_write_guard BEFORE INSERT OR UPDATE ON pc.%I
            FOR EACH ROW EXECUTE FUNCTION pc.org_write_guard()', t);
    END LOOP;
END
$$;
-- +goose StatementEnd

-- A campaign runs only for a range agent (HR-220: the database holds the
-- mark too), and starts running.
-- +goose StatementBegin
CREATE FUNCTION pc.campaign_insert() RETURNS trigger
    LANGUAGE plpgsql SET search_path = pc, pg_temp AS $$
BEGIN
    IF NEW.state <> 'RUNNING' OR NOT EXISTS (
        SELECT 1 FROM pc.agents a WHERE a.org_id = NEW.org_id AND a.id = NEW.range_agent_id AND a.range_agent) THEN
        RAISE EXCEPTION 'a campaign starts running, for a range agent' USING ERRCODE = 'check_violation';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pc.connections c WHERE c.org_id = NEW.org_id AND c.id = NEW.relay_connection_id AND c.simulated) THEN
        RAISE EXCEPTION 'a campaign''s relay is a simulated connection' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER campaigns_insert BEFORE INSERT ON pc.campaigns
    FOR EACH ROW EXECUTE FUNCTION pc.campaign_insert();

-- A campaign changes once, forward, at the database's time.
-- +goose StatementBegin
CREATE FUNCTION pc.campaign_forward() RETURNS trigger
    LANGUAGE plpgsql SET search_path = pc, pg_temp AS $$
BEGIN
    IF OLD.state <> 'RUNNING' OR NEW.state NOT IN ('FINISHED', 'ABANDONED') THEN
        RAISE EXCEPTION 'campaign % changes once, from RUNNING', OLD.id USING ERRCODE = 'check_violation';
    END IF;
    NEW.finished_at := clock_timestamp();
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER campaigns_forward BEFORE UPDATE ON pc.campaigns
    FOR EACH ROW EXECUTE FUNCTION pc.campaign_forward();

-- pc_app inserts no time. Steps are evidence (HR-055): inserted, never
-- updated or deleted.
GRANT SELECT ON pc.campaigns, pc.campaign_steps, pc.campaign_runs TO pc_app;
GRANT INSERT (org_id, id, range_agent_id, started_by, runner_version, set_digest, scenario_ids, image_digest, model_host,
    relay_connection_id, scripted) ON pc.campaigns TO pc_app;
GRANT UPDATE (state) ON pc.campaigns TO pc_app;
GRANT INSERT (org_id, campaign_id, scenario_id, step_id, boundary, expected, outcome, basis, transaction_id, reason,
    route_locator) ON pc.campaign_steps TO pc_app;
GRANT INSERT (org_id, campaign_id, run_id, scenario_id, model_host, requests, bytes_to_model, bytes_from_model) ON pc.campaign_runs TO pc_app;
GRANT UPDATE (scenario_id, requests, bytes_to_model, bytes_from_model) ON pc.campaign_runs TO pc_app;
GRANT SELECT ON pc.campaigns, pc.campaign_steps, pc.campaign_runs TO pc_audit_ro;
-- +goose StatementBegin
DO $$ BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'pc_deleter') THEN
        GRANT SELECT, DELETE ON pc.campaigns, pc.campaign_steps, pc.campaign_runs TO pc_deleter;
    END IF;
END $$;
-- +goose StatementEnd

-- +goose Down
DROP TABLE pc.campaign_runs;
DROP TABLE pc.campaign_steps;
DROP TABLE pc.campaigns;
DROP FUNCTION pc.campaign_forward();
DROP FUNCTION pc.campaign_insert();
