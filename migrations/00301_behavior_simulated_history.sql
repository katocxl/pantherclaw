-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Labelled simulated history (G0 M27 D502; F931; HR-642, HR-222, F630). A
-- generator gives a range agent a history without any real work. It has its
-- own table, so a query over pc.transactions can never read it as real, and
-- only a range agent can have one: the trigger below refuses any other, and
-- pc.agents.range_agent can't be changed after insert (00096).

-- +goose Up
CREATE TABLE pc.behavior_simulated_actions (
    org_id            uuid          NOT NULL,
    id                uuid          NOT NULL,
    agent_id          uuid          NOT NULL,
    run_ref           uuid          NOT NULL,
    operation         text          NOT NULL CHECK (char_length(operation) BETWEEN 1 AND 256),
    connection_id     uuid,
    destination_class text          NOT NULL DEFAULT '' CHECK (char_length(destination_class) <= 64),
    amount            numeric(26,8) CHECK (amount >= 0),
    currency          text          CHECK (currency ~ '^[A-Z]{3}$'),
    occurred_at       timestamptz   NOT NULL,
    generator         text          NOT NULL CHECK (char_length(generator) BETWEEN 1 AND 64),
    seed              bigint        NOT NULL,
    -- Always true: the label travels with every row (F630).
    simulated         boolean       NOT NULL DEFAULT true CHECK (simulated),
    created_at        timestamptz   NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, agent_id) REFERENCES pc.agents (org_id, id),
    CHECK ((amount IS NULL) = (currency IS NULL))
);
CREATE INDEX behavior_simulated_actions_time ON pc.behavior_simulated_actions (org_id, occurred_at);

ALTER TABLE pc.behavior_simulated_actions ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.behavior_simulated_actions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.behavior_simulated_actions
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));
CREATE TRIGGER org_write_guard BEFORE INSERT OR UPDATE ON pc.behavior_simulated_actions
    FOR EACH ROW EXECUTE FUNCTION pc.org_write_guard();

-- +goose StatementBegin
CREATE FUNCTION pc.behavior_simulated_range_agent() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NOT EXISTS (SELECT FROM pc.agents a WHERE a.org_id = NEW.org_id AND a.id = NEW.agent_id AND a.range_agent) THEN
        RAISE EXCEPTION 'simulated history is only for a range agent' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER range_agent_only BEFORE INSERT ON pc.behavior_simulated_actions
    FOR EACH ROW EXECUTE FUNCTION pc.behavior_simulated_range_agent();

GRANT SELECT ON pc.behavior_simulated_actions TO pc_app;
GRANT INSERT (org_id, id, agent_id, run_ref, operation, connection_id, destination_class, amount, currency, occurred_at, generator, seed)
    ON pc.behavior_simulated_actions TO pc_app;
GRANT SELECT ON pc.behavior_simulated_actions TO pc_audit_ro;

-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'pc_deleter') THEN
        GRANT SELECT, DELETE ON pc.behavior_simulated_actions TO pc_deleter;
    END IF;
END
$$;
-- +goose StatementEnd

-- +goose Down
DROP TABLE pc.behavior_simulated_actions;
DROP FUNCTION pc.behavior_simulated_range_agent();
