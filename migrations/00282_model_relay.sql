-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
-- A model relay connection (G0 M25 D313): a simulated http connection the
-- gateway's model face serves, only for runs of a range agent during an open
-- campaign. It has no package and no routes, so no other face serves it. The
-- mark is set at creation and never changes: pc_app gets no UPDATE on it.
-- +goose Up
-- The CHECK is NOT VALID: every existing row has the new column false, which
-- satisfies it, and every write from now on is checked.
ALTER TABLE pc.connections ADD COLUMN model_relay boolean NOT NULL DEFAULT false;
ALTER TABLE pc.connections ADD CONSTRAINT connections_model_relay
    CHECK (NOT model_relay OR (simulated AND kind = 'http')) NOT VALID;

-- A campaign's relay carries the mark, in the database too.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION pc.campaign_insert() RETURNS trigger
    LANGUAGE plpgsql SET search_path = pc, pg_temp AS $$
BEGIN
    IF NEW.state <> 'RUNNING' OR NOT EXISTS (
        SELECT 1 FROM pc.agents a WHERE a.org_id = NEW.org_id AND a.id = NEW.range_agent_id AND a.range_agent) THEN
        RAISE EXCEPTION 'a campaign starts running, for a range agent' USING ERRCODE = 'check_violation';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pc.connections c WHERE c.org_id = NEW.org_id AND c.id = NEW.relay_connection_id AND c.simulated AND c.model_relay) THEN
        RAISE EXCEPTION 'a campaign''s relay is a simulated model relay connection' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION pc.campaign_insert() RETURNS trigger
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
ALTER TABLE pc.connections DROP CONSTRAINT connections_model_relay;
ALTER TABLE pc.connections DROP COLUMN model_relay;
