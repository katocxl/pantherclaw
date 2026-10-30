-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Branching automations, run state (G0 M21 D301, D307; HR-530, HR-533).
--
-- A v2 execution points at a node: current_node, and path, every node it
-- entered in order. A v1 execution keeps current_step and never sets them.
-- An attempt names its node: node_id is its step id, in v1 and v2 alike, and
-- visit is how many times the node was entered, 1 while graphs are acyclic.
--
-- The backfill writes node_id on terminal attempts, which never change, so
-- the guard allows exactly that one change here. 00247 takes it away. The
-- guard also fills node_id on insert, so a server still on the previous
-- release keeps working during a rollout.
--
-- org_write_guard refuses every write without its organisation in context, so
-- the backfill runs organisation by organisation. A DELETED organisation
-- permits no write: its attempts keep a NULL node_id, nothing reads them, and
-- the NOT VALID check holds every new or changed row instead of NOT NULL.
--
-- The first ALTER takes ACCESS EXCLUSIVE and holds it to commit: every engine
-- round on attempts waits through the backfill and the unique index build,
-- and both grow with the whole table.

-- +goose Up
ALTER TABLE pc.automation_executions
    ADD COLUMN current_node text CHECK (current_node ~ '^[a-z][a-z0-9_-]{0,62}$'),
    ADD COLUMN path text[] NOT NULL DEFAULT '{}' CHECK (cardinality(path) <= 40 AND array_position(path, NULL) IS NULL);

ALTER TABLE pc.automation_step_attempts
    ADD COLUMN node_id text CHECK (node_id ~ '^[a-z][a-z0-9_-]{0,62}$'),
    ADD COLUMN visit smallint NOT NULL DEFAULT 1 CHECK (visit BETWEEN 1 AND 40);

-- pc_app moves the pointer; it never updates an attempt's node.
GRANT UPDATE (current_node, path) ON pc.automation_executions TO pc_app;

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION pc.automation_step_attempt_guard() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pc, pg_temp
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        NEW.started_at := now();
        NEW.node_id := COALESCE(NEW.node_id, NEW.step_id);
        IF NEW.state NOT IN ('RUNNING', 'WAITING') THEN
            NEW.ended_at := NEW.started_at;
        END IF;
        RETURN NEW;
    END IF;
    IF OLD.node_id IS NULL AND NEW.node_id = OLD.step_id
            AND to_jsonb(NEW) - 'node_id' = to_jsonb(OLD) - 'node_id' THEN
        RETURN NEW;
    END IF;
    IF OLD.state NOT IN ('RUNNING', 'WAITING') THEN
        RAISE EXCEPTION 'a finished step attempt never changes' USING ERRCODE = 'check_violation';
    END IF;
    IF (NEW.id, NEW.execution_id, NEW.step_index, NEW.step_id, NEW.attempt, NEW.kind, NEW.compensation, NEW.started_at)
            IS DISTINCT FROM (OLD.id, OLD.execution_id, OLD.step_index, OLD.step_id, OLD.attempt, OLD.kind,
                              OLD.compensation, OLD.started_at) THEN
        RAISE EXCEPTION 'a step attempt''s identity never changes' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.state NOT IN ('RUNNING', 'WAITING') THEN
        NEW.ended_at := now();
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd

-- RLS holds for the owner too, so it is lifted to list the organisations,
-- inside this migration's transaction; no other session ever sees it lifted.
ALTER TABLE pc.automation_step_attempts NO FORCE ROW LEVEL SECURITY;
-- +goose StatementBegin
DO $$
DECLARE
    org uuid;
    org_state text;
BEGIN
    FOR org IN SELECT DISTINCT org_id FROM pc.automation_step_attempts WHERE node_id IS NULL LOOP
        PERFORM set_config('app.org_id', org::text, true);
        SELECT state INTO org_state FROM pc.orgs WHERE id = org;
        IF org_state <> 'DELETED' THEN
            UPDATE pc.automation_step_attempts SET node_id = step_id WHERE org_id = org AND node_id IS NULL;
        END IF;
    END LOOP;
    PERFORM set_config('app.org_id', '', true);
END
$$;
-- +goose StatementEnd
ALTER TABLE pc.automation_step_attempts FORCE ROW LEVEL SECURITY;

ALTER TABLE pc.automation_step_attempts ADD CONSTRAINT automation_step_attempts_node_set CHECK (node_id IS NOT NULL) NOT VALID;
-- squawk-ignore constraint-missing-not-valid, disallowed-unique-constraint
ALTER TABLE pc.automation_step_attempts ADD CONSTRAINT automation_step_attempts_node UNIQUE (org_id, execution_id, compensation, node_id, attempt);

-- +goose Down
ALTER TABLE pc.automation_step_attempts DROP CONSTRAINT automation_step_attempts_node;
ALTER TABLE pc.automation_step_attempts DROP CONSTRAINT automation_step_attempts_node_set;

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION pc.automation_step_attempt_guard() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pc, pg_temp
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        NEW.started_at := now();
        IF NEW.state NOT IN ('RUNNING', 'WAITING') THEN
            NEW.ended_at := NEW.started_at;
        END IF;
        RETURN NEW;
    END IF;
    IF OLD.state NOT IN ('RUNNING', 'WAITING') THEN
        RAISE EXCEPTION 'a finished step attempt never changes' USING ERRCODE = 'check_violation';
    END IF;
    IF (NEW.id, NEW.execution_id, NEW.step_index, NEW.step_id, NEW.attempt, NEW.kind, NEW.compensation, NEW.started_at)
            IS DISTINCT FROM (OLD.id, OLD.execution_id, OLD.step_index, OLD.step_id, OLD.attempt, OLD.kind,
                              OLD.compensation, OLD.started_at) THEN
        RAISE EXCEPTION 'a step attempt''s identity never changes' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.state NOT IN ('RUNNING', 'WAITING') THEN
        NEW.ended_at := now();
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd

ALTER TABLE pc.automation_step_attempts DROP COLUMN node_id, DROP COLUMN visit;
ALTER TABLE pc.automation_executions DROP COLUMN current_node, DROP COLUMN path;
