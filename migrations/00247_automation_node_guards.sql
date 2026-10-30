-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Branching automations, final guards (G0 M21 D301, D307; HR-530, HR-533).
--
-- The backfill of 00246 is done: no change to node_id or visit is allowed any
-- more, on any attempt. An execution's path only grows, and its current node
-- moves only by entering a node, so a running execution is never re-pointed.

-- +goose Up
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
    IF OLD.state NOT IN ('RUNNING', 'WAITING') THEN
        RAISE EXCEPTION 'a finished step attempt never changes' USING ERRCODE = 'check_violation';
    END IF;
    IF (NEW.id, NEW.execution_id, NEW.step_index, NEW.step_id, NEW.node_id, NEW.visit, NEW.attempt, NEW.kind,
            NEW.compensation, NEW.started_at)
            IS DISTINCT FROM (OLD.id, OLD.execution_id, OLD.step_index, OLD.step_id, OLD.node_id, OLD.visit, OLD.attempt,
                              OLD.kind, OLD.compensation, OLD.started_at) THEN
        RAISE EXCEPTION 'a step attempt''s identity never changes' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.state NOT IN ('RUNNING', 'WAITING') THEN
        NEW.ended_at := now();
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION pc.automation_execution_guard() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pc, pg_temp
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.state IS DISTINCT FROM 'PENDING' AND NEW.mode = 'LIVE' THEN
            RAISE EXCEPTION 'a live execution is inserted PENDING' USING ERRCODE = 'check_violation';
        END IF;
        NEW.created_at := now();
        NEW.updated_at := NEW.created_at;
        RETURN NEW;
    END IF;
    IF OLD.state IN ('SUCCEEDED', 'PARTIALLY_COMPLETED', 'FAILED', 'CANCELLED') THEN
        RAISE EXCEPTION 'a finished execution never changes' USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.state = 'NEEDS_RECONCILIATION' AND NEW.state IN ('PENDING', 'RUNNING', 'WAITING') THEN
        RAISE EXCEPTION 'an execution needing reconciliation only resolves to a final state'
            USING ERRCODE = 'check_violation';
    END IF;
    IF (NEW.id, NEW.automation_id, NEW.version_id, NEW.trigger_id, NEW.mode, NEW.ceiling_id, NEW.service_account_id,
            NEW.principal_user_id, NEW.principal_sa_id, NEW.trigger_kind, NEW.params, NEW.subjects, NEW.evidence,
            NEW.occurred_at, NEW.root_trigger_id, NEW.ancestry, NEW.depth, NEW.created_at, NEW.deadline_at)
            IS DISTINCT FROM (OLD.id, OLD.automation_id, OLD.version_id, OLD.trigger_id, OLD.mode, OLD.ceiling_id,
                              OLD.service_account_id, OLD.principal_user_id, OLD.principal_sa_id, OLD.trigger_kind,
                              OLD.params, OLD.subjects, OLD.evidence, OLD.occurred_at, OLD.root_trigger_id,
                              OLD.ancestry, OLD.depth, OLD.created_at, OLD.deadline_at) THEN
        RAISE EXCEPTION 'an execution''s identity never changes' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.path[1:cardinality(OLD.path)] IS DISTINCT FROM OLD.path
            OR NEW.current_node IS DISTINCT FROM NEW.path[cardinality(NEW.path)] THEN
        RAISE EXCEPTION 'an execution''s path only grows, and its current node is the last entered'
            USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.cancel_requested_at IS NOT NULL AND (NEW.cancel_requested_at, NEW.cancel_reason, NEW.cancel_requested_by)
            IS DISTINCT FROM (OLD.cancel_requested_at, OLD.cancel_reason, OLD.cancel_requested_by) THEN
        RAISE EXCEPTION 'a cancellation is requested once' USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.started_at IS NOT NULL AND NEW.started_at IS DISTINCT FROM OLD.started_at THEN
        RAISE EXCEPTION 'an execution starts once' USING ERRCODE = 'check_violation';
    END IF;
    NEW.updated_at := now();
    IF NEW.state NOT IN ('PENDING', 'RUNNING', 'WAITING') AND OLD.state IN ('PENDING', 'RUNNING', 'WAITING') THEN
        NEW.ended_at := now();
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION pc.automation_execution_guard() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pc, pg_temp
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.state IS DISTINCT FROM 'PENDING' AND NEW.mode = 'LIVE' THEN
            RAISE EXCEPTION 'a live execution is inserted PENDING' USING ERRCODE = 'check_violation';
        END IF;
        NEW.created_at := now();
        NEW.updated_at := NEW.created_at;
        RETURN NEW;
    END IF;
    IF OLD.state IN ('SUCCEEDED', 'PARTIALLY_COMPLETED', 'FAILED', 'CANCELLED') THEN
        RAISE EXCEPTION 'a finished execution never changes' USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.state = 'NEEDS_RECONCILIATION' AND NEW.state IN ('PENDING', 'RUNNING', 'WAITING') THEN
        RAISE EXCEPTION 'an execution needing reconciliation only resolves to a final state'
            USING ERRCODE = 'check_violation';
    END IF;
    IF (NEW.id, NEW.automation_id, NEW.version_id, NEW.trigger_id, NEW.mode, NEW.ceiling_id, NEW.service_account_id,
            NEW.principal_user_id, NEW.principal_sa_id, NEW.trigger_kind, NEW.params, NEW.subjects, NEW.evidence,
            NEW.occurred_at, NEW.root_trigger_id, NEW.ancestry, NEW.depth, NEW.created_at, NEW.deadline_at)
            IS DISTINCT FROM (OLD.id, OLD.automation_id, OLD.version_id, OLD.trigger_id, OLD.mode, OLD.ceiling_id,
                              OLD.service_account_id, OLD.principal_user_id, OLD.principal_sa_id, OLD.trigger_kind,
                              OLD.params, OLD.subjects, OLD.evidence, OLD.occurred_at, OLD.root_trigger_id,
                              OLD.ancestry, OLD.depth, OLD.created_at, OLD.deadline_at) THEN
        RAISE EXCEPTION 'an execution''s identity never changes' USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.cancel_requested_at IS NOT NULL AND (NEW.cancel_requested_at, NEW.cancel_reason, NEW.cancel_requested_by)
            IS DISTINCT FROM (OLD.cancel_requested_at, OLD.cancel_reason, OLD.cancel_requested_by) THEN
        RAISE EXCEPTION 'a cancellation is requested once' USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.started_at IS NOT NULL AND NEW.started_at IS DISTINCT FROM OLD.started_at THEN
        RAISE EXCEPTION 'an execution starts once' USING ERRCODE = 'check_violation';
    END IF;
    NEW.updated_at := now();
    IF NEW.state NOT IN ('PENDING', 'RUNNING', 'WAITING') AND OLD.state IN ('PENDING', 'RUNNING', 'WAITING') THEN
        NEW.ended_at := now();
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd

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
