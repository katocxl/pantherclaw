-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
-- M13 D34/D54: organization erasure deletes every tenant table in foreign
-- key order and fails closed on an unreviewed cycle. Two older cycles are
-- reviewed here, each broken at its feedback edge:
-- - agent_instances.sandbox_session_id -> sandbox_sessions (00090), whose
--   sessions name the instance and the run;
-- - automation_triggers.execution_id -> automation_executions (00142),
--   whose executions name the trigger.
-- The edges become DEFERRABLE INITIALLY IMMEDIATE: every other transaction
-- checks them per statement as before, and only the deletion job defers
-- them until its commit, when both sides are gone.
-- +goose Up
ALTER TABLE pc.agent_instances ALTER CONSTRAINT agent_instances_sandbox_session_fk DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE pc.automation_triggers ALTER CONSTRAINT automation_triggers_execution_fk DEFERRABLE INITIALLY IMMEDIATE;

-- +goose Down
ALTER TABLE pc.automation_triggers ALTER CONSTRAINT automation_triggers_execution_fk NOT DEFERRABLE;
ALTER TABLE pc.agent_instances ALTER CONSTRAINT agent_instances_sandbox_session_fk NOT DEFERRABLE;
