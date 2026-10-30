-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- The rollout VERIFIED gate (G0 M18 D154; F602, HR-479). A rollout may be
-- started with require_verified_percent (1 to 100; NULL: no gate, as
-- before). A gated rollout becomes COMPLETE only while at least that
-- share of its targets other than EXCEPTION are VERIFIED; with no such
-- target it cannot complete. There are no waves.
--
-- The threshold is set when the rollout is inserted and never changes
-- (pc_app has no UPDATE on it). The trigger below checks it on the stage
-- change itself, in the completing transaction, so every path that
-- completes a rollout (CompleteRollout's publish and a publish of the
-- version made any other way) is held to it.

-- +goose Up
ALTER TABLE pc.policy_rollouts
    ADD COLUMN require_verified_percent integer CHECK (require_verified_percent BETWEEN 1 AND 100);
GRANT INSERT (require_verified_percent) ON pc.policy_rollouts TO pc_app;

-- +goose StatementBegin
CREATE FUNCTION pc.policy_rollout_verified_gate() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pc, pg_temp
AS $$
DECLARE
    verified bigint;
    counted  bigint;
BEGIN
    IF NEW.require_verified_percent IS DISTINCT FROM OLD.require_verified_percent THEN
        RAISE EXCEPTION 'a rollout keeps its verified threshold' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.stage <> 'COMPLETE' OR OLD.stage = 'COMPLETE' OR NEW.require_verified_percent IS NULL THEN
        RETURN NEW;
    END IF;
    SELECT count(*) FILTER (WHERE t.state = 'VERIFIED'), count(*)
    INTO verified, counted
    FROM pc.policy_rollout_targets t
    WHERE t.org_id = NEW.org_id AND t.rollout_id = NEW.id AND t.state <> 'EXCEPTION';
    IF counted = 0 OR verified * 100 < counted * NEW.require_verified_percent THEN
        RAISE EXCEPTION 'rollout % has % of % targets verified, below its % percent threshold',
            NEW.id, verified, counted, NEW.require_verified_percent
            USING ERRCODE = 'check_violation', CONSTRAINT = 'policy_rollouts_verified_gate';
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER policy_rollouts_verified_gate BEFORE UPDATE ON pc.policy_rollouts
    FOR EACH ROW EXECUTE FUNCTION pc.policy_rollout_verified_gate();

-- +goose Down
DROP TRIGGER policy_rollouts_verified_gate ON pc.policy_rollouts;
DROP FUNCTION pc.policy_rollout_verified_gate();
REVOKE INSERT (require_verified_percent) ON pc.policy_rollouts FROM pc_app;
ALTER TABLE pc.policy_rollouts DROP COLUMN require_verified_percent;
