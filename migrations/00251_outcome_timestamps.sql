-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Outcome timestamps (G0 M21 D303, F774 M3, M4, M6). Additive and nullable:
-- nothing is backfilled, so a row from before this migration reads as not
-- measured.
--
-- * approval_requests.first_decided_at: the first approval or decline. A
--   re-queued approval loses approved_at but keeps this.
-- * incidents.contained_at: the first time a person declared the incident
--   CONTAINED. It is a claim, so M3 never counts it as confirmed (HR-538).
-- * cases.contained_at: the first operational close through confirmed
--   containment. It is set by a trigger, because a case changes only by its
--   entries and pc_app may not write the column; a reason that no containment
--   is needed never sets it (HR-538).
-- * response_actions.execution_id: the automation execution that caused the
--   action (M6).

-- +goose Up
ALTER TABLE pc.approval_requests ADD COLUMN first_decided_at timestamptz;
GRANT UPDATE (first_decided_at) ON pc.approval_requests TO pc_app;

ALTER TABLE pc.incidents ADD COLUMN contained_at timestamptz;
GRANT UPDATE (contained_at) ON pc.incidents TO pc_app;

ALTER TABLE pc.cases ADD COLUMN contained_at timestamptz;

-- Runs after cases_transition (triggers fire by name), which has refused an
-- operational close without confirmed containment or a reason none is needed.
-- +goose StatementBegin
CREATE FUNCTION pc.case_contained_at() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pc, pg_temp
AS $$
DECLARE
    no_need boolean;
BEGIN
    IF TG_OP = 'INSERT' THEN
        NEW.contained_at := NULL;
        RETURN NEW;
    END IF;
    NEW.contained_at := OLD.contained_at;
    IF OLD.contained_at IS NULL AND OLD.state = 'OPEN' AND NEW.state IN ('CONTAINED', 'CLOSED') THEN
        SELECT e.no_containment_needed INTO no_need FROM pc.case_entries e
        WHERE e.org_id = NEW.org_id AND e.case_id = NEW.id AND e.seq = NEW.head_seq;
        IF NOT coalesce(no_need, true) THEN
            NEW.contained_at := now();
        END IF;
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER cases_transition_contained BEFORE INSERT OR UPDATE ON pc.cases
    FOR EACH ROW EXECUTE FUNCTION pc.case_contained_at();

ALTER TABLE pc.response_actions
    ADD COLUMN execution_id uuid,
    ADD CONSTRAINT response_actions_execution_fk FOREIGN KEY (org_id, execution_id)
        REFERENCES pc.automation_executions (org_id, id) NOT VALID;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.response_actions VALIDATE CONSTRAINT response_actions_execution_fk;

-- +goose Down
ALTER TABLE pc.response_actions DROP COLUMN execution_id;
DROP TRIGGER cases_transition_contained ON pc.cases;
DROP FUNCTION pc.case_contained_at();
ALTER TABLE pc.cases DROP COLUMN contained_at;
REVOKE UPDATE (contained_at) ON pc.incidents FROM pc_app;
ALTER TABLE pc.incidents DROP COLUMN contained_at;
REVOKE UPDATE (first_decided_at) ON pc.approval_requests FROM pc_app;
ALTER TABLE pc.approval_requests DROP COLUMN first_decided_at;
