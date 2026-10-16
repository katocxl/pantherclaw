-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Governed automations, engine (G0 M11 part 2 D24–D26, D30, D13, D25a,
-- D62; HR-279..283, T-124, T-125).
--
-- An execution is one accepted trigger worked through a version's steps:
-- PENDING → RUNNING ⇄ WAITING → SUCCEEDED | PARTIALLY_COMPLETED | FAILED |
-- CANCELLED | NEEDS_RECONCILIATION. Terminal states are final, except that
-- NEEDS_RECONCILIATION resolves once to a final state. It keeps a snapshot
-- of its trigger (kind, typed parameters, subjects, evidence, ancestry), so
-- the steps never read the trigger log. Each step attempt is a row; a
-- terminal attempt never changes (HR-280: a retry is a new attempt with
-- the same step id). A launch is the work handed to an enrolled agent: its
-- run and grant, claimed by one instance and completed by it (D26).
--
-- Gates (D25, D25a, D62) are approval requests of subject kind
-- AUTOMATION_GATE bound to an execution and a step. They have no agent
-- when the automation has none: agent_id may be NULL for this kind only.
-- Their requester is the automation (requested_by_automation), never a
-- person; every request names at most one requester. The waitlist gains
-- the AUTOMATION_GATE kind with the same subject and requester.
--
-- grants.automation_execution_id and runs.automation_execution_id (00140)
-- gain their foreign keys, and evidence packs a scope automation_execution
-- (D30).

-- +goose Up
CREATE TABLE pc.automation_executions (
    org_id              uuid        NOT NULL REFERENCES pc.orgs (id),
    id                  uuid        NOT NULL,
    automation_id       uuid        NOT NULL,
    version_id          uuid        NOT NULL,
    trigger_id          uuid        NOT NULL,
    mode                text        NOT NULL CHECK (mode IN ('LIVE', 'SHADOW', 'TEST')),
    state               text        NOT NULL DEFAULT 'PENDING'
                                    CHECK (state IN ('PENDING', 'RUNNING', 'WAITING', 'SUCCEEDED', 'PARTIALLY_COMPLETED',
                                                     'FAILED', 'CANCELLED', 'NEEDS_RECONCILIATION')),
    reason              text        CHECK (reason ~ '^[A-Z][A-Z_]{1,63}$'),
    -- The index of the step being worked (do), or of the compensation step
    -- when compensating.
    current_step        smallint    NOT NULL DEFAULT 0 CHECK (current_step BETWEEN 0 AND 40),
    compensating        boolean     NOT NULL DEFAULT false,
    ceiling_id          uuid,
    service_account_id  uuid        NOT NULL,
    principal_user_id   uuid,
    principal_sa_id     uuid,
    -- The trigger as the engine received it (D11 TriggerRef).
    trigger_kind        text        NOT NULL CHECK (trigger_kind IN ('SCHEDULE', 'EVENT', 'INBOUND', 'CONDITION',
                                                                     'THRESHOLD', 'MANUAL')),
    params              jsonb       NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(params) = 'object'
                                                                AND octet_length(params::text) <= 4096),
    subjects            jsonb       NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(subjects) = 'array'
                                                                AND octet_length(subjects::text) <= 16384),
    evidence            jsonb       NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(evidence) = 'array'
                                                                AND octet_length(evidence::text) <= 16384),
    occurred_at         timestamptz NOT NULL,
    root_trigger_id     uuid        NOT NULL,
    ancestry            uuid[]      NOT NULL DEFAULT '{}' CHECK (cardinality(ancestry) <= 8
                                                                AND array_position(ancestry, NULL) IS NULL),
    depth               smallint    NOT NULL DEFAULT 0 CHECK (depth BETWEEN 0 AND 3),
    -- The result (D27): steps changed / unchanged / unknown, unresolved
    -- work and cleanup refs; set at the terminal state.
    result              jsonb       CHECK (jsonb_typeof(result) = 'object' AND octet_length(result::text) <= 65536),
    transitions         integer     NOT NULL DEFAULT 0 CHECK (transitions >= 0),
    created_at          timestamptz NOT NULL DEFAULT now(),
    started_at          timestamptz,
    deadline_at         timestamptz NOT NULL,
    updated_at          timestamptz NOT NULL DEFAULT now(),
    ended_at            timestamptz,
    wake_at             timestamptz,
    cancel_requested_by text        CHECK (char_length(cancel_requested_by) BETWEEN 1 AND 100),
    cancel_reason       text        CHECK (cancel_reason ~ '^[A-Z][A-Z_]{1,63}$'),
    cancel_requested_at timestamptz,
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, trigger_id),
    FOREIGN KEY (org_id, automation_id) REFERENCES pc.automations (org_id, id),
    FOREIGN KEY (org_id, automation_id, version_id) REFERENCES pc.automation_versions (org_id, automation_id, id),
    FOREIGN KEY (org_id, ceiling_id) REFERENCES pc.automation_ceilings (org_id, id),
    FOREIGN KEY (org_id, service_account_id) REFERENCES pc.service_accounts (org_id, id),
    FOREIGN KEY (org_id, principal_user_id) REFERENCES pc.users (org_id, id),
    FOREIGN KEY (org_id, principal_sa_id) REFERENCES pc.service_accounts (org_id, id),
    CONSTRAINT automation_executions_principal CHECK (num_nonnulls(principal_user_id, principal_sa_id) = 1),
    CONSTRAINT automation_executions_deadline CHECK (deadline_at > created_at
                                                     AND deadline_at <= created_at + interval '7 days 1 minute'),
    CONSTRAINT automation_executions_ended CHECK (
        (state IN ('PENDING', 'RUNNING', 'WAITING')) = (ended_at IS NULL)
        AND (state IN ('PENDING', 'RUNNING', 'WAITING')) = (result IS NULL)
        AND (state IN ('SUCCEEDED', 'PENDING', 'RUNNING', 'WAITING') OR reason IS NOT NULL)),
    CONSTRAINT automation_executions_cancel CHECK (
        (cancel_requested_at IS NULL) = (cancel_reason IS NULL) AND (cancel_reason IS NULL) = (cancel_requested_by IS NULL)),
    CONSTRAINT automation_executions_live_ceiling CHECK (mode <> 'LIVE' OR ceiling_id IS NOT NULL),
    CONSTRAINT automation_executions_root CHECK ((depth = 0) = (root_trigger_id = trigger_id))
);
CREATE INDEX automation_executions_automation ON pc.automation_executions (org_id, automation_id, created_at DESC);
CREATE INDEX automation_executions_active ON pc.automation_executions (org_id, automation_id)
    WHERE state IN ('PENDING', 'RUNNING', 'WAITING');
CREATE INDEX automation_executions_wake ON pc.automation_executions (org_id, wake_at)
    WHERE state IN ('PENDING', 'RUNNING', 'WAITING', 'NEEDS_RECONCILIATION');
CREATE INDEX automation_executions_recent ON pc.automation_executions (org_id, created_at DESC);

-- Terminal states are final; NEEDS_RECONCILIATION resolves once. The
-- identity of an execution (automation, version, trigger, mode, authority,
-- trigger snapshot) never changes.
-- +goose StatementBegin
CREATE FUNCTION pc.automation_execution_guard() RETURNS trigger
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
CREATE TRIGGER automation_executions_guard BEFORE INSERT OR UPDATE ON pc.automation_executions
    FOR EACH ROW EXECUTE FUNCTION pc.automation_execution_guard();

-- Step attempts (D24, D27). Compensation attempts are flagged; a terminal
-- attempt never changes.
CREATE TABLE pc.automation_step_attempts (
    org_id       uuid        NOT NULL REFERENCES pc.orgs (id),
    id           uuid        NOT NULL,
    execution_id uuid        NOT NULL,
    step_index   smallint    NOT NULL CHECK (step_index BETWEEN 0 AND 39),
    step_id      text        NOT NULL CHECK (step_id ~ '^[a-z][a-z0-9_-]{0,62}$'),
    attempt      smallint    NOT NULL CHECK (attempt BETWEEN 1 AND 5),
    kind         text        NOT NULL CHECK (kind ~ '^[a-z][a-z_]{1,40}$'),
    compensation boolean     NOT NULL DEFAULT false,
    state        text        NOT NULL CHECK (state IN ('RUNNING', 'WAITING', 'DONE', 'FAILED', 'SKIPPED', 'UNKNOWN',
                                                       'SHADOWED', 'COMPENSATION')),
    decision     text        NOT NULL DEFAULT 'ALLOWED' CHECK (decision IN ('ALLOWED', 'REFUSED')),
    reason       text        CHECK (reason ~ '^[A-Z][A-Z_]{1,63}$'),
    output       jsonb       NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(output) = 'object'
                                                         AND octet_length(output::text) <= 4096),
    refs         jsonb       NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(refs) = 'array'
                                                         AND octet_length(refs::text) <= 16384),
    effect       text        NOT NULL DEFAULT 'NONE' CHECK (effect IN ('CHANGED', 'UNCHANGED', 'UNKNOWN', 'NONE')),
    started_at   timestamptz NOT NULL DEFAULT now(),
    ended_at     timestamptz,
    wake_at      timestamptz,
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, execution_id, compensation, step_index, attempt),
    FOREIGN KEY (org_id, execution_id) REFERENCES pc.automation_executions (org_id, id),
    CONSTRAINT automation_step_attempts_ended CHECK ((state IN ('RUNNING', 'WAITING')) = (ended_at IS NULL)),
    CONSTRAINT automation_step_attempts_refused CHECK (decision = 'ALLOWED' OR reason IS NOT NULL)
);
CREATE INDEX automation_step_attempts_execution ON pc.automation_step_attempts (org_id, execution_id, started_at);

-- +goose StatementBegin
CREATE FUNCTION pc.automation_step_attempt_guard() RETURNS trigger
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
CREATE TRIGGER automation_step_attempts_guard BEFORE INSERT OR UPDATE ON pc.automation_step_attempts
    FOR EACH ROW EXECUTE FUNCTION pc.automation_step_attempt_guard();

-- Launches (D26): the work handed to an enrolled agent, claimed by one
-- instance (or bound by its run) and completed only by that instance.
CREATE TABLE pc.automation_launches (
    org_id              uuid        NOT NULL REFERENCES pc.orgs (id),
    id                  uuid        NOT NULL,
    execution_id        uuid        NOT NULL,
    attempt_id          uuid        NOT NULL,
    agent_id            uuid        NOT NULL,
    instance_id         uuid,
    run_id              uuid        NOT NULL,
    grant_id            uuid        NOT NULL,
    task_ref            text        NOT NULL DEFAULT '' CHECK (char_length(task_ref) <= 256),
    delivery            text        NOT NULL CHECK (delivery IN ('PULL', 'WEBHOOK')),
    destination_id      uuid,
    delivery_id         uuid,
    state               text        NOT NULL DEFAULT 'PENDING'
                                    CHECK (state IN ('PENDING', 'CLAIMED', 'COMPLETED', 'EXPIRED', 'CANCELLED')),
    claimed_instance_id uuid,
    claimed_at          timestamptz,
    claim_deadline      timestamptz NOT NULL,
    completed_at        timestamptz,
    outcome             text        CHECK (outcome IN ('SUCCEEDED', 'FAILED', 'PARTIAL')),
    report              jsonb       CHECK (jsonb_typeof(report) = 'object' AND octet_length(report::text) <= 16384),
    calls               jsonb       NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(calls) = 'array'
                                                                AND jsonb_array_length(calls) <= 10
                                                                AND octet_length(calls::text) <= 32768),
    run_params          jsonb       NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(run_params) = 'object'
                                                                AND octet_length(run_params::text) <= 8192),
    created_at          timestamptz NOT NULL DEFAULT now(),
    ended_at            timestamptz,
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, run_id),
    FOREIGN KEY (org_id, execution_id) REFERENCES pc.automation_executions (org_id, id),
    -- The attempt row is written when the step returns, after the launch.
    FOREIGN KEY (org_id, attempt_id) REFERENCES pc.automation_step_attempts (org_id, id) DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (org_id, agent_id) REFERENCES pc.agents (org_id, id),
    FOREIGN KEY (org_id, instance_id) REFERENCES pc.agent_instances (org_id, id),
    FOREIGN KEY (org_id, claimed_instance_id) REFERENCES pc.agent_instances (org_id, id),
    FOREIGN KEY (org_id, run_id) REFERENCES pc.runs (org_id, id),
    FOREIGN KEY (org_id, grant_id) REFERENCES pc.grants (org_id, id),
    CONSTRAINT automation_launches_destination CHECK ((delivery = 'WEBHOOK') = (destination_id IS NOT NULL)),
    CONSTRAINT automation_launches_claimed CHECK (
        (claimed_at IS NULL) = (claimed_instance_id IS NULL)
        AND (state IN ('CLAIMED', 'COMPLETED')) <= (claimed_at IS NOT NULL)
        AND (instance_id IS NULL OR claimed_instance_id IS NULL OR claimed_instance_id = instance_id)),
    CONSTRAINT automation_launches_completed CHECK (
        (state = 'COMPLETED') = (completed_at IS NOT NULL) AND (state = 'COMPLETED') = (outcome IS NOT NULL)),
    CONSTRAINT automation_launches_ended CHECK ((state IN ('PENDING', 'CLAIMED')) = (ended_at IS NULL)),
    CONSTRAINT automation_launches_claim_deadline CHECK (claim_deadline > created_at
                                                         AND claim_deadline <= created_at + interval '1 hour 1 minute')
);
CREATE INDEX automation_launches_pending ON pc.automation_launches (org_id, agent_id, created_at) WHERE state = 'PENDING';
CREATE INDEX automation_launches_execution ON pc.automation_launches (org_id, execution_id);

-- PENDING → CLAIMED → COMPLETED; PENDING|CLAIMED → EXPIRED|CANCELLED. A
-- launch's content and its claim never change.
-- +goose StatementBegin
CREATE FUNCTION pc.automation_launch_guard() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pc, pg_temp
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.state IS DISTINCT FROM 'PENDING' OR NEW.claimed_at IS NOT NULL THEN
            RAISE EXCEPTION 'a launch is inserted PENDING' USING ERRCODE = 'check_violation';
        END IF;
        NEW.created_at := now();
        RETURN NEW;
    END IF;
    IF OLD.state NOT IN ('PENDING', 'CLAIMED') THEN
        RAISE EXCEPTION 'an ended launch never changes' USING ERRCODE = 'check_violation';
    END IF;
    IF (NEW.id, NEW.execution_id, NEW.attempt_id, NEW.agent_id, NEW.instance_id, NEW.run_id, NEW.grant_id, NEW.task_ref,
            NEW.delivery, NEW.destination_id, NEW.claim_deadline, NEW.calls, NEW.run_params, NEW.created_at)
            IS DISTINCT FROM (OLD.id, OLD.execution_id, OLD.attempt_id, OLD.agent_id, OLD.instance_id, OLD.run_id,
                              OLD.grant_id, OLD.task_ref, OLD.delivery, OLD.destination_id, OLD.claim_deadline,
                              OLD.calls, OLD.run_params, OLD.created_at) THEN
        RAISE EXCEPTION 'a launch''s content never changes' USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.delivery_id IS NOT NULL AND NEW.delivery_id IS DISTINCT FROM OLD.delivery_id THEN
        RAISE EXCEPTION 'a launch is delivered once' USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.claimed_at IS NOT NULL AND (NEW.claimed_at, NEW.claimed_instance_id)
            IS DISTINCT FROM (OLD.claimed_at, OLD.claimed_instance_id) THEN
        RAISE EXCEPTION 'a launch is claimed once' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.state = 'PENDING' AND OLD.state = 'CLAIMED' THEN
        RAISE EXCEPTION 'a claimed launch never returns to PENDING' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.state = 'CLAIMED' AND OLD.state = 'PENDING' THEN
        NEW.claimed_at := now();
    END IF;
    IF NEW.state = 'COMPLETED' THEN
        NEW.completed_at := now();
    END IF;
    IF NEW.state NOT IN ('PENDING', 'CLAIMED') THEN
        NEW.ended_at := now();
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER automation_launches_guard BEFORE INSERT OR UPDATE ON pc.automation_launches
    FOR EACH ROW EXECUTE FUNCTION pc.automation_launch_guard();

-- +goose StatementBegin
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['automation_executions', 'automation_step_attempts', 'automation_launches']
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

GRANT SELECT, INSERT ON pc.automation_executions, pc.automation_step_attempts, pc.automation_launches TO pc_app;
GRANT UPDATE (state, reason, current_step, compensating, result, transitions, started_at, updated_at, ended_at, wake_at,
              cancel_requested_by, cancel_reason, cancel_requested_at) ON pc.automation_executions TO pc_app;
GRANT UPDATE (state, decision, reason, output, refs, effect, ended_at, wake_at) ON pc.automation_step_attempts TO pc_app;
GRANT UPDATE (state, claimed_instance_id, claimed_at, completed_at, outcome, report, delivery_id, ended_at)
    ON pc.automation_launches TO pc_app;
GRANT SELECT ON pc.automation_executions, pc.automation_step_attempts, pc.automation_launches TO pc_audit_ro;

-- An execution and its trigger name each other (00141); deliveries and
-- launches name their execution and delivery.
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.automation_executions ADD CONSTRAINT automation_executions_trigger_fk
    FOREIGN KEY (org_id, trigger_id) REFERENCES pc.automation_triggers (org_id, id);
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.automation_triggers ADD CONSTRAINT automation_triggers_execution_fk
    FOREIGN KEY (org_id, execution_id) REFERENCES pc.automation_executions (org_id, id) NOT VALID;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.automation_triggers VALIDATE CONSTRAINT automation_triggers_execution_fk;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.automation_deliveries ADD CONSTRAINT automation_deliveries_execution_fk
    FOREIGN KEY (org_id, execution_id) REFERENCES pc.automation_executions (org_id, id) NOT VALID;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.automation_deliveries VALIDATE CONSTRAINT automation_deliveries_execution_fk;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.automation_launches ADD CONSTRAINT automation_launches_delivery_fk
    FOREIGN KEY (org_id, delivery_id) REFERENCES pc.automation_deliveries (org_id, id);

-- Grants and runs name their execution (00140 added the columns).
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.grants ADD CONSTRAINT grants_automation_execution_fk
    FOREIGN KEY (org_id, automation_execution_id) REFERENCES pc.automation_executions (org_id, id) NOT VALID;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.grants VALIDATE CONSTRAINT grants_automation_execution_fk;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.runs ADD CONSTRAINT runs_automation_execution_fk
    FOREIGN KEY (org_id, automation_execution_id) REFERENCES pc.automation_executions (org_id, id) NOT VALID;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.runs VALIDATE CONSTRAINT runs_automation_execution_fk;

-- A run that names an execution is launched by that execution's own
-- service account, and keeps naming it (D64, HR-270).
-- +goose StatementBegin
CREATE FUNCTION pc.run_automation_execution_guard() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pc, pg_temp
AS $$
BEGIN
    IF TG_OP = 'UPDATE' AND NEW.automation_execution_id IS DISTINCT FROM OLD.automation_execution_id THEN
        RAISE EXCEPTION 'a run''s execution never changes' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.automation_execution_id IS NOT NULL AND NEW.launcher_sa_id IS DISTINCT FROM (
            SELECT e.service_account_id FROM pc.automation_executions e
            WHERE e.org_id = NEW.org_id AND e.id = NEW.automation_execution_id) THEN
        RAISE EXCEPTION 'AUTOMATION_IDENTITY: a run of an execution is launched by its service account'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER runs_automation_execution_guard BEFORE INSERT OR UPDATE ON pc.runs
    FOR EACH ROW EXECUTE FUNCTION pc.run_automation_execution_guard();

-- Gates are approval requests (D25, D25a, D62). The new columns are
-- nullable without defaults (no rewrite); the CHECKs are added NOT VALID
-- and validated, and existing rows already satisfy them.
-- squawk-ignore adding-not-nullable-field
ALTER TABLE pc.approval_requests
    ADD COLUMN execution_id            uuid,
    ADD COLUMN step_id                 text CHECK (step_id ~ '^[a-z][a-z0-9_-]{0,62}$'),
    ADD COLUMN requested_by_automation uuid,
    ALTER COLUMN agent_id DROP NOT NULL,
    DROP CONSTRAINT approval_requests_subject_kind_check,
    DROP CONSTRAINT approval_requests_subject,
    DROP CONSTRAINT approval_requests_consumed,
    ADD CONSTRAINT approval_requests_subject_kind_check
        CHECK (subject_kind IN ('ACTION', 'RESTORATION', 'AUTOMATION_GATE')) NOT VALID,
    ADD CONSTRAINT approval_requests_subject CHECK (
        (subject_kind = 'ACTION' AND agent_id IS NOT NULL AND transaction_id IS NOT NULL AND evaluation IS NOT NULL
            AND run_id IS NOT NULL AND grant_id IS NOT NULL AND grant_revision IS NOT NULL AND variant_key IS NOT NULL
            AND requested_by IS NULL AND requested_by_automation IS NULL AND execution_id IS NULL AND step_id IS NULL)
        OR (subject_kind = 'RESTORATION' AND agent_id IS NOT NULL AND transaction_id IS NULL AND evaluation IS NULL
            AND run_id IS NULL AND grant_id IS NULL AND grant_revision IS NULL AND variant_key IS NULL
            AND requested_by IS NOT NULL AND requested_by_automation IS NULL AND execution_id IS NULL AND step_id IS NULL)
        OR (subject_kind = 'AUTOMATION_GATE' AND transaction_id IS NULL AND evaluation IS NULL AND run_id IS NULL
            AND grant_id IS NULL AND grant_revision IS NULL AND variant_key IS NULL AND requested_by IS NULL
            AND requested_by_automation IS NOT NULL AND execution_id IS NOT NULL AND step_id IS NOT NULL)) NOT VALID,
    ADD CONSTRAINT approval_requests_requester CHECK (num_nonnulls(requested_by, requested_by_automation) <= 1) NOT VALID,
    ADD CONSTRAINT approval_requests_consumed CHECK (
        (state = 'CONSUMED') = (consumed_at IS NOT NULL)
        AND (permit_id IS NULL OR state = 'CONSUMED')
        AND (state <> 'CONSUMED' OR subject_kind IN ('RESTORATION', 'AUTOMATION_GATE') OR permit_id IS NOT NULL)) NOT VALID,
    ADD CONSTRAINT approval_requests_execution_fk FOREIGN KEY (org_id, execution_id)
        REFERENCES pc.automation_executions (org_id, id) NOT VALID,
    ADD CONSTRAINT approval_requests_automation_fk FOREIGN KEY (org_id, requested_by_automation)
        REFERENCES pc.automations (org_id, id) NOT VALID;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.approval_requests VALIDATE CONSTRAINT approval_requests_subject_kind_check;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.approval_requests VALIDATE CONSTRAINT approval_requests_subject;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.approval_requests VALIDATE CONSTRAINT approval_requests_requester;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.approval_requests VALIDATE CONSTRAINT approval_requests_consumed;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.approval_requests VALIDATE CONSTRAINT approval_requests_execution_fk;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.approval_requests VALIDATE CONSTRAINT approval_requests_automation_fk;
-- One live gate per execution step (HR-281).
-- squawk-ignore require-concurrent-index-creation
CREATE UNIQUE INDEX approval_requests_live_gate ON pc.approval_requests (org_id, execution_id, step_id)
    WHERE subject_kind = 'AUTOMATION_GATE' AND state IN ('PENDING', 'EVIDENCE_REQUESTED', 'APPROVED');

-- The waitlist's AUTOMATION_GATE entries (D25a, D62).
-- squawk-ignore adding-not-nullable-field
ALTER TABLE pc.waitlist_entries
    ADD COLUMN requested_by_automation uuid,
    DROP CONSTRAINT waitlist_entries_kind_check,
    DROP CONSTRAINT waitlist_entries_kind_subject,
    ADD CONSTRAINT waitlist_entries_kind_check CHECK (kind IN ('ADMISSION', 'ACCESS_REQUEST', 'ACTION_HOLD', 'TOOL_REVIEW',
                                                               'RESTORATION', 'RECONCILIATION', 'AUTOMATION_GATE')) NOT VALID,
    ADD CONSTRAINT waitlist_entries_kind_subject CHECK (CASE kind
        WHEN 'ADMISSION' THEN subject_type IN ('agent', 'instance') AND agent_id IS NOT NULL
        WHEN 'ACCESS_REQUEST' THEN subject_type = 'grant' AND agent_id IS NOT NULL AND run_id IS NOT NULL
            AND requested_by IS NOT NULL
        WHEN 'ACTION_HOLD' THEN subject_type = 'approval_request' AND agent_id IS NOT NULL AND run_id IS NOT NULL
            AND transaction_id IS NOT NULL
        WHEN 'TOOL_REVIEW' THEN subject_type = 'package_version' AND agent_id IS NULL AND run_id IS NULL
        WHEN 'RESTORATION' THEN subject_type = 'approval_request' AND agent_id IS NOT NULL AND requested_by IS NOT NULL
        WHEN 'RECONCILIATION' THEN subject_type = 'transaction' AND agent_id IS NOT NULL AND run_id IS NOT NULL
            AND transaction_id = subject_id
        WHEN 'AUTOMATION_GATE' THEN subject_type = 'approval_request' AND requested_by IS NULL
            AND requested_by_automation IS NOT NULL AND run_id IS NULL AND transaction_id IS NULL
        ELSE false
    END AND (kind = 'AUTOMATION_GATE') = (requested_by_automation IS NOT NULL)) NOT VALID,
    ADD CONSTRAINT waitlist_entries_automation_fk FOREIGN KEY (org_id, requested_by_automation)
        REFERENCES pc.automations (org_id, id) NOT VALID;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.waitlist_entries VALIDATE CONSTRAINT waitlist_entries_kind_check;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.waitlist_entries VALIDATE CONSTRAINT waitlist_entries_kind_subject;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.waitlist_entries VALIDATE CONSTRAINT waitlist_entries_automation_fk;

-- Evidence packs of one execution (D30).
ALTER TABLE pc.evidence_packs
    DROP CONSTRAINT evidence_packs_scope_kind_check,
    ADD CONSTRAINT evidence_packs_scope_kind_check
        CHECK (scope_kind IN ('transactions', 'run', 'agent', 'time_range', 'range', 'automation_execution')) NOT VALID;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.evidence_packs VALIDATE CONSTRAINT evidence_packs_scope_kind_check;

-- +goose Down
DELETE FROM pc.evidence_packs WHERE scope_kind = 'automation_execution';
ALTER TABLE pc.evidence_packs
    DROP CONSTRAINT evidence_packs_scope_kind_check,
    ADD CONSTRAINT evidence_packs_scope_kind_check
        CHECK (scope_kind IN ('transactions', 'run', 'agent', 'time_range', 'range'));

DELETE FROM pc.waitlist_routes WHERE entry_id IN (SELECT id FROM pc.waitlist_entries WHERE kind = 'AUTOMATION_GATE');
DELETE FROM pc.waitlist_entries WHERE kind = 'AUTOMATION_GATE';
ALTER TABLE pc.waitlist_entries
    DROP CONSTRAINT waitlist_entries_automation_fk,
    DROP CONSTRAINT waitlist_entries_kind_subject,
    DROP CONSTRAINT waitlist_entries_kind_check,
    DROP COLUMN requested_by_automation,
    ADD CONSTRAINT waitlist_entries_kind_check CHECK (kind IN ('ADMISSION', 'ACCESS_REQUEST', 'ACTION_HOLD', 'TOOL_REVIEW',
                                                               'RESTORATION', 'RECONCILIATION')),
    ADD CONSTRAINT waitlist_entries_kind_subject CHECK (CASE kind
        WHEN 'ADMISSION' THEN subject_type IN ('agent', 'instance') AND agent_id IS NOT NULL
        WHEN 'ACCESS_REQUEST' THEN subject_type = 'grant' AND agent_id IS NOT NULL AND run_id IS NOT NULL
            AND requested_by IS NOT NULL
        WHEN 'ACTION_HOLD' THEN subject_type = 'approval_request' AND agent_id IS NOT NULL AND run_id IS NOT NULL
            AND transaction_id IS NOT NULL
        WHEN 'TOOL_REVIEW' THEN subject_type = 'package_version' AND agent_id IS NULL AND run_id IS NULL
        WHEN 'RESTORATION' THEN subject_type = 'approval_request' AND agent_id IS NOT NULL AND requested_by IS NOT NULL
        WHEN 'RECONCILIATION' THEN subject_type = 'transaction' AND agent_id IS NOT NULL AND run_id IS NOT NULL
            AND transaction_id = subject_id
    END);

DROP INDEX pc.approval_requests_live_gate;
DELETE FROM pc.webauthn_ceremonies WHERE approval_request_id IN
    (SELECT id FROM pc.approval_requests WHERE subject_kind = 'AUTOMATION_GATE');
DELETE FROM pc.approval_responses WHERE request_id IN
    (SELECT id FROM pc.approval_requests WHERE subject_kind = 'AUTOMATION_GATE');
DELETE FROM pc.approval_requests WHERE subject_kind = 'AUTOMATION_GATE';
ALTER TABLE pc.approval_requests
    DROP CONSTRAINT approval_requests_automation_fk,
    DROP CONSTRAINT approval_requests_execution_fk,
    DROP CONSTRAINT approval_requests_consumed,
    DROP CONSTRAINT approval_requests_requester,
    DROP CONSTRAINT approval_requests_subject,
    DROP CONSTRAINT approval_requests_subject_kind_check,
    DROP COLUMN requested_by_automation,
    DROP COLUMN step_id,
    DROP COLUMN execution_id,
    ALTER COLUMN agent_id SET NOT NULL,
    ADD CONSTRAINT approval_requests_subject_kind_check CHECK (subject_kind IN ('ACTION', 'RESTORATION')),
    ADD CONSTRAINT approval_requests_subject CHECK (
        (subject_kind = 'ACTION' AND transaction_id IS NOT NULL AND evaluation IS NOT NULL AND run_id IS NOT NULL
            AND grant_id IS NOT NULL AND grant_revision IS NOT NULL AND variant_key IS NOT NULL AND requested_by IS NULL)
        OR (subject_kind = 'RESTORATION' AND transaction_id IS NULL AND evaluation IS NULL AND run_id IS NULL
            AND grant_id IS NULL AND grant_revision IS NULL AND variant_key IS NULL AND requested_by IS NOT NULL)),
    ADD CONSTRAINT approval_requests_consumed CHECK (
        (state = 'CONSUMED') = (consumed_at IS NOT NULL)
        AND (permit_id IS NULL OR state = 'CONSUMED')
        AND (state <> 'CONSUMED' OR subject_kind = 'RESTORATION' OR permit_id IS NOT NULL));

ALTER TABLE pc.automation_launches DROP CONSTRAINT automation_launches_delivery_fk;
ALTER TABLE pc.automation_deliveries DROP CONSTRAINT automation_deliveries_execution_fk;
ALTER TABLE pc.automation_triggers DROP CONSTRAINT automation_triggers_execution_fk;
ALTER TABLE pc.automation_executions DROP CONSTRAINT automation_executions_trigger_fk;
DROP TRIGGER runs_automation_execution_guard ON pc.runs;
DROP FUNCTION pc.run_automation_execution_guard();
ALTER TABLE pc.runs DROP CONSTRAINT runs_automation_execution_fk;
ALTER TABLE pc.grants DROP CONSTRAINT grants_automation_execution_fk;

DROP TABLE pc.automation_launches;
DROP FUNCTION pc.automation_launch_guard();
DROP TABLE pc.automation_step_attempts;
DROP FUNCTION pc.automation_step_attempt_guard();
DROP TABLE pc.automation_executions;
DROP FUNCTION pc.automation_execution_guard();
