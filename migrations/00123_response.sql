-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Graduated containment, per-path confirmation, restoration plans and SOAR
-- requests (G0 M10 coordinator decisions D21–D26; F547, F552, F561, F288,
-- F134, F013, F243, F555, F564, F568, F570, F541; HR-248..HR-252).
--
-- containment_controls are what the Authority decision pipeline enforces
-- (HR-248): a scope (agent, run, grant with its dependants, connection,
-- resource target pattern, or principal) and a control (DENY_ALL,
-- HOLD_WRITES or DENY_OPERATION of one operation). The pipeline reads the
-- org's active controls in the decision transaction. Adding a control, or
-- lifting one, raises the org's containment epoch in the same transaction
-- (a trigger, whichever use case writes), so every outstanding permit fails
-- BeginDispatch and gateways see the change. A control is never deleted:
-- lifting records the restoration plan that lifted it, and pc_app may only
-- set the lift columns.
--
-- response_actions record each Contain, Terminate, Revoke or Rotate request
-- and its status; response_paths each path the request must reach (a
-- gateway serving the scope, a coverage route of an affected agent, an
-- agent-held credential, an in-flight transaction) with its confirmation
-- evidence or why it is unresolved, failed or unsupported (HR-249).
--
-- restoration_plans wrap the RESTORATION approval request that lifts
-- controls (HR-250): preconditions recorded on the plan, and for a staged
-- plan (Team) the stages with their dry-run test actions and results.
--
-- soar_requests are the idempotency keys of RequestControl (Business,
-- HR-251): the canonical request digest per (org, key) and the action it
-- created.
--
-- Times are the database's.

-- +goose Up
CREATE TABLE pc.response_actions (
    org_id           uuid        NOT NULL REFERENCES pc.orgs (id),
    id               uuid        NOT NULL,
    kind             text        NOT NULL CHECK (kind IN ('CONTAIN', 'TERMINATE', 'REVOKE', 'ROTATE')),
    scope_type       text        NOT NULL CHECK (scope_type IN ('agent', 'run', 'grant', 'connection', 'resource', 'principal',
                                                                'credential', 'transaction')),
    scope_id         text        NOT NULL CHECK (char_length(scope_id) BETWEEN 1 AND 300),
    control          text        CHECK (control IS NULL OR control IN ('DENY_ALL', 'HOLD_WRITES', 'DENY_OPERATION')),
    operation        text        CHECK (operation IS NULL OR char_length(operation) BETWEEN 1 AND 200),
    reason           text        NOT NULL CHECK (char_length(reason) BETWEEN 1 AND 1000),
    case_id          uuid,
    incident_id      uuid,
    -- Who asked: "user:<id>", "service_account:<id>" or "system:<name>".
    actor            text        NOT NULL CHECK (char_length(actor) BETWEEN 1 AND 128),
    -- Set by the server, never from request fields (D50): PERSON from the
    -- authenticated caller of Contain, SOAR from RequestControl, PLAYBOOK
    -- only from the identity playbook.
    source           text        NOT NULL CHECK (source IN ('PERSON', 'SOAR', 'PLAYBOOK')),
    -- The preview the server computed at request time (D23, D50): its digest
    -- and a summary of the known consequence; a supplied digest matched it.
    preview_digest   bytea       CHECK (preview_digest IS NULL OR octet_length(preview_digest) = 32),
    preview_summary  jsonb       NOT NULL DEFAULT '{}'
                                 CHECK (jsonb_typeof(preview_summary) = 'object' AND octet_length(preview_summary::text) <= 8192),
    -- The emergency skip of a wider control's preview, when recorded.
    skip_preview     boolean     NOT NULL DEFAULT false,
    skip_reason      text        CHECK (skip_reason IS NULL OR char_length(skip_reason) BETWEEN 1 AND 500),
    skip_step_up_at  timestamptz,
    idempotency_key  text        CHECK (idempotency_key IS NULL OR char_length(idempotency_key) BETWEEN 1 AND 128),
    request_digest   bytea       CHECK (request_digest IS NULL OR octet_length(request_digest) = 32),
    status           text        NOT NULL DEFAULT 'REQUESTED'
                                 CHECK (status IN ('REQUESTED', 'PARTIAL', 'CONFIRMED', 'FAILED', 'UNSUPPORTED')),
    -- New access stopped (F561), separate from historical exposure.
    future_confirmed boolean     NOT NULL DEFAULT false,
    historical_open  jsonb       NOT NULL DEFAULT '[]'
                                 CHECK (jsonb_typeof(historical_open) = 'array' AND octet_length(historical_open::text) <= 65536),
    -- The containment epoch the change raised the org to.
    epoch            bigint      CHECK (epoch IS NULL OR epoch > 0),
    requested_at     timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    settled_at       timestamptz,
    PRIMARY KEY (org_id, id),
    CONSTRAINT response_actions_control CHECK ((kind = 'CONTAIN') = (control IS NOT NULL)),
    CONSTRAINT response_actions_operation CHECK ((control = 'DENY_OPERATION') = (operation IS NOT NULL)),
    CONSTRAINT response_actions_skip CHECK (skip_preview = (skip_reason IS NOT NULL) AND skip_preview = (skip_step_up_at IS NOT NULL)),
    CONSTRAINT response_actions_idempotency CHECK ((idempotency_key IS NULL) = (request_digest IS NULL)),
    CONSTRAINT response_actions_settled CHECK ((status IN ('CONFIRMED', 'FAILED', 'UNSUPPORTED')) = (settled_at IS NOT NULL))
);
CREATE UNIQUE INDEX response_actions_idempotency_key ON pc.response_actions (org_id, idempotency_key)
    WHERE idempotency_key IS NOT NULL;
CREATE INDEX response_actions_unsettled ON pc.response_actions (org_id, requested_at) WHERE settled_at IS NULL;
CREATE INDEX response_actions_case ON pc.response_actions (org_id, case_id) WHERE case_id IS NOT NULL;
CREATE INDEX response_actions_incident ON pc.response_actions (org_id, incident_id) WHERE incident_id IS NOT NULL;
CREATE INDEX response_actions_scope ON pc.response_actions (org_id, scope_type, scope_id);
-- The SOAR rate limit counts the wide requests of the last hour (D50).
CREATE INDEX response_actions_soar ON pc.response_actions (org_id, requested_at) WHERE source = 'SOAR';

CREATE TABLE pc.containment_controls (
    org_id         uuid        NOT NULL REFERENCES pc.orgs (id),
    id             uuid        NOT NULL,
    action_id      uuid        NOT NULL,
    scope_type     text        NOT NULL CHECK (scope_type IN ('agent', 'run', 'grant', 'connection', 'resource', 'principal')),
    -- A uuid for every scope but resource, whose id is
    -- "<target type>:<target id pattern>" (a trailing * matches a prefix),
    -- and principal, which is "user:<id>" or "service_account:<id>".
    scope_id       text        NOT NULL CHECK (char_length(scope_id) BETWEEN 1 AND 300),
    control        text        NOT NULL CHECK (control IN ('DENY_ALL', 'HOLD_WRITES', 'DENY_OPERATION')),
    operation      text        CHECK (operation IS NULL OR char_length(operation) BETWEEN 1 AND 200),
    reason         text        NOT NULL CHECK (char_length(reason) BETWEEN 1 AND 1000),
    case_id        uuid,
    incident_id    uuid,
    created_by     text        NOT NULL CHECK (char_length(created_by) BETWEEN 1 AND 128),
    created_at     timestamptz NOT NULL DEFAULT now(),
    expires_at     timestamptz,
    lifted_at      timestamptz,
    lifted_by      text        CHECK (lifted_by IS NULL OR char_length(lifted_by) BETWEEN 1 AND 128),
    restoration_id uuid,
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, action_id) REFERENCES pc.response_actions (org_id, id),
    CONSTRAINT containment_controls_operation CHECK ((control = 'DENY_OPERATION') = (operation IS NOT NULL)),
    CONSTRAINT containment_controls_expiry CHECK (expires_at IS NULL OR expires_at > created_at),
    -- Lifting is a restoration (HR-248): a lift names the plan and who lifted.
    CONSTRAINT containment_controls_lift CHECK ((lifted_at IS NULL) = (lifted_by IS NULL)
                                                AND (lifted_at IS NULL) = (restoration_id IS NULL))
);
CREATE INDEX containment_controls_active ON pc.containment_controls (org_id) WHERE lifted_at IS NULL;
CREATE INDEX containment_controls_action ON pc.containment_controls (org_id, action_id);

-- Adding or lifting a control raises the epoch in the same transaction
-- (HR-248, HR-002); the org_containment trigger then notifies the
-- containment watchers. A lifted control is never lifted again.
-- +goose StatementBegin
CREATE FUNCTION pc.containment_control_epoch() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'UPDATE' THEN
        IF OLD.lifted_at IS NOT NULL THEN
            RAISE EXCEPTION 'containment control % is already lifted', OLD.id USING ERRCODE = 'check_violation';
        END IF;
        IF NEW.lifted_at IS NULL THEN
            RETURN NEW;
        END IF;
        NEW.lifted_at := now();
    END IF;
    INSERT INTO pc.org_containment (org_id) VALUES (NEW.org_id) ON CONFLICT (org_id) DO NOTHING;
    UPDATE pc.org_containment SET epoch = epoch + 1, updated_at = now() WHERE org_id = NEW.org_id;
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER containment_controls_epoch BEFORE INSERT OR UPDATE ON pc.containment_controls
    FOR EACH ROW EXECUTE FUNCTION pc.containment_control_epoch();

CREATE TABLE pc.response_paths (
    org_id             uuid        NOT NULL,
    action_id          uuid        NOT NULL,
    id                 uuid        NOT NULL,
    path_type          text        NOT NULL CHECK (path_type IN ('GATEWAY', 'ROUTE', 'CREDENTIAL', 'IN_FLIGHT')),
    subject_type       text        NOT NULL CHECK (subject_type IN ('gateway', 'connection', 'credential', 'transaction', 'agent')),
    subject_id         text        NOT NULL CHECK (char_length(subject_id) BETWEEN 1 AND 300),
    -- A material path decides the action's status; others are listed.
    material           boolean     NOT NULL DEFAULT true,
    -- What enforces the control on this path: the coverage route's state
    -- for a route (ENFORCED, PARTIAL, OBSERVE_ONLY, UNKNOWN), else the
    -- mechanism (epoch, revoke, rotate, cancel).
    control            text        NOT NULL CHECK (char_length(control) BETWEEN 1 AND 64),
    status             text        NOT NULL DEFAULT 'PENDING'
                                   CHECK (status IN ('PENDING', 'CONFIRMED', 'UNRESOLVED', 'FAILED', 'UNSUPPORTED')),
    -- Ids and times only (no payloads): the acknowledged epoch, the revoke
    -- receipt, the cancelled transaction's state.
    evidence           jsonb       NOT NULL DEFAULT '{}'
                                   CHECK (jsonb_typeof(evidence) = 'object' AND octet_length(evidence::text) <= 4096),
    failure            text        CHECK (failure IS NULL OR char_length(failure) BETWEEN 1 AND 500),
    unsupported_reason text        CHECK (unsupported_reason IS NULL OR char_length(unsupported_reason) BETWEEN 1 AND 500),
    -- Termination of dispatched work (F134).
    cancel_capability  text        CHECK (cancel_capability IS NULL OR cancel_capability IN ('CANCELLABLE', 'NOT_CANCELLABLE', 'UNKNOWN')),
    cancel_requested_at timestamptz,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    confirmed_at       timestamptz,
    PRIMARY KEY (org_id, action_id, id),
    FOREIGN KEY (org_id, action_id) REFERENCES pc.response_actions (org_id, id),
    CONSTRAINT response_paths_confirmed CHECK ((status = 'CONFIRMED') = (confirmed_at IS NOT NULL)),
    CONSTRAINT response_paths_failure CHECK (status <> 'FAILED' OR failure IS NOT NULL),
    CONSTRAINT response_paths_unsupported CHECK (status <> 'UNSUPPORTED' OR unsupported_reason IS NOT NULL)
);
CREATE UNIQUE INDEX response_paths_subject ON pc.response_paths (org_id, action_id, path_type, subject_type, subject_id);
CREATE INDEX response_paths_open ON pc.response_paths (org_id, action_id) WHERE status IN ('PENDING', 'UNRESOLVED');

CREATE TABLE pc.restoration_plans (
    org_id              uuid        NOT NULL REFERENCES pc.orgs (id),
    id                  uuid        NOT NULL,
    -- The RESTORATION approval request an independent reviewer decides.
    approval_request_id uuid,
    reason              text        NOT NULL CHECK (char_length(reason) BETWEEN 1 AND 1000),
    staged              boolean     NOT NULL DEFAULT false,
    state               text        NOT NULL DEFAULT 'REQUESTED'
                                    CHECK (state IN ('REQUESTED', 'APPROVED', 'STAGING', 'COMPLETED', 'REFUSED', 'CANCELLED')),
    -- Computed and recorded when asked for and again before each lift
    -- (F564): identity re-verified, connection health, remediation and test
    -- results, remaining grants, waiting approvals.
    preconditions       jsonb       NOT NULL DEFAULT '{}'
                                    CHECK (jsonb_typeof(preconditions) = 'object' AND octet_length(preconditions::text) <= 16384),
    requested_by        text        NOT NULL CHECK (char_length(requested_by) BETWEEN 1 AND 128),
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),
    finished_at         timestamptz,
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, approval_request_id) REFERENCES pc.approval_requests (org_id, id),
    CONSTRAINT restoration_plans_finished CHECK ((state IN ('COMPLETED', 'REFUSED', 'CANCELLED')) = (finished_at IS NOT NULL))
);
CREATE UNIQUE INDEX restoration_plans_request ON pc.restoration_plans (org_id, approval_request_id)
    WHERE approval_request_id IS NOT NULL;

ALTER TABLE pc.containment_controls
    ADD CONSTRAINT containment_controls_restoration_fk FOREIGN KEY (org_id, restoration_id)
        REFERENCES pc.restoration_plans (org_id, id);

-- The controls a plan lifts (insert-only).
CREATE TABLE pc.restoration_plan_controls (
    org_id     uuid NOT NULL,
    plan_id    uuid NOT NULL,
    control_id uuid NOT NULL,
    PRIMARY KEY (org_id, plan_id, control_id),
    FOREIGN KEY (org_id, plan_id) REFERENCES pc.restoration_plans (org_id, id),
    FOREIGN KEY (org_id, control_id) REFERENCES pc.containment_controls (org_id, id)
);

-- The stages of a staged plan (Team, F568): a cohort or task scope, the
-- permitted and prohibited test actions re-run through the replay
-- evaluator (dry-run, never dispatched) before widening, and their results.
CREATE TABLE pc.restoration_stages (
    org_id      uuid        NOT NULL,
    plan_id     uuid        NOT NULL,
    ordinal     integer     NOT NULL CHECK (ordinal BETWEEN 1 AND 20),
    scope       jsonb       NOT NULL CHECK (jsonb_typeof(scope) = 'object' AND octet_length(scope::text) <= 4096),
    tests       jsonb       NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(tests) = 'array' AND octet_length(tests::text) <= 65536),
    results     jsonb       NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(results) = 'array' AND octet_length(results::text) <= 65536),
    state       text        NOT NULL DEFAULT 'PENDING' CHECK (state IN ('PENDING', 'PASSED', 'FAILED', 'APPLIED')),
    created_at  timestamptz NOT NULL DEFAULT now(),
    tested_at   timestamptz,
    applied_at  timestamptz,
    PRIMARY KEY (org_id, plan_id, ordinal),
    FOREIGN KEY (org_id, plan_id) REFERENCES pc.restoration_plans (org_id, id),
    CONSTRAINT restoration_stages_tested CHECK (state = 'PENDING' OR tested_at IS NOT NULL),
    CONSTRAINT restoration_stages_applied CHECK ((state = 'APPLIED') = (applied_at IS NOT NULL))
);

CREATE TABLE pc.soar_requests (
    org_id          uuid        NOT NULL REFERENCES pc.orgs (id),
    idempotency_key text        NOT NULL CHECK (char_length(idempotency_key) BETWEEN 1 AND 128),
    request_digest  bytea       NOT NULL CHECK (octet_length(request_digest) = 32),
    action_id       uuid        NOT NULL,
    requested_by    text        NOT NULL CHECK (char_length(requested_by) BETWEEN 1 AND 128),
    created_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, idempotency_key),
    FOREIGN KEY (org_id, action_id) REFERENCES pc.response_actions (org_id, id)
);

-- The highest containment epoch each gateway's live containment stream
-- delivered (D22): a gateway path is confirmed once its gateway was sent the
-- action's epoch. The gateway itself fails closed when its stream goes
-- quiet (HR-010), and BeginDispatch refuses a permit of an older epoch.
CREATE TABLE pc.gateway_epoch_deliveries (
    org_id       uuid        NOT NULL REFERENCES pc.orgs (id),
    gateway_id   uuid        NOT NULL,
    epoch        bigint      NOT NULL CHECK (epoch > 0),
    delivered_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, gateway_id),
    FOREIGN KEY (org_id, gateway_id) REFERENCES pc.gateways (org_id, id)
);

ALTER TABLE pc.response_actions ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.response_actions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.response_actions
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));
ALTER TABLE pc.containment_controls ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.containment_controls FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.containment_controls
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));
ALTER TABLE pc.response_paths ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.response_paths FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.response_paths
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));
ALTER TABLE pc.restoration_plans ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.restoration_plans FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.restoration_plans
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));
ALTER TABLE pc.restoration_plan_controls ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.restoration_plan_controls FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.restoration_plan_controls
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));
ALTER TABLE pc.restoration_stages ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.restoration_stages FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.restoration_stages
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));
ALTER TABLE pc.gateway_epoch_deliveries ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.gateway_epoch_deliveries FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.gateway_epoch_deliveries
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));
ALTER TABLE pc.soar_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.soar_requests FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.soar_requests
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));

-- pc_app: controls are inserted and lifted, never changed otherwise or
-- deleted; actions, paths, plans and stages change only their status
-- columns; plan controls and SOAR keys are insert-only.
GRANT SELECT, INSERT ON pc.containment_controls, pc.response_actions, pc.response_paths, pc.restoration_plans,
    pc.restoration_plan_controls, pc.restoration_stages, pc.soar_requests TO pc_app;
GRANT UPDATE (lifted_at, lifted_by, restoration_id) ON pc.containment_controls TO pc_app;
GRANT UPDATE (status, future_confirmed, historical_open, epoch, updated_at, settled_at) ON pc.response_actions TO pc_app;
GRANT UPDATE (status, evidence, failure, unsupported_reason, cancel_capability, cancel_requested_at, updated_at, confirmed_at)
    ON pc.response_paths TO pc_app;
GRANT UPDATE (approval_request_id, state, preconditions, updated_at, finished_at) ON pc.restoration_plans TO pc_app;
GRANT UPDATE (results, state, tested_at, applied_at) ON pc.restoration_stages TO pc_app;
GRANT SELECT, INSERT ON pc.gateway_epoch_deliveries TO pc_app;
GRANT UPDATE (epoch, delivered_at) ON pc.gateway_epoch_deliveries TO pc_app;
GRANT SELECT ON pc.containment_controls, pc.response_actions, pc.response_paths, pc.restoration_plans,
    pc.restoration_plan_controls, pc.restoration_stages, pc.soar_requests TO pc_audit_ro;

-- +goose Down
DROP TABLE pc.gateway_epoch_deliveries;
DROP TABLE pc.soar_requests;
DROP TABLE pc.restoration_stages;
DROP TABLE pc.restoration_plan_controls;
ALTER TABLE pc.containment_controls DROP CONSTRAINT containment_controls_restoration_fk;
DROP TABLE pc.restoration_plans;
DROP TABLE pc.response_paths;
DROP TRIGGER containment_controls_epoch ON pc.containment_controls;
DROP FUNCTION pc.containment_control_epoch();
DROP TABLE pc.containment_controls;
DROP TABLE pc.response_actions;
