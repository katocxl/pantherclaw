-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Graduated containment and response actions (G0 M10 D21–D26).

-- ActiveContainmentControls are the controls the decision pipeline enforces
-- (HR-248): not lifted and not expired by the database clock.
-- name: ActiveContainmentControls :many
SELECT id, scope_type, scope_id, control, operation, expires_at
FROM pc.containment_controls
WHERE org_id = sqlc.arg(org_id) AND lifted_at IS NULL AND (expires_at IS NULL OR expires_at > now())
ORDER BY created_at, id
LIMIT 1000;

-- name: InsertResponseAction :one
INSERT INTO pc.response_actions (org_id, id, kind, scope_type, scope_id, control, operation, reason, case_id, incident_id,
                                 actor, source, preview_digest, preview_summary, skip_preview, skip_reason, skip_step_up_at,
                                 idempotency_key, request_digest)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(kind), sqlc.arg(scope_type), sqlc.arg(scope_id),
        sqlc.narg(control), sqlc.narg(operation), sqlc.arg(reason), sqlc.narg(case_id), sqlc.narg(incident_id),
        sqlc.arg(actor), sqlc.arg(source), sqlc.narg(preview_digest), sqlc.arg(preview_summary), sqlc.arg(skip_preview), sqlc.narg(skip_reason),
        sqlc.narg(skip_step_up_at), sqlc.narg(idempotency_key), sqlc.narg(request_digest))
RETURNING requested_at;

-- InsertContainmentControl adds a control; its trigger raises the epoch in
-- the same transaction (HR-248).
-- name: InsertContainmentControl :one
INSERT INTO pc.containment_controls (org_id, id, action_id, scope_type, scope_id, control, operation, reason, case_id,
                                     incident_id, created_by, expires_at)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(action_id), sqlc.arg(scope_type), sqlc.arg(scope_id), sqlc.arg(control),
        sqlc.narg(operation), sqlc.arg(reason), sqlc.narg(case_id), sqlc.narg(incident_id), sqlc.arg(created_by),
        sqlc.narg(expires_at))
RETURNING created_at;

-- LiftContainmentControl lifts an active control through a restoration
-- plan; its trigger stamps the database time and raises the epoch.
-- name: LiftContainmentControl :execrows
UPDATE pc.containment_controls
SET lifted_at = now(), lifted_by = sqlc.arg(lifted_by), restoration_id = sqlc.arg(restoration_id)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND lifted_at IS NULL;

-- name: GetContainmentControl :one
SELECT * FROM pc.containment_controls WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: ListContainmentControls :many
SELECT * FROM pc.containment_controls
WHERE org_id = sqlc.arg(org_id) AND (sqlc.arg(include_lifted)::boolean OR lifted_at IS NULL)
ORDER BY created_at DESC, id DESC
LIMIT sqlc.arg(max_rows);

-- name: GetResponseAction :one
SELECT * FROM pc.response_actions WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: ResponseActionByKey :one
SELECT * FROM pc.response_actions WHERE org_id = sqlc.arg(org_id) AND idempotency_key = sqlc.arg(idempotency_key);

-- name: SetResponseActionEpoch :exec
UPDATE pc.response_actions SET epoch = sqlc.arg(epoch), updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- SettleResponseAction moves an unsettled action to its next status
-- (conditional on the status read, HR-249).
-- name: SettleResponseAction :execrows
UPDATE pc.response_actions
SET status = sqlc.arg(status), future_confirmed = sqlc.arg(future_confirmed), historical_open = sqlc.arg(historical_open),
    updated_at = now(),
    settled_at = CASE WHEN sqlc.arg(status)::text IN ('CONFIRMED', 'FAILED', 'UNSUPPORTED') THEN now() END
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND status = sqlc.arg(expected) AND settled_at IS NULL;

-- name: UnsettledResponseActions :many
SELECT * FROM pc.response_actions
WHERE org_id = sqlc.arg(org_id) AND settled_at IS NULL
ORDER BY requested_at, id
LIMIT sqlc.arg(max_rows);

-- name: InsertResponsePath :exec
INSERT INTO pc.response_paths (org_id, action_id, id, path_type, subject_type, subject_id, material, control, status,
                               evidence, failure, unsupported_reason, cancel_capability, confirmed_at)
VALUES (sqlc.arg(org_id), sqlc.arg(action_id), sqlc.arg(id), sqlc.arg(path_type), sqlc.arg(subject_type),
        sqlc.arg(subject_id), sqlc.arg(material), sqlc.arg(control), sqlc.arg(status), sqlc.arg(evidence),
        sqlc.narg(failure), sqlc.narg(unsupported_reason), sqlc.narg(cancel_capability),
        CASE WHEN sqlc.arg(status)::text = 'CONFIRMED' THEN now() END)
ON CONFLICT (org_id, action_id, path_type, subject_type, subject_id) DO NOTHING;

-- name: ListResponsePaths :many
SELECT * FROM pc.response_paths
WHERE org_id = sqlc.arg(org_id) AND action_id = sqlc.arg(action_id)
ORDER BY path_type, subject_type, subject_id;

-- UpdateResponsePath moves an open path (conditional on its status).
-- name: UpdateResponsePath :execrows
UPDATE pc.response_paths
SET status = sqlc.arg(status), evidence = sqlc.arg(evidence), failure = sqlc.narg(failure),
    unsupported_reason = sqlc.narg(unsupported_reason), updated_at = now(),
    confirmed_at = CASE WHEN sqlc.arg(status)::text = 'CONFIRMED' THEN now() END
WHERE org_id = sqlc.arg(org_id) AND action_id = sqlc.arg(action_id) AND id = sqlc.arg(id)
  AND status = sqlc.arg(expected) AND status IN ('PENDING', 'UNRESOLVED');

-- RecordEpochDelivery keeps the highest epoch a gateway's live containment
-- stream delivered (D22).
-- name: RecordEpochDelivery :exec
INSERT INTO pc.gateway_epoch_deliveries (org_id, gateway_id, epoch)
VALUES (sqlc.arg(org_id), sqlc.arg(gateway_id), sqlc.arg(epoch))
ON CONFLICT (org_id, gateway_id) DO UPDATE SET epoch = EXCLUDED.epoch, delivered_at = now()
WHERE pc.gateway_epoch_deliveries.epoch < EXCLUDED.epoch;

-- name: GatewayEpochDelivery :one
SELECT epoch, delivered_at FROM pc.gateway_epoch_deliveries
WHERE org_id = sqlc.arg(org_id) AND gateway_id = sqlc.arg(gateway_id);

-- ScopeActiveRuns are the active runs a control's scope covers, as the
-- pipeline matches them (D21); a connection covers the runs of the agents
-- with a route through it. At most 1001 rows: more means "over 1000".
-- name: ScopeActiveRuns :many
SELECT r.id, r.agent_id
FROM pc.runs r
WHERE r.org_id = sqlc.arg(org_id) AND r.state = 'ACTIVE' AND (
    (sqlc.arg(scope_type)::text = 'run' AND r.id::text = sqlc.arg(scope_id)::text)
    OR (sqlc.arg(scope_type)::text = 'agent' AND r.agent_id::text = sqlc.arg(scope_id)::text)
    OR (sqlc.arg(scope_type)::text = 'grant' AND r.grant_id IN (
        SELECT l.grant_id FROM pc.grant_lineage l
        WHERE l.org_id = sqlc.arg(org_id) AND l.ancestor_id::text = sqlc.arg(scope_id)::text))
    OR (sqlc.arg(scope_type)::text = 'principal' AND sqlc.arg(scope_id)::text IN (
        'user:' || r.launcher_user_id::text, 'user:' || r.principal_user_id::text,
        'service_account:' || r.launcher_sa_id::text, 'service_account:' || r.principal_sa_id::text))
    OR (sqlc.arg(scope_type)::text = 'connection' AND r.agent_id IN (
        SELECT cr.agent_id FROM pc.coverage_routes cr
        WHERE cr.org_id = sqlc.arg(org_id) AND cr.connection_id::text = sqlc.arg(scope_id)::text AND cr.agent_id IS NOT NULL))
)
ORDER BY r.id
LIMIT 1001;

-- ScopeGateways are the active gateways that serve a scope: a connection's
-- own gateway, else every active gateway of the org.
-- name: ScopeGateways :many
SELECT g.id
FROM pc.gateways g
WHERE g.org_id = sqlc.arg(org_id) AND g.state = 'ACTIVE' AND (
    sqlc.arg(scope_type)::text <> 'connection'
    OR g.id IN (SELECT c.gateway_id FROM pc.connections c
                WHERE c.org_id = sqlc.arg(org_id) AND c.id::text = sqlc.arg(scope_id)::text))
ORDER BY g.id
LIMIT 200;

-- AgentCoverage is the current coverage state of each (connection,
-- operation) of the agents: an ENFORCED state past its expiry reads UNKNOWN.
-- name: AgentCoverage :many
SELECT DISTINCT ON (s.agent_id, s.connection_id, s.operation)
       s.agent_id, s.connection_id, s.operation, c.gateway_id,
       CASE WHEN s.state = 'ENFORCED' AND s.expires_at <= now() THEN 'UNKNOWN' ELSE s.state END::text AS state
FROM pc.coverage_snapshots s
JOIN pc.connections c ON c.org_id = s.org_id AND c.id = s.connection_id
WHERE s.org_id = sqlc.arg(org_id) AND s.agent_id = ANY (sqlc.arg(agents)::uuid[])
ORDER BY s.agent_id, s.connection_id, s.operation, s.id DESC
LIMIT 2000;

-- AgentHeldConnections are the connections whose credential the agents
-- hold themselves (agent_held access) and that they have a route through.
-- name: AgentHeldConnections :many
SELECT DISTINCT c.id, c.gateway_id
FROM pc.connections c
JOIN pc.coverage_routes cr ON cr.org_id = c.org_id AND cr.connection_id = c.id
WHERE c.org_id = sqlc.arg(org_id) AND c.access_mode = 'agent_held' AND c.state <> 'RETIRED'
  AND (cr.agent_id IS NULL OR cr.agent_id = ANY (sqlc.arg(agents)::uuid[]))
ORDER BY c.id
LIMIT 200;

-- InFlightTransactions are the dispatched-but-unfinished transactions of
-- the runs (permits DISPATCHING or UNKNOWN).
-- name: InFlightTransactions :many
SELECT t.id, t.run_id, p.state, p.gateway_id
FROM pc.transactions t
JOIN pc.permits p ON p.org_id = t.org_id AND p.transaction_id = t.id
WHERE t.org_id = sqlc.arg(org_id) AND t.run_id = ANY (sqlc.arg(runs)::uuid[]) AND p.state IN ('DISPATCHING', 'UNKNOWN')
ORDER BY t.id
LIMIT 500;

-- PermitState is a transaction's permit state now.
-- name: PermitState :one
SELECT state FROM pc.permits WHERE org_id = sqlc.arg(org_id) AND transaction_id = sqlc.arg(transaction_id);

-- WaitingHoldsOfRuns counts the waiting approval requests of the runs.
-- name: WaitingHoldsOfRuns :one
SELECT count(*) FROM pc.approval_requests a
WHERE a.org_id = sqlc.arg(org_id) AND a.run_id = ANY (sqlc.arg(runs)::uuid[])
  AND a.state IN ('PENDING', 'EVIDENCE_REQUESTED', 'APPROVED');

-- name: ListResponseActions :many
SELECT * FROM pc.response_actions
WHERE org_id = sqlc.arg(org_id)
  AND (sqlc.narg(case_id)::uuid IS NULL OR case_id = sqlc.narg(case_id)::uuid)
  AND (sqlc.narg(incident_id)::uuid IS NULL OR incident_id = sqlc.narg(incident_id)::uuid)
  AND (sqlc.narg(scope_type)::text IS NULL OR (scope_type = sqlc.narg(scope_type)::text AND scope_id = sqlc.narg(scope_id)::text))
  AND (sqlc.narg(before)::uuid IS NULL OR id < sqlc.narg(before)::uuid)
ORDER BY id DESC
LIMIT sqlc.arg(max_rows);

-- name: ControlsOfAction :many
SELECT * FROM pc.containment_controls WHERE org_id = sqlc.arg(org_id) AND action_id = sqlc.arg(action_id);

-- name: GatewayStateOf :one
SELECT state FROM pc.gateways WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- ScopeExists reports whether a control's subject exists in the org.
-- name: ScopeExists :one
SELECT CASE sqlc.arg(scope_type)::text
    WHEN 'agent' THEN EXISTS (SELECT 1 FROM pc.agents x WHERE x.org_id = sqlc.arg(org_id)::uuid AND x.id = sqlc.arg(id)::uuid)
    WHEN 'run' THEN EXISTS (SELECT 1 FROM pc.runs x WHERE x.org_id = sqlc.arg(org_id)::uuid AND x.id = sqlc.arg(id)::uuid)
    WHEN 'grant' THEN EXISTS (SELECT 1 FROM pc.grants x WHERE x.org_id = sqlc.arg(org_id)::uuid AND x.id = sqlc.arg(id)::uuid)
    WHEN 'connection' THEN EXISTS (SELECT 1 FROM pc.connections x WHERE x.org_id = sqlc.arg(org_id)::uuid AND x.id = sqlc.arg(id)::uuid)
    WHEN 'user' THEN EXISTS (SELECT 1 FROM pc.users x WHERE x.org_id = sqlc.arg(org_id)::uuid AND x.id = sqlc.arg(id)::uuid)
    WHEN 'service_account' THEN EXISTS (SELECT 1 FROM pc.service_accounts x WHERE x.org_id = sqlc.arg(org_id)::uuid AND x.id = sqlc.arg(id)::uuid)
    ELSE false END::boolean AS found;

-- CredentialChangedSince is the first revocation or supersession of a
-- connection's sealed credential after a time (D25), or no row.
-- name: CredentialChangedSince :one
SELECT coalesce(revoked_at, superseded_at)::timestamptz AS changed_at
FROM pc.credentials
WHERE org_id = sqlc.arg(org_id) AND connection_id = sqlc.arg(connection_id)
  AND coalesce(revoked_at, superseded_at) >= sqlc.arg(since)::timestamptz
ORDER BY 1
LIMIT 1;

-- CredentialOfConnection is one version of a connection's sealed credential.
-- name: CredentialOfConnection :one
SELECT c.id, c.version, c.state, c.kind, c.created_at, n.gateway_id, n.access_mode
FROM pc.credentials c
JOIN pc.connections n ON n.org_id = c.org_id AND n.id = c.connection_id
WHERE c.org_id = sqlc.arg(org_id) AND c.connection_id = sqlc.arg(connection_id) AND c.version = sqlc.arg(version);

-- ActiveCredentialVersion is the connection's active sealed version.
-- name: ActiveCredentialVersion :one
SELECT version, created_at FROM pc.credentials
WHERE org_id = sqlc.arg(org_id) AND connection_id = sqlc.arg(connection_id) AND state = 'ACTIVE';

-- CredentialSharers are the agents with a route through a connection, and
-- the other connections sharing its GitHub App installation (D25, F555).
-- name: CredentialAgents :many
SELECT DISTINCT cr.agent_id
FROM pc.coverage_routes cr
WHERE cr.org_id = sqlc.arg(org_id) AND cr.connection_id = sqlc.arg(connection_id) AND cr.agent_id IS NOT NULL
ORDER BY cr.agent_id
LIMIT 1000;

-- name: CredentialEveryAgentRoutes :one
SELECT count(*) FROM pc.coverage_routes
WHERE org_id = sqlc.arg(org_id) AND connection_id = sqlc.arg(connection_id) AND agent_id IS NULL;

-- name: SharedInstallationConnections :many
SELECT o.connection_id
FROM pc.connection_github g
JOIN pc.connection_github o ON o.org_id = g.org_id AND o.installation_id = g.installation_id AND o.connection_id <> g.connection_id
WHERE g.org_id = sqlc.arg(org_id) AND g.connection_id = sqlc.arg(connection_id)
ORDER BY o.connection_id
LIMIT 200;

-- name: WaitingRequestsOfRuns :many
SELECT id FROM pc.approval_requests
WHERE org_id = sqlc.arg(org_id) AND run_id = ANY (sqlc.arg(runs)::uuid[])
  AND state IN ('PENDING', 'EVIDENCE_REQUESTED', 'APPROVED')
ORDER BY id
LIMIT 500;


-- name: GetSOARRequest :one
SELECT * FROM pc.soar_requests WHERE org_id = sqlc.arg(org_id) AND idempotency_key = sqlc.arg(idempotency_key);

-- name: InsertSOARRequest :exec
INSERT INTO pc.soar_requests (org_id, idempotency_key, request_digest, action_id, requested_by)
VALUES (sqlc.arg(org_id), sqlc.arg(idempotency_key), sqlc.arg(request_digest), sqlc.arg(action_id), sqlc.arg(requested_by));

-- name: InsertRestorationPlan :one
INSERT INTO pc.restoration_plans (org_id, id, reason, staged, preconditions, requested_by)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(reason), sqlc.arg(staged), sqlc.arg(preconditions), sqlc.arg(requested_by))
RETURNING created_at;

-- name: InsertRestorationPlanControl :exec
INSERT INTO pc.restoration_plan_controls (org_id, plan_id, control_id) VALUES (sqlc.arg(org_id), sqlc.arg(plan_id), sqlc.arg(control_id));

-- name: InsertRestorationStage :exec
INSERT INTO pc.restoration_stages (org_id, plan_id, ordinal, scope, tests)
VALUES (sqlc.arg(org_id), sqlc.arg(plan_id), sqlc.arg(ordinal), sqlc.arg(scope), sqlc.arg(tests));

-- name: LockRestorationPlan :one
SELECT * FROM pc.restoration_plans WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) FOR UPDATE;

-- name: GetRestorationPlan :one
SELECT * FROM pc.restoration_plans WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: ListRestorationPlans :many
SELECT * FROM pc.restoration_plans
WHERE org_id = sqlc.arg(org_id) AND (sqlc.narg(before)::uuid IS NULL OR id < sqlc.narg(before)::uuid)
ORDER BY id DESC
LIMIT sqlc.arg(max_rows);

-- name: RestorationPlanControls :many
SELECT c.* FROM pc.containment_controls c
JOIN pc.restoration_plan_controls p ON p.org_id = c.org_id AND p.control_id = c.id
WHERE p.org_id = sqlc.arg(org_id) AND p.plan_id = sqlc.arg(plan_id)
ORDER BY c.id;

-- name: RestorationStages :many
SELECT * FROM pc.restoration_stages WHERE org_id = sqlc.arg(org_id) AND plan_id = sqlc.arg(plan_id) ORDER BY ordinal;

-- name: SetRestorationPlanState :execrows
UPDATE pc.restoration_plans
SET state = sqlc.arg(state), preconditions = sqlc.arg(preconditions), updated_at = now(),
    finished_at = CASE WHEN sqlc.arg(state)::text IN ('COMPLETED', 'REFUSED', 'CANCELLED') THEN now() END
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = sqlc.arg(expected);

-- name: SetRestorationStage :execrows
UPDATE pc.restoration_stages
SET results = sqlc.arg(results), state = sqlc.arg(state), tested_at = now(),
    applied_at = CASE WHEN sqlc.arg(state)::text = 'APPLIED' THEN now() END
WHERE org_id = sqlc.arg(org_id) AND plan_id = sqlc.arg(plan_id) AND ordinal = sqlc.arg(ordinal) AND state IN ('PENDING', 'FAILED');

-- OpenPlanOfControl is the unfinished plan that already lifts a control.
-- name: OpenPlanOfControl :one
SELECT p.id FROM pc.restoration_plans p
JOIN pc.restoration_plan_controls c ON c.org_id = p.org_id AND c.plan_id = p.id
WHERE p.org_id = sqlc.arg(org_id) AND c.control_id = sqlc.arg(control_id) AND p.finished_at IS NULL
LIMIT 1;

-- name: AgentStateOf :one
SELECT state FROM pc.agents WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: UserStateOf :one
SELECT state FROM pc.users WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: ConnectionHealth :one
SELECT c.state, g.state AS gateway_state
FROM pc.connections c JOIN pc.gateways g ON g.org_id = c.org_id AND g.id = c.gateway_id
WHERE c.org_id = sqlc.arg(org_id) AND c.id = sqlc.arg(id);

-- name: ActiveGrantsOfAgents :one
SELECT count(*) FROM pc.grants g
JOIN pc.grant_revisions r ON r.org_id = g.org_id AND r.grant_id = g.id AND r.revision = g.current_revision
WHERE g.org_id = sqlc.arg(org_id) AND g.agent_id = ANY (sqlc.arg(agents)::uuid[]) AND g.state = 'ACTIVE' AND r.expires_at > now();

-- SessionStepUp is when a person's browser session last stepped up with
-- one of their own active security keys, and the database time.
-- name: SessionStepUp :one
SELECT s.step_up_at::timestamptz AS step_up_at, s.step_up_credential_id::uuid AS credential_id, now()::timestamptz AS db_now
FROM pc.sessions s
JOIN pc.webauthn_credentials k ON k.org_id = s.org_id AND k.id = s.step_up_credential_id AND k.user_id = s.user_id
WHERE s.org_id = sqlc.arg(org_id) AND s.id = sqlc.arg(session_id) AND s.user_id = sqlc.arg(user_id)
  AND s.state = 'ACTIVE' AND s.step_up_at IS NOT NULL AND k.state = 'ACTIVE';

-- name: AgentOfRun :one
SELECT agent_id FROM pc.runs WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: AlertSubjects :one
SELECT subjects FROM pc.alerts WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: RunOfTransaction :one
SELECT run_id FROM pc.transactions WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- IncidentAlertSubjects are the subjects of an incident's alerts.
-- name: IncidentAlertSubjects :many
SELECT subjects FROM pc.alerts WHERE org_id = sqlc.arg(org_id) AND incident_id = sqlc.arg(incident_id) ORDER BY id LIMIT 50;

-- SOARWideLastHour counts the org's SOAR controls on grants and connections
-- in the last hour, by the database clock (D50).
-- name: SOARWideLastHour :one
SELECT count(*) FROM pc.response_actions
WHERE org_id = sqlc.arg(org_id) AND source = 'SOAR' AND scope_type IN ('grant', 'connection')
  AND requested_at > now() - interval '1 hour';

-- PlaybookContainedIssuer reports whether a grant was issued by a person
-- whom an active identity-playbook DENY_ALL control contains (D50).
-- name: PlaybookContainedIssuer :one
SELECT EXISTS (
    SELECT 1 FROM pc.grants g
    JOIN pc.containment_controls c ON c.org_id = g.org_id AND c.scope_type = 'principal'
        AND c.scope_id = 'user:' || g.grantor_id::text AND c.control = 'DENY_ALL' AND c.lifted_at IS NULL
        AND (c.expires_at IS NULL OR c.expires_at > now())
    JOIN pc.response_actions a ON a.org_id = c.org_id AND a.id = c.action_id AND a.source = 'PLAYBOOK'
    WHERE g.org_id = sqlc.arg(org_id) AND g.id = sqlc.arg(grant_id) AND g.grantor_kind = 'user'
)::boolean AS contained;
