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
                                 actor, source, preview_digest, skip_preview, skip_reason, skip_step_up_at,
                                 idempotency_key, request_digest)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(kind), sqlc.arg(scope_type), sqlc.arg(scope_id),
        sqlc.narg(control), sqlc.narg(operation), sqlc.arg(reason), sqlc.narg(case_id), sqlc.narg(incident_id),
        sqlc.arg(actor), sqlc.arg(source), sqlc.narg(preview_digest), sqlc.arg(skip_preview), sqlc.narg(skip_reason),
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
