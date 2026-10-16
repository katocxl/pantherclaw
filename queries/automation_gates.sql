-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Automation gates (G0 M11 part 2 D25, D25a, D62; HR-281): approval
-- requests of subject kind AUTOMATION_GATE, requested by an automation for
-- one step of one execution.

-- name: InsertAutomationGateRequest :exec
INSERT INTO pc.approval_requests (org_id, id, subject_kind, agent_id, requested_by_automation, execution_id, step_id,
    operation, binding, binding_input, requirements, display, display_hash, deadline_at)
VALUES (sqlc.arg(org_id), sqlc.arg(id), 'AUTOMATION_GATE', sqlc.narg(agent_id), sqlc.arg(automation_id),
    sqlc.arg(execution_id), sqlc.arg(step_id), 'automation.gate', sqlc.arg(binding), sqlc.arg(binding_input),
    sqlc.arg(requirements), sqlc.arg(display), sqlc.arg(display_hash), sqlc.arg(deadline_at));

-- name: LiveAutomationGate :one
SELECT id, (convert_from(binding_input, 'UTF8')::jsonb ->> 'attempt')::int AS attempt FROM pc.approval_requests
WHERE org_id = sqlc.arg(org_id) AND execution_id = sqlc.arg(execution_id) AND step_id = sqlc.arg(step_id)
  AND subject_kind = 'AUTOMATION_GATE' AND state IN ('PENDING', 'EVIDENCE_REQUESTED', 'APPROVED');

-- name: AutomationGateState :one
SELECT r.state, r.subject_kind, r.deadline_at,
       coalesce((SELECT array_agg(DISTINCT x.user_id) FROM pc.approval_responses x
                 WHERE x.org_id = r.org_id AND x.request_id = r.id AND x.kind = 'APPROVE' AND x.voided_at IS NULL),
                '{}')::uuid[] AS approvers
FROM pc.approval_requests r
WHERE r.org_id = sqlc.arg(org_id) AND r.id = sqlc.arg(id);

-- name: ConsumeAutomationGate :execrows
UPDATE pc.approval_requests SET state = 'CONSUMED', consumed_at = now(), ended_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND subject_kind = 'AUTOMATION_GATE' AND state = 'APPROVED';

-- name: EndAutomationGate :execrows
-- Ends an open gate: EXPIRED at its deadline, INVALIDATED when its
-- execution ended.
UPDATE pc.approval_requests SET state = sqlc.arg(state), end_reason = sqlc.arg(reason), ended_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND subject_kind = 'AUTOMATION_GATE'
  AND state IN ('PENDING', 'EVIDENCE_REQUESTED', 'APPROVED');

-- name: OpenAutomationGates :many
SELECT id FROM pc.approval_requests
WHERE org_id = sqlc.arg(org_id) AND execution_id = sqlc.arg(execution_id) AND subject_kind = 'AUTOMATION_GATE'
  AND state IN ('PENDING', 'EVIDENCE_REQUESTED', 'APPROVED');

-- name: GateCandidates :many
-- People holding a role at the org scope among roles (those holding
-- automation.approve), enabled; eligibility is then checked per person.
SELECT DISTINCT b.user_id::uuid AS user_id FROM pc.role_bindings b
JOIN pc.users u ON u.org_id = b.org_id AND u.id = b.user_id
WHERE b.org_id = sqlc.arg(org_id) AND b.scope_type = 'ORG' AND b.role = ANY (sqlc.arg(roles)::text[])
  AND b.user_id IS NOT NULL AND u.state = 'ACTIVE';
