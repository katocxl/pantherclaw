-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Onboarding progress (G0 UI D15; HR-362..364): each step's first record,
-- read in the caller's org's tenant transaction (HR-363). Simulated
-- records — range agents and simulated transactions — never count
-- (HR-364, F630).

-- name: OnboardingSecurityKey :one
SELECT id, created_at FROM pc.webauthn_credentials
WHERE org_id = sqlc.arg(org_id) AND user_id = sqlc.arg(user_id) AND state = 'ACTIVE'
ORDER BY created_at, id LIMIT 1;

-- name: OnboardingInvitation :one
SELECT id, created_at FROM pc.invitations
WHERE org_id = sqlc.arg(org_id) AND kind = 'MEMBER'
ORDER BY created_at, id LIMIT 1;

-- name: OnboardingGateway :one
SELECT c.gateway_id, c.issued_at FROM pc.gateway_certs c
WHERE c.org_id = sqlc.arg(org_id) AND c.issued_via = 'ENROLL'
ORDER BY c.issued_at, c.id LIMIT 1;

-- name: OnboardingAgentInstance :one
SELECT i.id, coalesce(i.decided_at, i.created_at)::timestamptz AS at FROM pc.agent_instances i
JOIN pc.agents a ON a.org_id = i.org_id AND a.id = i.agent_id
WHERE i.org_id = sqlc.arg(org_id) AND i.state = 'ADMITTED' AND NOT a.range_agent
ORDER BY 2, i.id LIMIT 1;

-- name: OnboardingDecision :one
-- The first real decision of any of the given kinds.
SELECT t.id, t.created_at FROM pc.transactions t
JOIN pc.runs r ON r.org_id = t.org_id AND r.id = t.run_id
JOIN pc.agents a ON a.org_id = r.org_id AND a.id = r.agent_id
WHERE t.org_id = sqlc.arg(org_id) AND NOT t.simulated AND NOT r.simulated AND NOT a.range_agent
  AND t.decision = ANY(sqlc.arg(decisions)::text[])
ORDER BY t.created_at, t.id LIMIT 1;

-- name: OnboardingApprovalDecided :one
-- A person's security-key decision of a held real action.
SELECT p.request_id, p.created_at FROM pc.approval_responses p
JOIN pc.approval_requests q ON q.org_id = p.org_id AND q.id = p.request_id
JOIN pc.transactions t ON t.org_id = q.org_id AND t.id = q.transaction_id
WHERE p.org_id = sqlc.arg(org_id) AND p.kind IN ('APPROVE', 'DECLINE') AND p.credential_id IS NOT NULL
  AND q.subject_kind = 'ACTION' AND NOT t.simulated
ORDER BY p.created_at, p.id LIMIT 1;

-- name: OnboardingSuspension :one
-- An agent restored after it was suspended.
SELECT r.agent_id, r.created_at FROM pc.agent_changes r
JOIN pc.agents a ON a.org_id = r.org_id AND a.id = r.agent_id
WHERE r.org_id = sqlc.arg(org_id) AND r.kind = 'agent.restored' AND NOT a.range_agent
  AND EXISTS (SELECT 1 FROM pc.agent_changes s WHERE s.org_id = r.org_id AND s.agent_id = r.agent_id
              AND s.kind = 'agent.suspended' AND s.created_at <= r.created_at)
ORDER BY r.created_at, r.id LIMIT 1;
