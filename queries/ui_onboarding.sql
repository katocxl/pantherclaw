-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Onboarding progress (G0 UI D15; HR-362..364): each step's first record,
-- read in the caller's org's tenant transaction (HR-363). Simulated
-- records — range agents and simulated transactions — never count
-- (HR-364, F630). A step done from a real record stays done (D98): each
-- query reads a record that later changes do not take away — a removed
-- key, a revoked instance or an executed held action still count.

-- name: OnboardingSecurityKey :one
SELECT id, created_at FROM pc.webauthn_credentials
WHERE org_id = sqlc.arg(org_id) AND user_id = sqlc.arg(user_id)
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
-- An instance admitted now, or one admitted before and revoked since (a
-- suspension revokes the agent's instances): its admission change, or a
-- real run it took part in.
SELECT e.agent_id, e.at FROM (
    SELECT i.agent_id, coalesce(i.decided_at, i.created_at)::timestamptz AS at, i.id AS ref FROM pc.agent_instances i
    WHERE i.org_id = sqlc.arg(org_id) AND i.state = 'ADMITTED'
    UNION ALL
    SELECT c.agent_id, c.created_at, c.id FROM pc.agent_changes c
    WHERE c.org_id = sqlc.arg(org_id) AND c.kind = 'instance.admitted'
    UNION ALL
    SELECT r.agent_id, r.created_at, r.id FROM pc.runs r
    WHERE r.org_id = sqlc.arg(org_id) AND r.instance_id IS NOT NULL AND NOT r.simulated
) e
JOIN pc.agents a ON a.org_id = sqlc.arg(org_id) AND a.id = e.agent_id
WHERE NOT a.range_agent
ORDER BY e.at, e.ref LIMIT 1;

-- name: OnboardingDecision :one
-- The first real decision of any of the given kinds. With unheld, an
-- action that was held for approval never counts: an approved hold that
-- became ALLOW, or a declined one that became DENY, is the held test, not
-- the allowed or denied one (D98).
SELECT t.id, t.created_at FROM pc.transactions t
JOIN pc.runs r ON r.org_id = t.org_id AND r.id = t.run_id
JOIN pc.agents a ON a.org_id = r.org_id AND a.id = r.agent_id
WHERE t.org_id = sqlc.arg(org_id) AND NOT t.simulated AND NOT r.simulated AND NOT a.range_agent
  AND t.decision = ANY(sqlc.arg(decisions)::text[])
  AND (NOT sqlc.arg(unheld)::boolean OR NOT EXISTS (
      SELECT 1 FROM pc.approval_requests q
      WHERE q.org_id = t.org_id AND q.transaction_id = t.id AND q.subject_kind = 'ACTION'))
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
-- An agent was suspended (D97(2)); restoring it is an optional follow-up.
SELECT s.agent_id, s.created_at, s.id AS suspension_id
FROM pc.agent_changes s
JOIN pc.agents a ON a.org_id = s.org_id AND a.id = s.agent_id
WHERE s.org_id = sqlc.arg(org_id) AND s.kind = 'agent.suspended' AND NOT a.range_agent
ORDER BY s.created_at, s.id LIMIT 1;

-- name: OnboardingHeld :one
-- The first real action held for approval: its approval request, which
-- stays whatever happens to the action afterwards (approved and executed,
-- declined, expired), and the transaction it holds (D98).
SELECT t.id, q.created_at, q.id AS request_id
FROM pc.approval_requests q
JOIN pc.transactions t ON t.org_id = q.org_id AND t.id = q.transaction_id
JOIN pc.runs r ON r.org_id = t.org_id AND r.id = t.run_id
JOIN pc.agents a ON a.org_id = r.org_id AND a.id = r.agent_id
WHERE q.org_id = sqlc.arg(org_id) AND q.subject_kind = 'ACTION'
  AND NOT t.simulated AND NOT r.simulated AND NOT a.range_agent
ORDER BY q.created_at, q.id LIMIT 1;
