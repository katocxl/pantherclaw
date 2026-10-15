-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Policy change requests (G0 M11.1 design decision 11, HR-231): a change
-- that loosens the published policy waits until enough people holding
-- policy.publish confirm it, each with a security key over the request's
-- binding. Every transition is conditional (HR-004) and expiry is the
-- database clock's.

-- name: InsertPolicyChangeRequest :exec
INSERT INTO pc.policy_change_requests (org_id, id, kind, subject_id, base_version_id, binding, summary, required,
    requested_by)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(kind), sqlc.arg(subject_id), sqlc.narg(base_version_id),
    sqlc.arg(binding), sqlc.arg(summary), sqlc.arg(required), sqlc.arg(requested_by));

-- GetPolicyChangeRequest is one request, with whether it is past its
-- expiry by the database clock.
-- name: GetPolicyChangeRequest :one
SELECT id, kind, subject_id, base_version_id, binding, summary, required, state, requested_by, created_at,
    expires_at, decided_at, decided_reason, (state = 'PENDING' AND expires_at <= now())::boolean AS expired
FROM pc.policy_change_requests
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- LockPolicyChangeRequest is GetPolicyChangeRequest, locked until the
-- transaction ends, so two confirmations are counted one after the other.
-- name: LockPolicyChangeRequest :one
SELECT id, kind, subject_id, base_version_id, binding, summary, required, state, requested_by, created_at,
    expires_at, decided_at, decided_reason, (state = 'PENDING' AND expires_at <= now())::boolean AS expired
FROM pc.policy_change_requests
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id)
FOR UPDATE;

-- PendingPolicyChangeRequest is the one pending request of a subject,
-- locked.
-- name: PendingPolicyChangeRequest :one
SELECT id, binding, base_version_id, (expires_at <= now())::boolean AS expired
FROM pc.policy_change_requests
WHERE org_id = sqlc.arg(org_id) AND kind = sqlc.arg(kind) AND subject_id = sqlc.arg(subject_id) AND state = 'PENDING'
FOR UPDATE;

-- ExpirePolicyChangeRequests marks the org's pending requests past their
-- expiry EXPIRED.
-- name: ExpirePolicyChangeRequests :execrows
UPDATE pc.policy_change_requests
SET state = 'EXPIRED', decided_at = now(), decided_reason = 'EXPIRED'
WHERE org_id = sqlc.arg(org_id) AND state = 'PENDING' AND expires_at <= now();

-- DecidePolicyChangeRequest ends a pending request once: APPROVED and
-- DECLINED only before its expiry, VOIDED at any time.
-- name: DecidePolicyChangeRequest :execrows
UPDATE pc.policy_change_requests
SET state = sqlc.arg(state)::text, decided_at = now(), decided_reason = sqlc.narg(reason)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'PENDING'
  AND sqlc.arg(state)::text IN ('APPROVED', 'DECLINED', 'VOIDED')
  AND (sqlc.arg(state)::text = 'VOIDED' OR expires_at > now());

-- name: ListPolicyChangeRequests :many
SELECT id, kind, subject_id, base_version_id, binding, summary, required, state, requested_by, created_at,
    expires_at, decided_at, decided_reason, (state = 'PENDING' AND expires_at <= now())::boolean AS expired
FROM pc.policy_change_requests
WHERE org_id = sqlc.arg(org_id) AND (sqlc.narg(state)::text IS NULL OR state = sqlc.narg(state)::text)
ORDER BY created_at DESC, id DESC
LIMIT sqlc.arg(max_rows);

-- name: InsertPolicyChangeConfirmation :exec
INSERT INTO pc.policy_change_confirmations (org_id, request_id, principal_id, credential_id)
VALUES (sqlc.arg(org_id), sqlc.arg(request_id), sqlc.arg(principal_id), sqlc.arg(credential_id));

-- name: ListPolicyChangeConfirmations :many
SELECT principal_id, credential_id, created_at
FROM pc.policy_change_confirmations
WHERE org_id = sqlc.arg(org_id) AND request_id = sqlc.arg(request_id)
ORDER BY created_at, principal_id;

-- PolicyChangeCeremony is the person's open BINDING ceremony for a change
-- request in this browser session, locked: what their key signed.
-- name: PolicyChangeCeremony :one
SELECT challenge, expires_at > now() AS live
FROM pc.webauthn_ceremonies
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND purpose = 'BINDING'
  AND policy_change_request_id = sqlc.arg(request_id) AND user_id = sqlc.arg(user_id)
  AND session_id = sqlc.arg(session_id) AND consumed_at IS NULL
FOR UPDATE;

-- ConsumePolicyChangeCeremony consumes the ceremony once, in the
-- transaction that records the confirmation (HR-033, HR-153, HR-004).
-- name: ConsumePolicyChangeCeremony :execrows
UPDATE pc.webauthn_ceremonies SET consumed_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND purpose = 'BINDING'
  AND policy_change_request_id = sqlc.arg(request_id) AND user_id = sqlc.arg(user_id)
  AND session_id = sqlc.arg(session_id) AND challenge = sqlc.arg(challenge) AND consumed_at IS NULL
  AND expires_at > now();
