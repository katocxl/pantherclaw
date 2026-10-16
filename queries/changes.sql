-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- The generic M11 BINDING ceremony (G0 M11 part 2 D6): change requests,
-- their confirmations and the WebAuthn ceremonies that confirm them.

-- name: InsertChangeRequest :exec
INSERT INTO pc.change_requests (org_id, id, domain, kind, subject_id, content_digest, binding, summary, required,
    requested_by, expires_at)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(domain), sqlc.arg(kind), sqlc.arg(subject_id), sqlc.arg(content_digest),
        sqlc.arg(binding), sqlc.arg(summary), sqlc.arg(required), sqlc.arg(requested_by),
        now() + make_interval(secs => sqlc.arg(ttl_seconds)::int));

-- name: GetChangeRequest :one
SELECT r.org_id, r.id, r.domain, r.kind, r.subject_id, r.content_digest, r.binding, r.summary, r.required, r.state,
       r.requested_by, r.created_at, r.expires_at, r.decided_at, r.decided_reason, (r.expires_at <= now())::bool AS expired
FROM pc.change_requests r
WHERE r.org_id = sqlc.arg(org_id) AND r.id = sqlc.arg(id);

-- name: LockChangeRequest :one
SELECT r.org_id, r.id, r.domain, r.kind, r.subject_id, r.content_digest, r.binding, r.summary, r.required, r.state,
       r.requested_by, r.created_at, r.expires_at, r.decided_at, r.decided_reason, (r.expires_at <= now())::bool AS expired
FROM pc.change_requests r
WHERE r.org_id = sqlc.arg(org_id) AND r.id = sqlc.arg(id)
FOR UPDATE;

-- name: ListChangeRequests :many
-- Newest first; domain, states and subject filter when set.
SELECT r.org_id, r.id, r.domain, r.kind, r.subject_id, r.content_digest, r.binding, r.summary, r.required, r.state,
       r.requested_by, r.created_at, r.expires_at, r.decided_at, r.decided_reason, (r.expires_at <= now())::bool AS expired
FROM pc.change_requests r
WHERE r.org_id = sqlc.arg(org_id)
  AND (sqlc.narg(domain)::text IS NULL OR r.domain = sqlc.narg(domain)::text)
  AND (sqlc.narg(subject_id)::uuid IS NULL OR r.subject_id = sqlc.narg(subject_id)::uuid)
  AND (cardinality(sqlc.arg(states)::text[]) = 0 OR r.state = ANY (sqlc.arg(states)::text[]))
  AND (sqlc.narg(before_id)::uuid IS NULL OR r.id < sqlc.narg(before_id)::uuid)
ORDER BY r.id DESC
LIMIT sqlc.arg(max_rows)::int;

-- name: DecideChangeRequest :execrows
-- state: APPROVED, DECLINED, EXPIRED or VOIDED.
UPDATE pc.change_requests SET state = sqlc.arg(state), decided_at = now(), decided_reason = sqlc.narg(reason)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'PENDING';

-- name: VoidChangeRequests :many
-- New content or a new state of the subject voids its pending requests.
UPDATE pc.change_requests SET state = 'VOIDED', decided_at = now(), decided_reason = sqlc.arg(reason)
WHERE org_id = sqlc.arg(org_id) AND domain = sqlc.arg(domain) AND subject_id = sqlc.arg(subject_id) AND state = 'PENDING'
RETURNING id, kind;

-- name: VoidChangeRequestsConfirmedBy :many
-- A compromised person's pending requests (requested or confirmed by them).
UPDATE pc.change_requests r SET state = 'VOIDED', decided_at = now(), decided_reason = sqlc.arg(reason)
WHERE r.org_id = sqlc.arg(org_id) AND r.state = 'PENDING'
  AND (r.requested_by = sqlc.arg(requested_by)::text OR EXISTS (
        SELECT 1 FROM pc.change_confirmations c
        WHERE c.org_id = r.org_id AND c.request_id = r.id AND c.user_id = sqlc.arg(user_id)::uuid))
RETURNING r.id, r.domain, r.kind;

-- name: ExpireChangeRequests :many
UPDATE pc.change_requests SET state = 'EXPIRED', decided_at = now(), decided_reason = 'EXPIRED'
WHERE org_id = sqlc.arg(org_id) AND state = 'PENDING' AND expires_at <= now()
RETURNING id, domain, kind;

-- name: InsertChangeConfirmation :execrows
INSERT INTO pc.change_confirmations (org_id, request_id, user_id, credential_id)
VALUES (sqlc.arg(org_id), sqlc.arg(request_id), sqlc.arg(user_id), sqlc.arg(credential_id))
ON CONFLICT DO NOTHING;

-- name: ListChangeConfirmations :many
SELECT user_id, credential_id, confirmed_at FROM pc.change_confirmations
WHERE org_id = sqlc.arg(org_id) AND request_id = sqlc.arg(request_id)
ORDER BY confirmed_at;

-- name: ChangeRequestCeremony :one
SELECT challenge, (expires_at > now() AND consumed_at IS NULL)::bool AS live FROM pc.webauthn_ceremonies
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND purpose = 'BINDING'
  AND change_request_id = sqlc.arg(request_id) AND user_id = sqlc.arg(user_id) AND session_id = sqlc.arg(session_id);

-- name: ConsumeChangeRequestCeremony :execrows
UPDATE pc.webauthn_ceremonies SET consumed_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND purpose = 'BINDING'
  AND change_request_id = sqlc.arg(request_id) AND user_id = sqlc.arg(user_id)
  AND session_id = sqlc.arg(session_id) AND challenge = sqlc.arg(challenge) AND consumed_at IS NULL
  AND expires_at > now();
