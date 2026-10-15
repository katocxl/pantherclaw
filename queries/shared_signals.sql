-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Shared Signals receiver (G0 M10 D37; HR-261). Transmitters, verified
-- events and their replay keys.

-- name: InsertSSFTransmitter :exec
INSERT INTO pc.ssf_transmitters (org_id, id, name, issuer, jwks_uri, audience, created_by)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(name), sqlc.arg(issuer), sqlc.arg(jwks_uri), sqlc.arg(audience),
        sqlc.arg(created_by));

-- name: GetSSFTransmitter :one
SELECT id, name, issuer, jwks_uri, audience, state, created_by, created_at, activated_by, activated_at, updated_at,
       last_event_at, events_accepted, events_refused, last_refusal_at, last_refusal_code
FROM pc.ssf_transmitters
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: ListSSFTransmitters :many
SELECT id, name, issuer, jwks_uri, audience, state, created_by, created_at, activated_by, activated_at, updated_at,
       last_event_at, events_accepted, events_refused, last_refusal_at, last_refusal_code
FROM pc.ssf_transmitters
WHERE org_id = sqlc.arg(org_id) AND state <> 'DISABLED'
  AND (sqlc.narg(after_id)::uuid IS NULL OR id > sqlc.narg(after_id)::uuid)
ORDER BY id
LIMIT sqlc.arg(max_rows)::int;

-- name: ActivateSSFTransmitter :execrows
UPDATE pc.ssf_transmitters
SET state = 'ACTIVE', activated_by = sqlc.arg(activated_by), activated_credential = sqlc.arg(activated_credential),
    updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'PENDING';

-- name: SetSSFTransmitterState :execrows
UPDATE pc.ssf_transmitters SET state = sqlc.arg(state), updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = sqlc.arg(expected);

-- name: InsertSSFEvent :execrows
-- Zero rows: the jti was already received from this transmitter (replay).
INSERT INTO pc.ssf_events (org_id, id, transmitter_id, jti, event_type, issued_at, subject_format, user_id, match_basis,
                           outcome)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(transmitter_id), sqlc.arg(jti), sqlc.arg(event_type),
        sqlc.arg(issued_at), sqlc.narg(subject_format), sqlc.narg(user_id), sqlc.narg(match_basis), sqlc.arg(outcome))
ON CONFLICT (org_id, transmitter_id, jti) DO NOTHING;

-- name: SetSSFEventCase :execrows
UPDATE pc.ssf_events SET case_id = sqlc.arg(case_id)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND case_id IS NULL;

-- name: SSFAccepted :exec
UPDATE pc.ssf_transmitters SET last_event_at = now(), events_accepted = events_accepted + 1
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: SSFRefused :exec
UPDATE pc.ssf_transmitters
SET events_refused = events_refused + 1, last_refusal_at = now(), last_refusal_code = sqlc.arg(code)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: SSFUserByIssSub :many
-- Users are unique per (issuer, subject); at most one row.
SELECT id FROM pc.users
WHERE org_id = sqlc.arg(org_id) AND issuer = sqlc.arg(issuer) AND subject = sqlc.arg(subject) AND state = 'ACTIVE';

-- name: SSFUsersByEmail :many
-- Two rows mean the email is ambiguous and nothing matches.
SELECT id FROM pc.users
WHERE org_id = sqlc.arg(org_id) AND email = sqlc.arg(email) AND email <> '' AND state = 'ACTIVE'
ORDER BY id
LIMIT 2;

-- name: ListSSFEvents :many
SELECT id, transmitter_id, jti, event_type, issued_at, subject_format, user_id, match_basis, outcome, case_id, received_at
FROM pc.ssf_events
WHERE org_id = sqlc.arg(org_id) AND transmitter_id = sqlc.arg(transmitter_id)
ORDER BY received_at DESC
LIMIT 50;

-- name: DeleteExpiredSSFEvents :execrows
DELETE FROM pc.ssf_events WHERE org_id = sqlc.arg(org_id) AND expires_at <= now();

-- name: SetSSFEventCaseNote :execrows
UPDATE pc.ssf_events SET case_note = sqlc.arg(note)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND case_id IS NULL;

-- The grants a case about a person lists (D37, at most 100; the case says
-- how many there are): the active grants they issued or are the principal
-- of.
-- name: SSFPersonGrants :many
SELECT g.id, (g.grantor_kind = 'user' AND g.grantor_id = sqlc.arg(user_id))::bool AS issued
FROM pc.grants g
WHERE g.org_id = sqlc.arg(org_id) AND g.state = 'ACTIVE'
  AND ((g.grantor_kind = 'user' AND g.grantor_id = sqlc.arg(user_id)) OR g.principal_user_id = sqlc.arg(user_id))
ORDER BY g.id
LIMIT 100;

-- Identity playbook (D38).

-- name: GetIdentityPlaybook :one
SELECT enabled, events, version, request_id, updated_at FROM pc.identity_playbooks WHERE org_id = sqlc.arg(org_id);

-- name: EnsureIdentityPlaybook :exec
INSERT INTO pc.identity_playbooks (org_id) VALUES (sqlc.arg(org_id)) ON CONFLICT (org_id) DO NOTHING;

-- name: LockIdentityPlaybook :one
SELECT enabled, events, version FROM pc.identity_playbooks WHERE org_id = sqlc.arg(org_id) FOR UPDATE;

-- name: ApplyIdentityPlaybook :execrows
-- Only from the version the request was made against.
UPDATE pc.identity_playbooks
SET enabled = sqlc.arg(enabled), events = sqlc.arg(events), version = version + 1, request_id = sqlc.arg(request_id),
    updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND version = sqlc.arg(base_version);

-- name: InsertIdentityPlaybookRequest :exec
INSERT INTO pc.identity_playbook_requests (org_id, id, kind, events, base_version, binding, required, requested_by)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(kind), sqlc.arg(events), sqlc.arg(base_version), sqlc.arg(binding),
        sqlc.arg(required), sqlc.arg(requested_by));

-- name: GetIdentityPlaybookRequest :one
SELECT id, kind, events, base_version, binding, required, state, requested_by, created_at, expires_at, decided_at,
       decided_reason, (expires_at <= now())::bool AS expired
FROM pc.identity_playbook_requests
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: LockIdentityPlaybookRequest :one
SELECT id, kind, events, base_version, binding, required, state, requested_by, created_at, expires_at, decided_at,
       decided_reason, (expires_at <= now())::bool AS expired
FROM pc.identity_playbook_requests
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id)
FOR UPDATE;

-- name: ListIdentityPlaybookRequests :many
SELECT id, kind, events, base_version, binding, required, state, requested_by, created_at, expires_at, decided_at,
       decided_reason, (expires_at <= now())::bool AS expired
FROM pc.identity_playbook_requests
WHERE org_id = sqlc.arg(org_id)
ORDER BY created_at DESC
LIMIT 50;

-- name: DecideIdentityPlaybookRequest :execrows
UPDATE pc.identity_playbook_requests SET state = sqlc.arg(state), decided_at = now(), decided_reason = sqlc.narg(reason)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'PENDING';

-- name: ExpireIdentityPlaybookRequests :execrows
UPDATE pc.identity_playbook_requests SET state = 'EXPIRED', decided_at = now(), decided_reason = 'EXPIRED'
WHERE org_id = sqlc.arg(org_id) AND state = 'PENDING' AND expires_at <= now();

-- name: InsertIdentityPlaybookConfirmation :execrows
INSERT INTO pc.identity_playbook_confirmations (org_id, request_id, principal_id, credential_id)
VALUES (sqlc.arg(org_id), sqlc.arg(request_id), sqlc.arg(principal_id), sqlc.arg(credential_id))
ON CONFLICT DO NOTHING;

-- name: ListIdentityPlaybookConfirmations :many
SELECT principal_id, credential_id, created_at FROM pc.identity_playbook_confirmations
WHERE org_id = sqlc.arg(org_id) AND request_id = sqlc.arg(request_id)
ORDER BY created_at;

-- name: IdentityPlaybookCeremony :one
SELECT challenge, (expires_at > now() AND consumed_at IS NULL)::bool AS live FROM pc.webauthn_ceremonies
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND purpose = 'BINDING'
  AND identity_playbook_request_id = sqlc.arg(request_id) AND user_id = sqlc.arg(user_id) AND session_id = sqlc.arg(session_id);

-- name: ConsumeIdentityPlaybookCeremony :execrows
UPDATE pc.webauthn_ceremonies SET consumed_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND purpose = 'BINDING'
  AND identity_playbook_request_id = sqlc.arg(request_id) AND user_id = sqlc.arg(user_id)
  AND session_id = sqlc.arg(session_id) AND challenge = sqlc.arg(challenge) AND consumed_at IS NULL
  AND expires_at > now();

-- The playbook pages through every active grant the person issued and
-- every waiting approval of theirs, with no cap (D64).
-- name: SSFIssuedGrantsPage :many
SELECT g.id FROM pc.grants g
WHERE g.org_id = sqlc.arg(org_id) AND g.state = 'ACTIVE' AND g.grantor_kind = 'user' AND g.grantor_id = sqlc.arg(user_id)
  AND (sqlc.narg(after_id)::uuid IS NULL OR g.id > sqlc.narg(after_id)::uuid)
ORDER BY g.id
LIMIT sqlc.arg(max_rows)::int;

-- name: SSFPersonApprovalsPage :many
SELECT r.id FROM pc.approval_requests r
LEFT JOIN pc.grants g ON g.org_id = r.org_id AND g.id = r.grant_id
WHERE r.org_id = sqlc.arg(org_id) AND r.state IN ('PENDING', 'EVIDENCE_REQUESTED', 'APPROVED')
  AND (sqlc.narg(after_id)::uuid IS NULL OR r.id > sqlc.narg(after_id)::uuid)
  AND (r.requested_by = sqlc.arg(user_id)::uuid
       OR (g.grantor_kind = 'user' AND g.grantor_id = sqlc.arg(user_id)::uuid)
       OR g.principal_user_id = sqlc.arg(user_id)::uuid
       OR EXISTS (SELECT 1 FROM pc.approval_responses x
                  WHERE x.org_id = r.org_id AND x.request_id = r.id AND x.user_id = sqlc.arg(user_id)::uuid
                    AND x.kind IN ('APPROVE', 'STEP_UP') AND x.voided_at IS NULL))
ORDER BY r.id
LIMIT sqlc.arg(max_rows)::int;

-- name: SSFPersonCounts :one
-- How many grants and waiting approvals the person has, for the case.
SELECT
  (SELECT count(*) FROM pc.grants g WHERE g.org_id = sqlc.arg(org_id) AND g.state = 'ACTIVE'
     AND ((g.grantor_kind = 'user' AND g.grantor_id = sqlc.arg(user_id)::uuid) OR g.principal_user_id = sqlc.arg(user_id)::uuid))::int AS grants,
  (SELECT count(*) FROM pc.approval_requests r
     LEFT JOIN pc.grants g ON g.org_id = r.org_id AND g.id = r.grant_id
     WHERE r.org_id = sqlc.arg(org_id) AND r.state IN ('PENDING', 'EVIDENCE_REQUESTED', 'APPROVED')
       AND (r.requested_by = sqlc.arg(user_id)::uuid
            OR (g.grantor_kind = 'user' AND g.grantor_id = sqlc.arg(user_id)::uuid)
            OR g.principal_user_id = sqlc.arg(user_id)::uuid
            OR EXISTS (SELECT 1 FROM pc.approval_responses x
                       WHERE x.org_id = r.org_id AND x.request_id = r.id AND x.user_id = sqlc.arg(user_id)::uuid
                         AND x.kind IN ('APPROVE', 'STEP_UP') AND x.voided_at IS NULL)))::int AS approvals;
