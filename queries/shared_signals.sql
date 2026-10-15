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
