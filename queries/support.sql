-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Customer-approved support access (G0 M13 D32, D38; HR-385..388), in the
-- customer org's tenant transaction.

-- name: InsertSupportRequest :one
INSERT INTO pc.support_access_requests (org_id, id, requester_account, requester_issuer, requester_subject, requester_email,
                                        requester_name, staff_org, staff_user, staff_credential, task, scope, duration_hours,
                                        expires_at)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(requester_account), sqlc.arg(requester_issuer), sqlc.arg(requester_subject),
        sqlc.arg(requester_email), sqlc.arg(requester_name), sqlc.arg(staff_org), sqlc.arg(staff_user),
        sqlc.arg(staff_credential), sqlc.arg(task), sqlc.arg(scope), sqlc.arg(duration_hours),
        now() + make_interval(secs => sqlc.arg(pending_seconds)::int))
RETURNING *;

-- name: GetSupportRequest :one
SELECT r.*, (r.state = 'PENDING' AND now() >= r.expires_at)::bool AS expired, g.id AS grant_id
FROM pc.support_access_requests r
LEFT JOIN pc.support_access_grants g ON g.org_id = r.org_id AND g.request_id = r.id
WHERE r.org_id = sqlc.arg(org_id) AND r.id = sqlc.arg(id);

-- name: LockSupportRequest :one
SELECT r.*, (now() >= r.expires_at)::bool AS past_expiry
FROM pc.support_access_requests r
WHERE r.org_id = sqlc.arg(org_id) AND r.id = sqlc.arg(id)
FOR UPDATE;

-- name: ListSupportRequests :many
-- Newest first; state filters on the effective state (EXPIRED is a
-- pending request past its expiry).
SELECT r.*, (r.state = 'PENDING' AND now() >= r.expires_at)::bool AS expired, g.id AS grant_id
FROM pc.support_access_requests r
LEFT JOIN pc.support_access_grants g ON g.org_id = r.org_id AND g.request_id = r.id
WHERE r.org_id = sqlc.arg(org_id)
  AND (sqlc.narg(state)::text IS NULL
       OR (sqlc.narg(state)::text = 'EXPIRED' AND r.state = 'PENDING' AND now() >= r.expires_at)
       OR (sqlc.narg(state)::text = 'PENDING' AND r.state = 'PENDING' AND now() < r.expires_at)
       OR (sqlc.narg(state)::text NOT IN ('EXPIRED', 'PENDING') AND r.state = sqlc.narg(state)::text))
  AND (sqlc.narg(before)::uuid IS NULL OR r.id < sqlc.narg(before)::uuid)
ORDER BY r.id DESC
LIMIT sqlc.arg(max_rows);

-- name: DecideSupportRequest :execrows
UPDATE pc.support_access_requests
SET state = sqlc.arg(state), decided_by = sqlc.arg(decided_by), decided_credential = sqlc.arg(decided_credential),
    decided_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'PENDING' AND now() < expires_at;

-- name: InsertSupportGrant :one
INSERT INTO pc.support_access_grants (org_id, id, request_id, account_id, scope, approved_by, approved_credential, expires_at)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(request_id), sqlc.arg(account_id), sqlc.arg(scope), sqlc.arg(approved_by),
        sqlc.arg(approved_credential), now() + make_interval(hours => sqlc.arg(duration_hours)::int))
RETURNING *;

-- name: GetSupportGrant :one
SELECT g.*, (SELECT count(*) FROM pc.support_sessions s WHERE s.org_id = g.org_id AND s.grant_id = g.id)::int AS sessions_opened,
       r.requester_email, r.requester_name, r.task, (now() >= g.expires_at)::bool AS expired
FROM pc.support_access_grants g
JOIN pc.support_access_requests r ON r.org_id = g.org_id AND r.id = g.request_id
WHERE g.org_id = sqlc.arg(org_id) AND g.id = sqlc.arg(id);

-- name: ListSupportGrants :many
SELECT g.*, (SELECT count(*) FROM pc.support_sessions s WHERE s.org_id = g.org_id AND s.grant_id = g.id)::int AS sessions_opened,
       r.requester_email, r.requester_name, r.task, (now() >= g.expires_at)::bool AS expired
FROM pc.support_access_grants g
JOIN pc.support_access_requests r ON r.org_id = g.org_id AND r.id = g.request_id
WHERE g.org_id = sqlc.arg(org_id)
  AND (NOT sqlc.arg(active_only)::bool OR (g.revoked_at IS NULL AND now() < g.expires_at))
  AND (sqlc.narg(before)::uuid IS NULL OR g.id < sqlc.narg(before)::uuid)
ORDER BY g.id DESC
LIMIT sqlc.arg(max_rows);

-- name: RevokeSupportGrant :execrows
UPDATE pc.support_access_grants
SET revoked_at = now(), revoked_by_type = sqlc.arg(revoked_by_type), revoked_by_id = sqlc.arg(revoked_by_id)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND revoked_at IS NULL;

-- name: EndSupportSessionsOfGrant :execrows
UPDATE pc.support_sessions
SET state = 'ENDED', end_reason = sqlc.arg(end_reason), ended_at = now()
WHERE org_id = sqlc.arg(org_id) AND grant_id = sqlc.arg(grant_id) AND state = 'ACTIVE';

-- name: LiveSupportGrantOfRequest :one
-- The grant of a request, for its requester, while it is in force.
SELECT g.*, r.requester_issuer, r.requester_subject
FROM pc.support_access_grants g
JOIN pc.support_access_requests r ON r.org_id = g.org_id AND r.id = g.request_id
WHERE g.org_id = sqlc.arg(org_id) AND g.request_id = sqlc.arg(request_id) AND g.account_id = sqlc.arg(account_id)
  AND g.revoked_at IS NULL AND now() >= g.starts_at AND now() < g.expires_at;

-- name: InsertSupportSession :one
INSERT INTO pc.support_sessions (org_id, id, grant_id, account_id, staff_credential, secret_hash, user_agent, client_ip,
                                 expires_at)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(grant_id), sqlc.arg(account_id), sqlc.arg(staff_credential),
        sqlc.arg(secret_hash), sqlc.arg(user_agent), sqlc.arg(client_ip),
        LEAST(sqlc.arg(grant_expires_at)::timestamptz, now() + make_interval(secs => sqlc.arg(max_seconds)::int)))
RETURNING *;

-- name: SupportSessionBySecret :one
-- A support session with its grant's and request's state, by the
-- database clock.
SELECT s.id, s.grant_id, s.account_id, s.state, s.expires_at, s.last_seen_at,
       (now() < s.expires_at)::bool AS within_lifetime,
       (now() < s.last_seen_at + make_interval(secs => sqlc.arg(idle_seconds)::int))::bool AS within_idle,
       (now() >= s.last_seen_at + interval '1 minute')::bool AS touch,
       g.scope, g.revoked_at, g.starts_at AS grant_starts_at, g.expires_at AS grant_expires_at,
       (g.revoked_at IS NULL AND now() >= g.starts_at AND now() < g.expires_at)::bool AS grant_live,
       r.requester_issuer, r.requester_subject, now()::timestamptz AS db_now
FROM pc.support_sessions s
JOIN pc.support_access_grants g ON g.org_id = s.org_id AND g.id = s.grant_id
JOIN pc.support_access_requests r ON r.org_id = g.org_id AND r.id = g.request_id
WHERE s.org_id = sqlc.arg(org_id) AND s.secret_hash = sqlc.arg(secret_hash);

-- name: EndSupportSession :execrows
UPDATE pc.support_sessions
SET state = 'ENDED', end_reason = sqlc.arg(end_reason), ended_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'ACTIVE';

-- name: TouchSupportSession :exec
UPDATE pc.support_sessions SET last_seen_at = now() WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'ACTIVE';

-- name: GetSupportSession :one
SELECT * FROM pc.support_sessions WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: LiveSupportScopesOfAccount :many
-- The scopes of the account's grants in force (tenancy Bindings).
SELECT DISTINCT g.scope
FROM pc.support_access_grants g
WHERE g.org_id = sqlc.arg(org_id) AND g.account_id = sqlc.arg(account_id) AND g.revoked_at IS NULL
  AND now() >= g.starts_at AND now() < g.expires_at;

-- name: UserIdentityForSupport :one
-- A staff org user's state, identity and linked account.
SELECT id, issuer, subject, email, display_name, state, account_id FROM pc.users
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);
