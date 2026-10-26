-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Browser sign-in and browser sessions (G0 M5 part 1, HR-150, HR-152).
-- Every transition is conditional on the current state, and expiry is judged
-- by the database clock (HR-004). A sign-in state is single use:
-- ConsumeLoginState clears it, the browser binding, the nonce and the PKCE
-- verifier in the statement that reads them.

-- name: InsertLoginRequest :execrows
-- Creates a pending sign-in unless the org already has max_open of them
-- (unauthenticated requests create these rows, so their number is capped).
INSERT INTO pc.login_requests (org_id, id, state_hash, binding_hash, nonce, pkce_verifier, provider, next_path, max_age,
                               requested_ip, expires_at)
SELECT sqlc.arg(org_id)::uuid, sqlc.arg(id)::uuid, sqlc.arg(state_hash)::bytea, sqlc.arg(binding_hash)::bytea,
       sqlc.arg(nonce)::text, sqlc.arg(pkce_verifier)::text, sqlc.arg(provider)::text, sqlc.arg(next_path)::text,
       sqlc.narg(max_age)::int, sqlc.arg(requested_ip)::text, now() + make_interval(secs => sqlc.arg(ttl_seconds)::int)
WHERE (SELECT count(*) FROM pc.login_requests
       WHERE org_id = sqlc.arg(org_id)::uuid AND state = 'PENDING' AND expires_at > now()) < sqlc.arg(max_open)::int;

-- name: ConsumeLoginState :one
UPDATE pc.login_requests r
SET state = 'CONSUMED', consumed_at = now(), state_hash = NULL, binding_hash = NULL, nonce = NULL, pkce_verifier = NULL
FROM (SELECT c.id, c.binding_hash, c.nonce, c.pkce_verifier, c.provider, c.next_path, c.max_age
      FROM pc.login_requests c
      WHERE c.org_id = sqlc.arg(org_id) AND c.state_hash = sqlc.arg(state_hash) AND c.state = 'PENDING'
        AND c.expires_at > now()
      FOR UPDATE) old
WHERE r.org_id = sqlc.arg(org_id) AND r.id = old.id
RETURNING old.id, old.binding_hash, old.nonce, old.pkce_verifier, old.provider, old.next_path, old.max_age;

-- name: EndDeadBrowserSessions :exec
-- Ends a user's sessions that are past their idle or absolute limit.
UPDATE pc.sessions
SET state = 'ENDED', ended_at = now(), end_reason = CASE WHEN expires_at <= now() THEN 'EXPIRED' ELSE 'IDLE' END
WHERE org_id = sqlc.arg(org_id) AND user_id = sqlc.arg(user_id) AND state = 'ACTIVE'
  AND (expires_at <= now() OR last_seen_at <= now() - make_interval(secs => sqlc.arg(idle_seconds)::int));

-- name: EndExcessBrowserSessions :execrows
-- Ends a user's oldest active sessions so that at most keep remain.
UPDATE pc.sessions t SET state = 'ENDED', end_reason = 'SESSION_LIMIT', ended_at = now()
WHERE t.org_id = sqlc.arg(org_id) AND t.state = 'ACTIVE' AND t.id IN (
    SELECT s.id FROM pc.sessions s
    WHERE s.org_id = sqlc.arg(org_id) AND s.user_id = sqlc.arg(user_id) AND s.state = 'ACTIVE'
    ORDER BY s.created_at DESC, s.id DESC
    OFFSET sqlc.arg(keep)::int);

-- name: InsertBrowserSession :one
INSERT INTO pc.sessions (org_id, id, user_id, secret_hash, provider, auth_time, roles_digest, user_agent, client_ip,
                         expires_at)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(user_id), sqlc.arg(secret_hash), sqlc.arg(provider),
        sqlc.narg(auth_time), sqlc.arg(roles_digest), sqlc.arg(user_agent), sqlc.arg(client_ip),
        now() + make_interval(secs => sqlc.arg(ttl_seconds)::int))
RETURNING created_at, expires_at;

-- name: BrowserSessionBySecret :one
-- Finds the session whose current or previous secret has this hash, with
-- its limits judged by the database clock.
SELECT s.id, s.user_id, s.state, s.auth_time, s.roles_digest, s.step_up_at, s.step_up_credential_id,
       (s.secret_hash = sqlc.arg(secret_hash))::bool AS current,
       (s.rotated_at IS NOT NULL AND s.rotated_at > now() - make_interval(secs => sqlc.arg(grace_seconds)::int))::bool AS within_grace,
       (s.expires_at > now())::bool AS within_lifetime,
       (s.last_seen_at > now() - make_interval(secs => sqlc.arg(idle_seconds)::int))::bool AS within_idle,
       (s.last_seen_at < now() - interval '1 minute')::bool AS touch,
       u.state AS user_state, now()::timestamptz AS db_now
FROM pc.sessions s
JOIN pc.users u ON u.org_id = s.org_id AND u.id = s.user_id
WHERE s.org_id = sqlc.arg(org_id) AND (s.secret_hash = sqlc.arg(secret_hash) OR s.prev_secret_hash = sqlc.arg(secret_hash)) AND pc.identity_available(u.issuer,u.subject,false);

-- name: TouchBrowserSession :exec
UPDATE pc.sessions SET last_seen_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'ACTIVE';

-- name: RotateBrowserSession :execrows
-- Replaces the secret; the old one stays valid for the grace period only.
UPDATE pc.sessions
SET prev_secret_hash = secret_hash, rotated_at = now(), secret_hash = sqlc.arg(new_hash), generation = generation + 1,
    roles_digest = sqlc.arg(roles_digest), last_seen_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND secret_hash = sqlc.arg(old_hash) AND state = 'ACTIVE';

-- name: EndBrowserSession :execrows
UPDATE pc.sessions SET state = 'ENDED', end_reason = sqlc.arg(reason), ended_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'ACTIVE';

-- name: EndUserBrowserSession :execrows
-- Ends one session, only if it belongs to the user.
UPDATE pc.sessions SET state = 'ENDED', end_reason = sqlc.arg(reason), ended_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND user_id = sqlc.arg(user_id) AND state = 'ACTIVE';

-- name: UserBrowserSessionExists :one
SELECT EXISTS (SELECT 1 FROM pc.sessions WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND user_id = sqlc.arg(user_id))::bool;

-- name: ListUserBrowserSessions :many
SELECT id, provider, auth_time, step_up_at, user_agent, client_ip, state, end_reason, created_at, last_seen_at, expires_at,
       ended_at,
       (state = 'ACTIVE' AND expires_at > now()
        AND last_seen_at > now() - make_interval(secs => sqlc.arg(idle_seconds)::int))::bool AS live
FROM pc.sessions
WHERE org_id = sqlc.arg(org_id) AND user_id = sqlc.arg(user_id)
ORDER BY created_at DESC, id DESC
LIMIT 50;

-- Housekeeping (the authn janitor). Ceremonies go before the sessions they
-- reference.

-- name: DeleteOldLoginRequests :execrows
DELETE FROM pc.login_requests WHERE org_id = sqlc.arg(org_id) AND expires_at < now() - interval '1 day';

-- name: DeleteOldWebAuthnCeremonies :execrows
DELETE FROM pc.webauthn_ceremonies WHERE org_id = sqlc.arg(org_id) AND expires_at < now() - interval '1 day';

-- name: DeleteOldBrowserSessions :execrows
DELETE FROM pc.sessions s
WHERE s.org_id = sqlc.arg(org_id)
  AND (s.ended_at < now() - interval '30 days' OR s.expires_at < now() - interval '30 days')
  AND NOT EXISTS (SELECT 1 FROM pc.webauthn_ceremonies c WHERE c.org_id = s.org_id AND c.session_id = s.id);

-- Account administration (AccountService): a user's CLI sessions (M2's
-- cli_sessions) beside the browser ones, and ending all of them at once.

-- name: ListUserCLISessions :many
SELECT id, device_name, state, revoke_reason, created_at, refreshed_at, expires_at, revoked_at,
       (state = 'ACTIVE' AND expires_at > now())::bool AS live
FROM pc.cli_sessions
WHERE org_id = sqlc.arg(org_id) AND user_id = sqlc.arg(user_id)
ORDER BY created_at DESC, id DESC
LIMIT 50;

-- name: RevokeUserCLISession :execrows
UPDATE pc.cli_sessions SET state = 'REVOKED', revoke_reason = sqlc.arg(reason), revoked_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND user_id = sqlc.arg(user_id) AND state = 'ACTIVE';

-- name: UserCLISessionExists :one
SELECT EXISTS (SELECT 1 FROM pc.cli_sessions WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND user_id = sqlc.arg(user_id))::bool;

-- name: RevokeAllUserCLISessions :execrows
UPDATE pc.cli_sessions SET state = 'REVOKED', revoke_reason = sqlc.arg(reason), revoked_at = now()
WHERE org_id = sqlc.arg(org_id) AND user_id = sqlc.arg(user_id) AND state = 'ACTIVE';

-- name: EndAllUserBrowserSessions :execrows
UPDATE pc.sessions SET state = 'ENDED', end_reason = sqlc.arg(reason), ended_at = now()
WHERE org_id = sqlc.arg(org_id) AND user_id = sqlc.arg(user_id) AND state = 'ACTIVE';
