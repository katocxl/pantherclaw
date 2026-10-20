-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- CLI device login and sessions (ADR-0016). Every transition is
-- conditional on the current state and on expiry by the database clock
-- (HR-004). The OAuth state is single use: ConsumeDeviceState clears it, the
-- browser binding, the nonce and the PKCE verifier in the same statement that
-- reads them.

-- name: InsertDeviceCode :one
INSERT INTO pc.device_codes (org_id, id, code_hash, user_code, device_jkt, device_jwk, device_name, requested_ip,
                             invitation_id, provider, expires_at)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(code_hash), sqlc.arg(user_code), sqlc.arg(device_jkt), sqlc.arg(device_jwk),
        sqlc.arg(device_name), sqlc.arg(requested_ip), sqlc.narg(invitation_id), sqlc.arg(provider),
        now() + make_interval(secs => sqlc.arg(ttl_seconds)::int))
-- A user-code collision among open codes must not abort the transaction:
-- skip the row (no RETURNING row) and let the caller draw another code.
-- Only the open-user-code index is an arbiter: any other conflict is an error.
ON CONFLICT (org_id, user_code) WHERE state IN ('PENDING', 'AUTHORIZING') DO NOTHING
RETURNING created_at, expires_at;

-- name: PendingInvitationByHash :one
SELECT id FROM pc.invitations
WHERE org_id = sqlc.arg(org_id) AND token_hash = sqlc.arg(token_hash) AND state = 'PENDING' AND expires_at > now();

-- name: OpenDeviceCodeByUserCode :one
SELECT id, device_name, requested_ip, provider, created_at, expires_at, invitation_id
FROM pc.device_codes
WHERE org_id = sqlc.arg(org_id) AND user_code = sqlc.arg(user_code) AND state IN ('PENDING', 'AUTHORIZING')
  AND expires_at > now();

-- name: AuthorizeDeviceCode :execrows
UPDATE pc.device_codes
SET state = 'AUTHORIZING', oauth_state_hash = sqlc.arg(oauth_state_hash), binding_hash = sqlc.arg(binding_hash),
    nonce = sqlc.arg(nonce), pkce_verifier = sqlc.arg(pkce_verifier), attempts = attempts + 1
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state IN ('PENDING', 'AUTHORIZING')
  AND expires_at > now() AND attempts < 5;

-- name: ConsumeDeviceState :one
UPDATE pc.device_codes d
SET oauth_state_hash = NULL, binding_hash = NULL, nonce = NULL, pkce_verifier = NULL
FROM (SELECT c.id, c.binding_hash, c.nonce, c.pkce_verifier, c.provider, c.invitation_id
      FROM pc.device_codes c
      WHERE c.org_id = sqlc.arg(org_id) AND c.oauth_state_hash = sqlc.arg(oauth_state_hash) AND c.state = 'AUTHORIZING'
        AND c.expires_at > now()
      FOR UPDATE) old
WHERE d.org_id = sqlc.arg(org_id) AND d.id = old.id
RETURNING old.id, old.binding_hash, old.nonce, old.pkce_verifier, old.provider, old.invitation_id;

-- name: ApproveDeviceCode :execrows
UPDATE pc.device_codes SET state = 'APPROVED', user_id = sqlc.arg(user_id), approved_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'AUTHORIZING' AND expires_at > now();

-- name: DenyDeviceCode :execrows
UPDATE pc.device_codes SET state = 'DENIED', deny_reason = sqlc.arg(reason),
    oauth_state_hash = NULL, binding_hash = NULL, nonce = NULL, pkce_verifier = NULL
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state IN ('PENDING', 'AUTHORIZING', 'APPROVED');

-- name: PollDeviceCode :one
UPDATE pc.device_codes d SET last_polled_at = now()
FROM (SELECT c.id, c.state, c.user_id, c.device_jkt, c.device_jwk, c.device_name, (c.expires_at > now())::bool AS live,
             (c.last_polled_at IS NOT NULL AND c.last_polled_at > now() - make_interval(secs => sqlc.arg(interval_seconds)::int))::bool AS too_fast
      FROM pc.device_codes c
      WHERE c.org_id = sqlc.arg(org_id) AND c.code_hash = sqlc.arg(code_hash)
      FOR UPDATE) old
WHERE d.org_id = sqlc.arg(org_id) AND d.id = old.id
RETURNING old.id, old.state, old.user_id, old.device_jkt, old.device_jwk, old.device_name, old.live, old.too_fast;

-- name: ConsumeDeviceCode :execrows
UPDATE pc.device_codes SET state = 'CONSUMED', consumed_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'APPROVED' AND expires_at > now();

-- name: UserByIdentity :one
SELECT * FROM pc.users WHERE org_id = sqlc.arg(org_id) AND issuer = sqlc.arg(issuer) AND subject = sqlc.arg(subject) FOR UPDATE;

-- name: RecordLogin :exec
UPDATE pc.users SET email = sqlc.arg(email), display_name = sqlc.arg(display_name), last_login_at = now(), updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: InsertUser :one
INSERT INTO pc.users (org_id, id, issuer, subject, email, display_name, last_login_at)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(issuer), sqlc.arg(subject), sqlc.arg(email), sqlc.arg(display_name), now())
RETURNING *;

-- name: LockInvitation :one
SELECT *, (expires_at > now())::bool AS live FROM pc.invitations WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) FOR UPDATE;

-- name: AcceptInvitation :execrows
UPDATE pc.invitations SET state = 'ACCEPTED', accepted_at = now(), accepted_user_id = sqlc.arg(user_id), accepted_via = 'CLI'
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'PENDING' AND expires_at > now();

-- name: InsertCLISession :one
INSERT INTO pc.cli_sessions (org_id, id, user_id, device_jkt, device_jwk, device_name, refresh_hash, expires_at)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(user_id), sqlc.arg(device_jkt), sqlc.arg(device_jwk), sqlc.arg(device_name),
        sqlc.arg(refresh_hash), now() + make_interval(secs => sqlc.arg(ttl_seconds)::int))
RETURNING expires_at;

-- name: SessionByRefresh :one
SELECT s.id, s.user_id, s.device_jkt, s.device_jwk, s.state, (s.expires_at > now())::bool AS live, u.state AS user_state
FROM pc.cli_sessions s
JOIN pc.users u ON u.org_id = s.org_id AND u.id = s.user_id
WHERE s.org_id = sqlc.arg(org_id) AND s.refresh_hash = sqlc.arg(refresh_hash)
FOR UPDATE OF s;

-- name: SessionByPreviousRefresh :one
SELECT id, user_id FROM pc.cli_sessions
WHERE org_id = sqlc.arg(org_id) AND prev_refresh_hash = sqlc.arg(refresh_hash) AND state = 'ACTIVE'
FOR UPDATE;

-- name: RotateRefresh :execrows
UPDATE pc.cli_sessions
SET prev_refresh_hash = refresh_hash, refresh_hash = sqlc.arg(new_hash), generation = generation + 1, refreshed_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND refresh_hash = sqlc.arg(old_hash) AND state = 'ACTIVE'
  AND expires_at > now();

-- name: RevokeSession :execrows
UPDATE pc.cli_sessions SET state = 'REVOKED', revoke_reason = sqlc.arg(reason), revoked_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'ACTIVE';
