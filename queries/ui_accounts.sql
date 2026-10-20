-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Hosted accounts (G0 UI D8; HR-348..353). The account tables are global:
-- these queries run only in the restricted global purpose "accounts". The
-- org-side queries (linking a user, recording terms) run in the org's
-- tenant transaction. Expiry uses the database clock.

-- name: UpsertAccount :one
-- One account per (issuer, subject); email and name are refreshed from the
-- ID token at each sign-in (HR-348: never matched by email).
INSERT INTO pc.accounts (id, issuer, subject, email, email_verified, display_name, last_sign_in_at)
VALUES (sqlc.arg(id), sqlc.arg(issuer), sqlc.arg(subject), sqlc.arg(email), sqlc.arg(email_verified), sqlc.arg(display_name), now())
ON CONFLICT (issuer, subject) DO UPDATE
SET email = EXCLUDED.email, email_verified = EXCLUDED.email_verified, display_name = EXCLUDED.display_name,
    last_sign_in_at = now()
RETURNING *;

-- name: GetAccount :one
SELECT * FROM pc.accounts WHERE id = sqlc.arg(id);

-- name: LockAccount :one
SELECT * FROM pc.accounts WHERE id = sqlc.arg(id) FOR UPDATE;

-- name: InsertAccountEvent :exec
INSERT INTO pc.account_events (account_id, kind, org_id, client_ip, detail)
VALUES (sqlc.arg(account_id), sqlc.arg(kind), sqlc.narg(org_id), sqlc.arg(client_ip), sqlc.arg(detail));

-- name: CountAccountEventsSince :one
SELECT count(*)::int FROM pc.account_events
WHERE account_id = sqlc.arg(account_id) AND kind = ANY(sqlc.arg(kinds)::text[])
  AND created_at > now() - make_interval(secs => sqlc.arg(window_seconds)::int);

-- name: CountIPEventsSince :one
SELECT count(*)::int FROM pc.account_events
WHERE client_ip = sqlc.arg(client_ip) AND kind = ANY(sqlc.arg(kinds)::text[])
  AND created_at > now() - make_interval(secs => sqlc.arg(window_seconds)::int);

-- name: AccountCreatedOrgs :many
SELECT org_id::uuid FROM pc.account_events
WHERE account_id = sqlc.arg(account_id) AND kind = 'ORG_CREATED' AND org_id IS NOT NULL
ORDER BY id;

-- name: InsertAccountLoginRequest :execrows
-- Creates a pending sign-in without an org unless max_open of them are
-- pending (unauthenticated requests create these rows).
INSERT INTO pc.account_login_requests (id, state_hash, binding_hash, nonce_hash, pkce_verifier, provider, next_path, max_age,
                                       requested_ip, expires_at, invitation_org_id, invitation_token_hash)
SELECT sqlc.arg(id)::uuid, sqlc.arg(state_hash)::bytea, sqlc.arg(binding_hash)::bytea, sqlc.arg(nonce_hash)::bytea,
       sqlc.arg(pkce_verifier)::text, sqlc.arg(provider)::text, sqlc.arg(next_path)::text, sqlc.narg(max_age)::int,
       sqlc.arg(requested_ip)::text, now() + make_interval(secs => sqlc.arg(ttl_seconds)::int),
       sqlc.narg(invitation_org_id)::uuid, sqlc.narg(invitation_token_hash)::bytea
WHERE (SELECT count(*) FROM pc.account_login_requests WHERE state = 'PENDING' AND expires_at > now()) < sqlc.arg(max_open)::int;

-- name: ConsumeAccountLoginState :one
UPDATE pc.account_login_requests r
SET state = 'CONSUMED', consumed_at = now(), state_hash = NULL, binding_hash = NULL, nonce_hash = NULL, pkce_verifier = NULL,
    invitation_org_id = NULL, invitation_token_hash = NULL
FROM (SELECT c.id, c.binding_hash, c.nonce_hash, c.pkce_verifier, c.provider, c.next_path, c.max_age, c.invitation_org_id,
             c.invitation_token_hash
      FROM pc.account_login_requests c
      WHERE c.state_hash = sqlc.arg(state_hash) AND c.state = 'PENDING' AND c.expires_at > now()
      FOR UPDATE) old
WHERE r.id = old.id
RETURNING old.id, old.binding_hash, old.nonce_hash, old.pkce_verifier, old.provider, old.next_path, old.max_age,
          old.invitation_org_id, old.invitation_token_hash;

-- name: InsertAccountSession :one
INSERT INTO pc.account_sessions (id, account_id, secret_hash, provider, auth_time, user_agent, client_ip, expires_at)
VALUES (sqlc.arg(id), sqlc.arg(account_id), sqlc.arg(secret_hash), sqlc.arg(provider), sqlc.narg(auth_time),
        sqlc.arg(user_agent), sqlc.arg(client_ip), now() + make_interval(secs => sqlc.arg(ttl_seconds)::int))
RETURNING created_at, expires_at;

-- name: AccountSessionBySecret :one
SELECT s.id, s.account_id, s.state, s.auth_time, s.provider, s.created_at,
       (s.secret_hash = sqlc.arg(secret_hash))::bool AS current,
       (s.rotated_at IS NOT NULL AND s.rotated_at > now() - make_interval(secs => sqlc.arg(grace_seconds)::int))::bool AS within_grace,
       (s.expires_at > now())::bool AS within_lifetime,
       (s.last_seen_at > now() - make_interval(secs => sqlc.arg(idle_seconds)::int))::bool AS within_idle,
       (s.last_seen_at < now() - interval '1 minute')::bool AS touch,
       a.email, a.email_verified, a.display_name, now()::timestamptz AS db_now
FROM pc.account_sessions s
JOIN pc.accounts a ON a.id = s.account_id
WHERE s.secret_hash = sqlc.arg(secret_hash) OR s.prev_secret_hash = sqlc.arg(secret_hash);

-- name: TouchAccountSession :exec
UPDATE pc.account_sessions SET last_seen_at = now() WHERE id = sqlc.arg(id) AND state = 'ACTIVE';

-- name: EndAccountSession :execrows
UPDATE pc.account_sessions SET state = 'ENDED', end_reason = sqlc.arg(reason), ended_at = now()
WHERE id = sqlc.arg(id) AND state = 'ACTIVE';

-- name: EndExcessAccountSessions :execrows
UPDATE pc.account_sessions t SET state = 'ENDED', end_reason = 'SESSION_LIMIT', ended_at = now()
WHERE t.state = 'ACTIVE' AND t.id IN (
    SELECT s.id FROM pc.account_sessions s
    WHERE s.account_id = sqlc.arg(account_id) AND s.state = 'ACTIVE'
    ORDER BY s.created_at DESC, s.id DESC
    OFFSET sqlc.arg(keep)::int);

-- name: DeleteOldAccountLoginRequests :execrows
DELETE FROM pc.account_login_requests WHERE expires_at < now() - interval '1 day';

-- name: DeleteOldAccountSessions :execrows
DELETE FROM pc.account_sessions WHERE ended_at < now() - interval '30 days' OR expires_at < now() - interval '30 days';

-- Org side, in the org's tenant transaction.

-- name: LinkUserAccount :execrows
-- Links a user to its account once (the trigger checks the identity).
UPDATE pc.users SET account_id = sqlc.arg(account_id)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND account_id IS NULL;

-- name: InsertAccountUser :one
INSERT INTO pc.users (org_id, id, issuer, subject, email, display_name, account_id, last_login_at)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(issuer), sqlc.arg(subject), sqlc.arg(email), sqlc.arg(display_name),
        sqlc.arg(account_id), now())
RETURNING *;

-- name: SetOrgSignup :exec
UPDATE pc.orgs SET slug = sqlc.arg(slug), created_by_account = sqlc.arg(account_id), updated_at = now()
WHERE id = sqlc.arg(org_id);

-- name: InsertTermsAcceptance :exec
INSERT INTO pc.org_terms_acceptances (org_id, id, account_id, user_id, terms_version, dpa_version, client_ip)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(account_id), sqlc.arg(user_id), sqlc.arg(terms_version),
        sqlc.arg(dpa_version), sqlc.arg(client_ip));

-- name: OrgSummary :one
SELECT id, name, coalesce(slug, '')::text AS slug, state FROM pc.orgs WHERE id = sqlc.arg(org_id);

-- name: LockInvitationByHash :one
SELECT *, (expires_at > now())::bool AS live FROM pc.invitations
WHERE org_id = sqlc.arg(org_id) AND token_hash = sqlc.arg(token_hash) FOR UPDATE;

-- name: AcceptInvitationInBrowser :execrows
UPDATE pc.invitations
SET state = 'ACCEPTED', accepted_at = now(), accepted_user_id = sqlc.arg(user_id), accepted_account_id = sqlc.arg(account_id),
    accepted_via = 'BROWSER'
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'PENDING' AND expires_at > now();

-- name: CountActiveMembers :one
SELECT count(*)::int FROM pc.users WHERE org_id = sqlc.arg(org_id) AND state = 'ACTIVE';

-- name: CountPendingMemberInvitations :one
SELECT count(*)::int FROM pc.invitations
WHERE org_id = sqlc.arg(org_id) AND state = 'PENDING' AND expires_at > now();
