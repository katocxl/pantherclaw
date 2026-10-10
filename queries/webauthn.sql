-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- WebAuthn credentials, ceremonies and step-up (G0 M5 part 1, HR-153..156).
-- A ceremony is consumed once, by its own session and user, before it
-- expires (HR-004, HR-153). The signature counter only moves forward: the
-- conditional update in RecordAssertion is the second line behind the
-- application's check (HR-154).

-- name: ActiveCredentialsOfUser :many
SELECT id, credential_id, public_key, alg, sign_count, backup_eligible, backup_state, transports, aaguid, attestation_fmt
FROM pc.webauthn_credentials
WHERE org_id = sqlc.arg(org_id) AND user_id = sqlc.arg(user_id) AND state = 'ACTIVE'
ORDER BY created_at, id;

-- name: ListCredentialsOfUser :many
SELECT id, name, alg, backup_eligible, backup_state, transports, aaguid, state, state_reason, created_at, last_used_at,
       changed_at
FROM pc.webauthn_credentials
WHERE org_id = sqlc.arg(org_id) AND user_id = sqlc.arg(user_id)
ORDER BY created_at DESC, id DESC
LIMIT 100;

-- name: InsertCredential :exec
INSERT INTO pc.webauthn_credentials (org_id, id, user_id, credential_id, public_key, alg, sign_count, backup_eligible,
                                     backup_state, transports, aaguid, attestation_fmt, name)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(user_id), sqlc.arg(credential_id), sqlc.arg(public_key), sqlc.arg(alg),
        sqlc.arg(sign_count), sqlc.arg(backup_eligible), sqlc.arg(backup_state), sqlc.arg(transports), sqlc.narg(aaguid),
        sqlc.arg(attestation_fmt), sqlc.arg(name));

-- name: InsertCeremony :exec
INSERT INTO pc.webauthn_ceremonies (org_id, id, session_id, user_id, purpose, challenge, allowed_credentials, expires_at)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(session_id), sqlc.arg(user_id), sqlc.arg(purpose), sqlc.arg(challenge),
        sqlc.arg(allowed_credentials), now() + make_interval(secs => sqlc.arg(ttl_seconds)::int));

-- name: ConsumeCeremony :one
UPDATE pc.webauthn_ceremonies SET consumed_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND session_id = sqlc.arg(session_id) AND user_id = sqlc.arg(user_id)
  AND purpose = sqlc.arg(purpose) AND consumed_at IS NULL AND expires_at > now()
RETURNING challenge, allowed_credentials, expires_at;

-- name: RecordAssertion :execrows
UPDATE pc.webauthn_credentials
SET sign_count = sqlc.arg(sign_count), backup_state = sqlc.arg(backup_state), last_used_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'ACTIVE'
  AND ((sign_count = 0 AND sqlc.arg(sign_count) = 0) OR sign_count < sqlc.arg(sign_count));

-- name: SuspendCredential :execrows
UPDATE pc.webauthn_credentials
SET state = 'SUSPENDED', state_reason = 'CLONE_SUSPECTED', changed_at = now(), changed_by = sqlc.arg(changed_by)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'ACTIVE';

-- name: RemoveCredential :execrows
-- Removes one of a user's credentials (active or suspended).
UPDATE pc.webauthn_credentials
SET state = 'REMOVED', state_reason = sqlc.arg(reason), changed_at = now(), changed_by = sqlc.arg(changed_by)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND user_id = sqlc.arg(user_id) AND state <> 'REMOVED';

-- name: RenameCredential :execrows
UPDATE pc.webauthn_credentials SET name = sqlc.arg(name)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND user_id = sqlc.arg(user_id) AND state = 'ACTIVE';

-- name: CredentialOfUser :one
SELECT state, name FROM pc.webauthn_credentials
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND user_id = sqlc.arg(user_id);

-- name: RecordStepUp :execrows
UPDATE pc.sessions SET step_up_at = now(), step_up_credential_id = sqlc.arg(credential_id)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND user_id = sqlc.arg(user_id) AND state = 'ACTIVE';

-- An approval's BINDING ceremony (G0 M5 part 2, HR-033): its challenge is
-- the binding (or a batch's hash), bound to the browser session, the user
-- and the request or batch. A person's open ceremony for the same request
-- is replaced.
-- name: DeleteOpenBindingCeremonies :exec
DELETE FROM pc.webauthn_ceremonies
WHERE org_id = sqlc.arg(org_id) AND user_id = sqlc.arg(user_id) AND purpose = 'BINDING' AND consumed_at IS NULL
  AND (approval_request_id = sqlc.narg(approval_request_id)::uuid OR batch_id = sqlc.narg(batch_id)::uuid);

-- name: InsertBindingCeremony :exec
INSERT INTO pc.webauthn_ceremonies (org_id, id, session_id, user_id, purpose, challenge, allowed_credentials,
    approval_request_id, batch_id, expires_at)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(session_id), sqlc.arg(user_id), 'BINDING', sqlc.arg(challenge),
    sqlc.arg(allowed_credentials), sqlc.narg(approval_request_id), sqlc.narg(batch_id),
    now() + make_interval(secs => sqlc.arg(ttl_seconds)::int));

-- The approval page verifies an assertion against an open ceremony of this
-- session and user; the approval consumes it in the transaction that
-- records the response.
-- name: GetOpenBindingCeremony :one
SELECT challenge, allowed_credentials, expires_at, approval_request_id, batch_id FROM pc.webauthn_ceremonies
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND session_id = sqlc.arg(session_id) AND user_id = sqlc.arg(user_id)
  AND purpose = 'BINDING' AND consumed_at IS NULL AND expires_at > now();
