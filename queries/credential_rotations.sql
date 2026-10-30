-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Target-confirmed rotation of a GitHub App key (G0 M20 S20c, D253,
-- HR-517..520). No query here returns sealed bytes; only the gateway's
-- rotation lease carries them (configuration.sql), to the gateway the
-- credential is bound to.

-- name: InsertCredentialRotation :one
INSERT INTO pc.credential_rotations (org_id, id, connection_id, old_credential_id, preview_digest, requested_by)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(connection_id), sqlc.arg(old_credential_id), sqlc.arg(preview_digest),
        sqlc.arg(requested_by))
RETURNING *;

-- name: GetCredentialRotation :one
SELECT * FROM pc.credential_rotations WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: LockCredentialRotation :one
SELECT * FROM pc.credential_rotations WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) FOR UPDATE;

-- name: OpenCredentialRotation :one
SELECT * FROM pc.credential_rotations
WHERE org_id = sqlc.arg(org_id) AND connection_id = sqlc.arg(connection_id)
  AND state NOT IN ('CONFIRMED', 'FAILED', 'ROLLED_BACK');

-- name: ListCredentialRotations :many
SELECT * FROM pc.credential_rotations
WHERE org_id = sqlc.arg(org_id) AND connection_id = sqlc.arg(connection_id)
ORDER BY created_at DESC
LIMIT 50;

-- ActiveCredential is a connection's ACTIVE credential, as metadata.
-- name: ActiveCredential :one
SELECT id, version, kind FROM pc.credentials
WHERE org_id = sqlc.arg(org_id) AND connection_id = sqlc.arg(connection_id) AND state = 'ACTIVE';

-- name: InsertCandidateCredential :one
INSERT INTO pc.credentials (org_id, id, connection_id, version, broker_key_id, sealed, allowed_hosts, header, scheme, created_by,
                            kind, state)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(connection_id), sqlc.arg(version), sqlc.arg(broker_key_id), sqlc.arg(sealed),
        sqlc.arg(allowed_hosts)::text[], sqlc.arg(header), sqlc.narg(scheme), sqlc.arg(created_by), sqlc.arg(kind), 'CANDIDATE')
RETURNING id, version, state, created_at;

-- name: SealRotationCandidate :execrows
UPDATE pc.credential_rotations SET state = 'CANDIDATE_SEALED', candidate_credential_id = sqlc.arg(candidate)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'REQUESTED';

-- name: StartRotationTest :execrows
UPDATE pc.credential_rotations SET state = 'TESTING', test_verification_id = sqlc.arg(task)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state IN ('CANDIDATE_SEALED', 'TESTING') AND test_passed_at IS NULL;

-- name: PassRotationTest :execrows
UPDATE pc.credential_rotations SET test_passed_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'TESTING' AND test_passed_at IS NULL;

-- name: FailCredentialRotation :execrows
UPDATE pc.credential_rotations SET state = 'FAILED', end_reason = sqlc.arg(reason), finished_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state IN ('REQUESTED', 'CANDIDATE_SEALED', 'TESTING');

-- ActivateCredentialRotation starts the rollback window by the database
-- clock (HR-519).
-- name: ActivateCredentialRotation :execrows
UPDATE pc.credential_rotations
SET state = 'ACTIVATING', activated_by = sqlc.arg(activated_by), activated_at = now(), rollback_until = now() + interval '24 hours'
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'TESTING' AND test_passed_at IS NOT NULL;

-- name: RollBackCredentialRotation :execrows
UPDATE pc.credential_rotations SET state = 'ROLLED_BACK', end_reason = sqlc.arg(reason), finished_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'ACTIVATING' AND rollback_until >= now();

-- AwaitOldRemoval closes the rollback window: from ACTIVATING (when it
-- passed, or when confirmation starts) or from CONFIRMING (GitHub did not
-- refuse the old key).
-- name: AwaitOldRemoval :execrows
UPDATE pc.credential_rotations
SET state = 'AWAITING_OLD_REMOVAL', awaiting_since = coalesce(awaiting_since, least(now(), rollback_until))
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state IN ('ACTIVATING', 'CONFIRMING');

-- CloseRollbackWindows moves the org's ACTIVATING rotations whose window
-- passed to AWAITING_OLD_REMOVAL, awaiting since the window's end.
-- name: CloseRollbackWindows :many
UPDATE pc.credential_rotations
SET state = 'AWAITING_OLD_REMOVAL', awaiting_since = rollback_until
WHERE org_id = sqlc.arg(org_id) AND state = 'ACTIVATING' AND rollback_until < now()
RETURNING id, connection_id;

-- name: StartRotationConfirm :execrows
UPDATE pc.credential_rotations SET state = 'CONFIRMING', confirm_verification_id = sqlc.arg(task)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'AWAITING_OLD_REMOVAL';

-- name: ConfirmCredentialRotation :execrows
UPDATE pc.credential_rotations SET state = 'CONFIRMED', confirmed_at = now(), finished_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'CONFIRMING';

-- Credential moves of a rotation; the state trigger of 00239 holds them
-- to the rotation's state.

-- name: ActivateCandidateCredential :execrows
UPDATE pc.credentials SET state = 'ACTIVE'
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'CANDIDATE';

-- name: SupersedeCredential :execrows
UPDATE pc.credentials SET state = 'SUPERSEDED', superseded_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'ACTIVE';

-- name: ReactivateCredential :execrows
UPDATE pc.credentials SET state = 'ACTIVE', superseded_at = NULL
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'SUPERSEDED';

-- name: RevokeCredentialByID :execrows
UPDATE pc.credentials SET state = 'REVOKED', superseded_at = NULL, revoked_by = sqlc.arg(revoked_by), revoked_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state <> 'REVOKED';

-- InsertRotationTask leases a rotation's test or confirmation to the
-- connection's gateway. Its request holds ids only, never sealed bytes
-- (HR-061): the claim attaches the sealed credential.
-- name: InsertRotationTask :exec
INSERT INTO pc.verifications (org_id, id, purpose, connection_id, operation, request, next_at, deadline_at)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(purpose), sqlc.arg(connection_id), sqlc.arg(operation), sqlc.arg(request), now(),
        now() + interval '15 minutes');

-- RotationOfTask is the rotation a claimed rotation task belongs to, with
-- the credential it tests or confirms.
-- name: RotationOfTask :one
SELECT r.id, r.state, r.connection_id, r.test_passed_at,
       CASE WHEN r.test_verification_id = sqlc.arg(task) THEN r.candidate_credential_id ELSE r.old_credential_id END::uuid AS credential_id,
       r.candidate_credential_id
FROM pc.credential_rotations r
WHERE r.org_id = sqlc.arg(org_id) AND (r.test_verification_id = sqlc.arg(task) OR r.confirm_verification_id = sqlc.arg(task));

-- LeasedRotationTask is a rotation task under a live lease of this
-- gateway (HR-190), locked with its rotation.
-- name: LeasedRotationTask :one
SELECT v.id, v.purpose, v.connection_id, r.id AS rotation_id, r.state AS rotation_state, r.old_credential_id,
       r.candidate_credential_id
FROM pc.verifications v
JOIN pc.credential_rotations r ON r.org_id = v.org_id
     AND ((v.purpose = 'credential_rotation_test' AND r.test_verification_id = v.id)
          OR (v.purpose = 'credential_rotation_confirm' AND r.confirm_verification_id = v.id))
WHERE v.org_id = sqlc.arg(org_id) AND v.id = sqlc.arg(id) AND v.state = 'LEASED' AND v.leased_by = sqlc.arg(gateway_id)
  AND v.lease_hash = sqlc.arg(lease_hash) AND v.lease_expires_at >= now()
FOR UPDATE OF v, r;

-- RotationTaskOpen reports whether a rotation task is still pending or
-- leased.
-- name: RotationTaskOpen :one
SELECT EXISTS (SELECT 1 FROM pc.verifications
               WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state IN ('PENDING', 'LEASED'));

-- UnconfirmedRotations are the org's activated, unconfirmed rotations and
-- since when each awaits the old key's removal: from awaiting_since, or,
-- for one still ACTIVATING, from its rollback window's end.
-- name: UnconfirmedRotations :many
SELECT r.id, r.connection_id, c.name AS connection_name,
       coalesce(r.awaiting_since, r.rollback_until)::timestamptz AS since
FROM pc.credential_rotations r
JOIN pc.connections c ON c.org_id = r.org_id AND c.id = r.connection_id
WHERE r.org_id = sqlc.arg(org_id) AND r.state IN ('ACTIVATING', 'AWAITING_OLD_REMOVAL', 'CONFIRMING')
ORDER BY r.id;

-- ConnectionInstallation is the GitHub App installation a connection's
-- credential is for: a candidate must be sealed for the same one.
-- name: ConnectionInstallation :one
SELECT app_client_id, installation_id, account_login FROM pc.connection_github
WHERE org_id = sqlc.arg(org_id) AND connection_id = sqlc.arg(connection_id);
