-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

-- name: AccountIdentityShared :one
SELECT pc.identity_available(sqlc.arg(issuer)::text,sqlc.arg(subject)::text,true)::boolean;

-- name: AccountIdentityExclusive :exec
SELECT pg_advisory_xact_lock(('x' || left(encode(sha256(convert_to(octet_length(sqlc.arg(issuer)::text)::text || ':' || sqlc.arg(issuer)::text || sqlc.arg(subject)::text,'UTF8')),'hex'),16))::bit(64)::bigint);

-- name: StartAccountDeletion :exec
INSERT INTO pc.account_deletions(account_id,state) VALUES(sqlc.arg(account_id),'PREPARING')
ON CONFLICT(account_id) DO UPDATE SET state='PREPARING',journal_id=gen_random_uuid(),updated_at=now() WHERE pc.account_deletions.state='REFUSED';

-- name: AccountDeletion :one
SELECT * FROM pc.account_deletions WHERE account_id=sqlc.arg(account_id);

-- name: LockAccountDeletion :one
SELECT * FROM pc.account_deletions WHERE account_id=sqlc.arg(account_id) FOR UPDATE;

-- name: ShareAccountDeletion :one
SELECT state FROM pc.account_deletions WHERE account_id=sqlc.arg(account_id) FOR SHARE;

-- name: PendingAccountDeletions :many
SELECT account_id FROM pc.account_deletions WHERE state IN ('PREPARING','ROLLING_BACK','INTENT_PENDING','DELETING') OR (state='DONE' AND NOT event_recorded)
ORDER BY account_id LIMIT 100;

-- name: SetAccountDeletionState :exec
UPDATE pc.account_deletions SET state=sqlc.arg(state),updated_at=now() WHERE account_id=sqlc.arg(account_id) AND state=sqlc.arg(expected);

-- name: SetAccountDeletionDigest :exec
UPDATE pc.account_deletions SET record_digest=sqlc.arg(record_digest),updated_at=now() WHERE account_id=sqlc.arg(account_id);

-- name: AccountDeletionEventRecorded :exec
UPDATE pc.account_deletions SET event_recorded=true WHERE account_id=sqlc.arg(account_id) AND state='DONE';

-- name: BlockAccountIdentity :exec
INSERT INTO pc.identity_deletion_guards(identity_hash,state)
VALUES(sha256(convert_to(octet_length(sqlc.arg(issuer)::text)::text || ':' || sqlc.arg(issuer)::text || sqlc.arg(subject)::text,'UTF8')),sqlc.arg(state))
ON CONFLICT(identity_hash) DO UPDATE SET state=EXCLUDED.state;

-- name: UnblockAccountIdentity :exec
DELETE FROM pc.identity_deletion_guards WHERE identity_hash=sha256(convert_to(octet_length(sqlc.arg(issuer)::text)::text || ':' || sqlc.arg(issuer)::text || sqlc.arg(subject)::text,'UTF8'));

-- name: ReserveAccountUser :exec
INSERT INTO pc.account_deletion_steps(org_id,id,user_id,state) VALUES(sqlc.arg(org_id),sqlc.arg(account_id),sqlc.arg(user_id),'PREPARED') ON CONFLICT(org_id,id) DO NOTHING;

-- name: AccountUserDeletionStep :one
SELECT * FROM pc.account_deletion_steps WHERE org_id=sqlc.arg(org_id) AND id=sqlc.arg(account_id);

-- name: RemoveAccountUserReservation :exec
DELETE FROM pc.account_deletion_steps WHERE org_id=sqlc.arg(org_id) AND id=sqlc.arg(account_id) AND state='PREPARED';

-- name: MarkAccountUserDeleted :exec
UPDATE pc.account_deletion_steps SET state='DELETED' WHERE org_id=sqlc.arg(org_id) AND id=sqlc.arg(account_id);

-- name: PseudonymiseAccountUser :exec
UPDATE pc.users SET state='DISABLED',issuer='deleted',subject=sqlc.arg(tombstone),email='',display_name='deleted user ' || left(id::text,8),updated_at=now()
WHERE org_id=sqlc.arg(org_id) AND id=sqlc.arg(user_id) AND issuer<>'deleted';

-- name: DisableDeletingAccountUser :exec
UPDATE pc.users SET state='DISABLED',account_id=coalesce(account_id,sqlc.arg(account_id)::uuid),updated_at=now()
WHERE org_id=sqlc.arg(org_id) AND id=sqlc.arg(user_id);

-- name: TombstoneAccount :exec
UPDATE pc.accounts SET deleted_at=now(),issuer='deleted',subject=sqlc.arg(tombstone),email='',display_name='',email_verified=false
WHERE id=sqlc.arg(account_id) AND deleted_at IS NULL;

-- name: EndDeletedAccountSessions :exec
UPDATE pc.account_sessions SET state='ENDED',end_reason=coalesce(end_reason,'REVOKED'),ended_at=coalesce(ended_at,now()),user_agent='',client_ip='' WHERE account_id=sqlc.arg(account_id);

-- name: ScrubDeletedAccountEvents :exec
UPDATE pc.account_events SET client_ip='' WHERE account_id=sqlc.arg(account_id);

-- name: SetDeletionReauthentication :exec
UPDATE pc.account_sessions SET deletion_reauthenticated_at=now() WHERE id=sqlc.arg(session_id) AND account_id=sqlc.arg(account_id) AND state='ACTIVE';

-- name: ConsumeDeletionReauthentication :execrows
UPDATE pc.account_sessions SET deletion_reauthenticated_at=NULL WHERE id=sqlc.arg(session_id) AND account_id=sqlc.arg(account_id)
AND state='ACTIVE' AND deletion_reauthenticated_at>now()-interval '5 minutes' AND expires_at>now();
