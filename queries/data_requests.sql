-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Data requests: exports and deletion requests (G0 M13 D34, migrations
-- 00176-00177).

-- name: InsertDataRequest :exec
INSERT INTO pc.data_requests (org_id, id, kind, state, created_by, created_by_account, reason, window_end, lapsed_at,
                              admin_accounts)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(kind), sqlc.arg(state), sqlc.narg(created_by), sqlc.narg(created_by_account),
        sqlc.narg(reason), sqlc.narg(window_end), sqlc.narg(lapsed_at), sqlc.arg(admin_accounts)::uuid[]);

-- name: GetDataRequest :one
SELECT * FROM pc.data_requests WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: LockDataRequest :one
SELECT * FROM pc.data_requests WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) FOR UPDATE;

-- name: ListDataRequests :many
-- Newest first (ids are UUIDv7).
SELECT * FROM pc.data_requests
WHERE org_id = sqlc.arg(org_id)
  AND (coalesce(sqlc.arg(before)::uuid, '00000000-0000-0000-0000-000000000000') = '00000000-0000-0000-0000-000000000000'
       OR id < sqlc.arg(before)::uuid)
ORDER BY id DESC
LIMIT sqlc.arg(page_limit);

-- name: OpenDeletionRequest :one
SELECT * FROM pc.data_requests
WHERE org_id = sqlc.arg(org_id) AND kind = 'DELETION' AND state IN ('PENDING', 'HELD', 'DELETING');

-- name: SetDataRequestState :execrows
UPDATE pc.data_requests SET state = sqlc.arg(state), updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = sqlc.arg(from_state);

-- name: SetDeletionAdminAccounts :exec
UPDATE pc.data_requests SET admin_accounts = sqlc.arg(admin_accounts)::uuid[], updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: CancelDeletionRequest :execrows
UPDATE pc.data_requests SET state = 'CANCELED', canceled_by = sqlc.arg(canceled_by), canceled_at = now(), updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND kind = 'DELETION' AND state IN ('PENDING', 'HELD')
  AND window_end > now();

-- name: FailDataRequest :execrows
UPDATE pc.data_requests SET state = 'FAILED', error_code = sqlc.arg(error_code), updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state IN ('BUILDING', 'PENDING', 'HELD', 'DELETING');

-- name: MarkExportReady :execrows
UPDATE pc.data_requests
SET state = 'READY', ready_at = sqlc.arg(ready_at), expires_at = sqlc.arg(ready_at)::timestamptz + interval '7 days',
    parts = sqlc.arg(parts), total_size = sqlc.arg(total_size), manifest = sqlc.arg(manifest), updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'BUILDING';

-- name: InsertDataRequestPart :exec
INSERT INTO pc.data_request_parts (org_id, request_id, number, content, sha256)
VALUES (sqlc.arg(org_id), sqlc.arg(request_id), sqlc.arg(number), sqlc.arg(content), sqlc.arg(sha256));

-- name: DataRequestPartSizes :many
SELECT number, octet_length(content)::bigint AS size, sha256 FROM pc.data_request_parts
WHERE org_id = sqlc.arg(org_id) AND request_id = sqlc.arg(request_id)
ORDER BY number;

-- name: GetDataRequestPart :one
SELECT content, sha256 FROM pc.data_request_parts
WHERE org_id = sqlc.arg(org_id) AND request_id = sqlc.arg(request_id) AND number = sqlc.arg(number);

-- name: DeleteDataRequestParts :execrows
DELETE FROM pc.data_request_parts WHERE org_id = sqlc.arg(org_id) AND request_id = sqlc.arg(request_id);

-- name: ExpiredExports :many
SELECT id FROM pc.data_requests
WHERE org_id = sqlc.arg(org_id) AND kind = 'EXPORT' AND state = 'READY' AND expires_at <= now()
ORDER BY id
LIMIT 100;

-- name: ExpireExport :execrows
UPDATE pc.data_requests SET state = 'EXPIRED', updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'READY';

-- name: ActiveOrgLegalHold :one
SELECT EXISTS (SELECT 1 FROM pc.legal_holds
               WHERE org_id = sqlc.arg(org_id) AND scope = 'org' AND state = 'ACTIVE')::boolean;

-- name: AccountsOfUsers :many
SELECT DISTINCT account_id::uuid AS account_id FROM pc.users
WHERE org_id = sqlc.arg(org_id) AND id = ANY (sqlc.arg(users)::uuid[]) AND account_id IS NOT NULL
ORDER BY 1;

-- name: AccountOfUser :one
SELECT account_id FROM pc.users WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: LedgerHeadSeq :one
SELECT coalesce((SELECT seq FROM pc.ledger_heads WHERE org_id = sqlc.arg(org_id)), 0)::bigint;

-- name: LockOrgState :one
SELECT state FROM pc.orgs WHERE id = sqlc.arg(org_id) FOR UPDATE;

-- name: MarkOrgDeleted :execrows
UPDATE pc.orgs SET state = 'DELETED', updated_at = now() WHERE id = sqlc.arg(org_id) AND state <> 'DELETED';

-- name: OrgDeletedAt :one
SELECT state, deleted_at FROM pc.orgs WHERE id = sqlc.arg(org_id);

-- name: InsertDeletionRecord :exec
INSERT INTO pc.deletion_records (org_id, id, deleted_org_id, reason, requested_by_account, accounts, reapplied_from, record,
                                 signed_record)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(deleted_org_id), sqlc.arg(reason), sqlc.narg(requested_by_account),
        sqlc.arg(accounts)::uuid[], sqlc.narg(reapplied_from), sqlc.arg(record), sqlc.arg(signed_record));

-- name: LatestDeletionRecord :one
SELECT * FROM pc.deletion_records
WHERE org_id = sqlc.arg(org_id) AND deleted_org_id = sqlc.arg(deleted_org_id)
ORDER BY created_at DESC, id DESC
LIMIT 1;
