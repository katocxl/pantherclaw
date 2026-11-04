-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Owned account queries (G0 M30 D933, D935). Every query runs inside
-- db.InTenantTx and also filters by org_id explicitly.

-- name: ListOwnedAccounts :many
SELECT * FROM pc.owned_accounts
WHERE org_id = sqlc.arg(org_id)
ORDER BY kind, value;

-- name: OwnedAccountValues :many
-- The org's listed values of one kind, for the share step (D935).
SELECT value FROM pc.owned_accounts
WHERE org_id = sqlc.arg(org_id) AND kind = sqlc.arg(kind);

-- name: GetOwnedAccountByValue :one
SELECT * FROM pc.owned_accounts
WHERE org_id = sqlc.arg(org_id) AND kind = sqlc.arg(kind) AND value = sqlc.arg(value);

-- name: InsertOwnedAccount :one
INSERT INTO pc.owned_accounts (org_id, id, kind, value, added_by)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(kind), sqlc.arg(value), sqlc.arg(added_by))
RETURNING *;

-- name: DeleteOwnedAccount :one
DELETE FROM pc.owned_accounts
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id)
RETURNING *;
