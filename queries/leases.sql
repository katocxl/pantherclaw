-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Stream and wait leases (G0 M19 D201, HR-491), in the org's tenant
-- transaction. Lifetimes are on the database's clock, so every replica
-- agrees on which leases are live.

-- name: LockStreamLeaseKey :exec
-- Serializes the takers of one key until the transaction ends, so the
-- count and the insert below act as one.
SELECT pg_advisory_xact_lock(hashtextextended(
    'pc.stream_leases:' || sqlc.arg(org_id)::uuid::text || ':' || sqlc.arg(kind)::text || ':' || sqlc.arg(key)::text, 0));

-- name: DeleteExpiredStreamLeases :execrows
DELETE FROM pc.stream_leases WHERE org_id = sqlc.arg(org_id) AND expires_at <= now();

-- name: CountStreamLeases :one
SELECT count(*)::int FROM pc.stream_leases
WHERE org_id = sqlc.arg(org_id) AND kind = sqlc.arg(kind) AND key = sqlc.arg(key) AND expires_at > now();

-- name: InsertStreamLease :exec
INSERT INTO pc.stream_leases (org_id, kind, key, id, holder, expires_at)
VALUES (sqlc.arg(org_id), sqlc.arg(kind), sqlc.arg(key), sqlc.arg(id), sqlc.arg(holder),
        now() + make_interval(secs => sqlc.arg(ttl_seconds)::float8));

-- name: RenewStreamLease :execrows
-- A lease that already expired is not renewed: its slot may be taken.
UPDATE pc.stream_leases SET expires_at = now() + make_interval(secs => sqlc.arg(ttl_seconds)::float8)
WHERE org_id = sqlc.arg(org_id) AND kind = sqlc.arg(kind) AND key = sqlc.arg(key) AND id = sqlc.arg(id)
  AND expires_at > now();

-- name: DeleteStreamLease :exec
DELETE FROM pc.stream_leases
WHERE org_id = sqlc.arg(org_id) AND kind = sqlc.arg(kind) AND key = sqlc.arg(key) AND id = sqlc.arg(id);
