-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Evidence ledger queries. Every query runs inside db.InTenantTx and also
-- filters by org_id explicitly (tenancy twice, ARCHITECTURE §7). xid8 values
-- travel as text because pgx has no xid8 type.

-- name: InsertLedgerEntry :one
INSERT INTO pc.ledger_entries (org_id, id, kind, actor_type, actor_id, body)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(kind), sqlc.arg(actor_type), sqlc.arg(actor_id), sqlc.arg(body))
RETURNING occurred_at;

-- name: EnsureLedgerHead :exec
INSERT INTO pc.ledger_heads (org_id) VALUES (sqlc.arg(org_id))
ON CONFLICT (org_id) DO NOTHING;

-- name: LockLedgerHead :one
SELECT seq, head_hash, xid_watermark::text AS xid_watermark
FROM pc.ledger_heads
WHERE org_id = sqlc.arg(org_id)
FOR UPDATE;

-- name: CurrentXmin :one
SELECT pg_snapshot_xmin(pg_current_snapshot())::text AS xmin;

-- name: UnchainedLedgerEntries :many
SELECT e.id, e.kind, e.actor_type, e.actor_id, e.occurred_at, e.body
FROM pc.ledger_entries e
WHERE e.org_id = sqlc.arg(org_id)
  AND e.xid >= sqlc.arg(watermark)::text::xid8
  AND e.xid < sqlc.arg(xmin)::text::xid8
  AND NOT EXISTS (
      SELECT 1 FROM pc.ledger_chain c WHERE c.org_id = e.org_id AND c.entry_id = e.id
  )
ORDER BY e.xid, e.id
LIMIT sqlc.arg(max_rows);

-- name: InsertLedgerLink :exec
INSERT INTO pc.ledger_chain (org_id, seq, entry_id, prev_hash, entry_hash)
VALUES (sqlc.arg(org_id), sqlc.arg(seq), sqlc.arg(entry_id), sqlc.arg(prev_hash), sqlc.arg(entry_hash));

-- name: UpdateLedgerHead :exec
UPDATE pc.ledger_heads
SET seq = sqlc.arg(seq), head_hash = sqlc.arg(head_hash),
    xid_watermark = sqlc.arg(watermark)::text::xid8, updated_at = now()
WHERE org_id = sqlc.arg(org_id);

-- name: ChainedLedgerEntries :many
SELECT c.seq, c.prev_hash, c.entry_hash, e.id, e.kind, e.actor_type, e.actor_id, e.occurred_at, e.body, e.body_removed_at
FROM pc.ledger_chain c
JOIN pc.ledger_entries e ON e.org_id = c.org_id AND e.id = c.entry_id
WHERE c.org_id = sqlc.arg(org_id) AND c.seq > sqlc.arg(after_seq)
ORDER BY c.seq
LIMIT sqlc.arg(max_rows);

-- name: GetLedgerHead :one
SELECT seq, head_hash, xid_watermark::text AS xid_watermark
FROM pc.ledger_heads
WHERE org_id = sqlc.arg(org_id);
