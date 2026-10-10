-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Checkpoint queries (G0 M7 design decision 8, HR-194). Every query runs
-- inside db.InTenantTx and also filters by org_id explicitly.

-- name: ReadLedgerTile :one
-- The widest stored version of a tile.
SELECT hashes
FROM pc.ledger_tiles
WHERE org_id = sqlc.arg(org_id) AND level = sqlc.arg(level) AND tile_index = sqlc.arg(tile_index)
ORDER BY width DESC
LIMIT 1;

-- name: InsertLedgerTile :exec
INSERT INTO pc.ledger_tiles (org_id, level, tile_index, width, hashes)
VALUES (sqlc.arg(org_id), sqlc.arg(level), sqlc.arg(tile_index), sqlc.arg(width), sqlc.arg(hashes));

-- name: LedgerTileLeaves :one
-- How many leaves the level-0 tiles hold (no row: none).
SELECT (tile_index * 256 + width)::bigint AS leaves
FROM pc.ledger_tiles
WHERE org_id = sqlc.arg(org_id) AND level = 0
ORDER BY tile_index DESC, width DESC
LIMIT 1;

-- name: LatestCheckpoint :one
SELECT tree_size, root_hash, note, kid, pq_kid, created_at
FROM pc.checkpoints
WHERE org_id = sqlc.arg(org_id)
ORDER BY tree_size DESC
LIMIT 1;

-- name: InsertCheckpoint :exec
INSERT INTO pc.checkpoints (org_id, tree_size, root_hash, note, kid, pq_kid)
VALUES (sqlc.arg(org_id), sqlc.arg(tree_size), sqlc.arg(root_hash), sqlc.arg(note), sqlc.arg(kid), sqlc.narg(pq_kid));

-- name: LedgerEntryHashAt :one
SELECT entry_hash
FROM pc.ledger_chain
WHERE org_id = sqlc.arg(org_id) AND seq = sqlc.arg(seq);

-- name: ChainedLedgerRange :many
SELECT c.seq, c.prev_hash, c.entry_hash, e.id, e.kind, e.actor_type, e.actor_id, e.occurred_at, e.body,
       e.body_removed_at, e.removed_by_policy
FROM pc.ledger_chain c
JOIN pc.ledger_entries e ON e.org_id = c.org_id AND e.id = c.entry_id
WHERE c.org_id = sqlc.arg(org_id) AND c.seq > sqlc.arg(after_seq) AND c.seq <= sqlc.arg(upto_seq)
ORDER BY c.seq
LIMIT sqlc.arg(max_rows);

-- name: GetEvidenceIntegrity :one
SELECT state, failure_code, failed_seq, failed_at, verified_size, verified_at
FROM pc.evidence_integrity
WHERE org_id = sqlc.arg(org_id);

-- name: MarkEvidenceIntegrityFailed :execrows
-- Only the first failure counts; an org stays FAILED until an operator
-- investigates and resets it (ResetEvidenceIntegrity).
INSERT INTO pc.evidence_integrity (org_id, state, failure_code, failed_seq, failed_at, updated_at)
VALUES (sqlc.arg(org_id), 'FAILED', sqlc.arg(failure_code)::text, sqlc.narg(failed_seq)::bigint, now(), now())
ON CONFLICT (org_id) DO UPDATE
SET state = 'FAILED', failure_code = EXCLUDED.failure_code, failed_seq = EXCLUDED.failed_seq,
    failed_at = EXCLUDED.failed_at, updated_at = now()
WHERE pc.evidence_integrity.state = 'OK';

-- name: MarkEvidenceVerified :execrows
INSERT INTO pc.evidence_integrity (org_id, verified_size, verified_at, updated_at)
VALUES (sqlc.arg(org_id), sqlc.arg(verified_size)::bigint, now(), now())
ON CONFLICT (org_id) DO UPDATE
SET verified_size = EXCLUDED.verified_size, verified_at = EXCLUDED.verified_at, updated_at = now()
WHERE pc.evidence_integrity.state = 'OK';

-- name: ResetEvidenceIntegrity :one
-- An operator clears a FAILED status after investigating (HR-004: only a
-- FAILED row changes; no row means it was not FAILED). The last
-- verification goes too, so the daily job verifies the whole chain again
-- at its next dispatch. Returns the failure it cleared.
WITH old AS (
    SELECT f.org_id, f.failure_code, f.failed_seq, f.failed_at
    FROM pc.evidence_integrity AS f
    WHERE f.org_id = sqlc.arg(org_id) AND f.state = 'FAILED'
    FOR UPDATE
)
UPDATE pc.evidence_integrity AS i
SET state = 'OK', failure_code = NULL, failed_seq = NULL, failed_at = NULL,
    verified_size = NULL, verified_at = NULL, updated_at = now()
FROM old
WHERE i.org_id = old.org_id AND i.state = 'FAILED'
RETURNING old.failure_code, old.failed_seq, old.failed_at;
