-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- The deployment-wide root log and its witnesses (G0 M35 D1041). Platform
-- tables: written in a global transaction for the "global_log" purpose.
-- Bundles read them inside an org's tenant transaction (they hold no
-- tenant data). Receipt co-signatures (D1042) are tenant rows.

-- name: LockGlobalLog :exec
-- One appender at a time.
SELECT pg_advisory_xact_lock(hashtextextended('pc.global_log', 0));

-- name: GlobalLogSize :one
SELECT coalesce(max(leaf_index) + 1, 0)::bigint AS size
FROM pc.global_log_leaves;

-- name: AnchorsNotInGlobalLog :many
-- The anchors whose global root is not a leaf yet, oldest period first.
SELECT a.id, a.root
FROM pc.anchors a
WHERE NOT EXISTS (SELECT 1 FROM pc.global_log_leaves g WHERE g.anchor_id = a.id)
ORDER BY a.period
LIMIT sqlc.arg(max_rows);

-- name: InsertGlobalLogLeaf :exec
INSERT INTO pc.global_log_leaves (leaf_index, anchor_id, root)
VALUES (sqlc.arg(leaf_index), sqlc.arg(anchor_id), sqlc.arg(root));

-- name: GlobalLogLeafOfAnchor :one
SELECT leaf_index, root
FROM pc.global_log_leaves
WHERE anchor_id = sqlc.arg(anchor_id);

-- name: ReadGlobalLogTile :one
-- The widest stored version of a tile.
SELECT hashes
FROM pc.global_log_tiles
WHERE level = sqlc.arg(level) AND tile_index = sqlc.arg(tile_index)
ORDER BY width DESC
LIMIT 1;

-- name: InsertGlobalLogTile :exec
INSERT INTO pc.global_log_tiles (level, tile_index, width, hashes)
VALUES (sqlc.arg(level), sqlc.arg(tile_index), sqlc.arg(width), sqlc.arg(hashes))
ON CONFLICT DO NOTHING;

-- name: LatestGlobalCheckpoint :one
SELECT tree_size, root_hash, note, kid, created_at
FROM pc.global_checkpoints
ORDER BY tree_size DESC
LIMIT 1;

-- name: GlobalCheckpointAt :one
SELECT tree_size, root_hash, note, kid, created_at
FROM pc.global_checkpoints
WHERE tree_size = sqlc.arg(tree_size);

-- name: InsertGlobalCheckpoint :exec
INSERT INTO pc.global_checkpoints (tree_size, root_hash, note, kid)
VALUES (sqlc.arg(tree_size), sqlc.arg(root_hash), sqlc.arg(note), sqlc.arg(kid));

-- name: LastWitnessedSize :one
-- The newest checkpoint size the witness cosigned (no row: none).
SELECT tree_size
FROM pc.global_checkpoint_cosignatures
WHERE witness = sqlc.arg(witness)
ORDER BY tree_size DESC
LIMIT 1;

-- name: InsertGlobalCosignature :exec
INSERT INTO pc.global_checkpoint_cosignatures (tree_size, witness, key_id, signed_at, line)
VALUES (sqlc.arg(tree_size), sqlc.arg(witness), sqlc.arg(key_id), sqlc.arg(signed_at), sqlc.arg(line))
ON CONFLICT (tree_size, witness) DO NOTHING;

-- name: GlobalCosignatures :many
SELECT witness, key_id, signed_at, line
FROM pc.global_checkpoint_cosignatures
WHERE tree_size = sqlc.arg(tree_size)
ORDER BY witness;

-- name: InsertReceiptSignatures :exec
INSERT INTO pc.receipt_signatures (org_id, receipt_sha256, sigs)
VALUES (sqlc.arg(org_id), sqlc.arg(receipt_sha256), sqlc.arg(sigs))
ON CONFLICT (org_id, receipt_sha256) DO NOTHING;

-- name: ReceiptSignatures :many
SELECT receipt_sha256, sigs
FROM pc.receipt_signatures
WHERE org_id = sqlc.arg(org_id) AND receipt_sha256 = ANY (sqlc.arg(digests)::bytea[]);
