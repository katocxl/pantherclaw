-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Anchoring (G0 M7 design decision 12, HR-195). pc.anchors is the one
-- global table: the worker writes it in a global transaction for the
-- "anchors" purpose, and it holds only blinded leaves and the global root.
-- An org's own leaf, nonce and checkpoint stay in its anchor_leaves row,
-- written and read in that org's tenant transaction.

-- name: InsertAnchor :execrows
-- One anchor per period; a second worker for the same period inserts
-- nothing.
INSERT INTO pc.anchors (id, period, leaves, root, statement, signature, kid)
VALUES (sqlc.arg(id), sqlc.arg(period), sqlc.arg(leaves), sqlc.arg(root), sqlc.arg(statement), sqlc.arg(signature),
    sqlc.arg(kid))
ON CONFLICT (period) DO NOTHING;

-- name: GetAnchor :one
SELECT id, period, leaves, root, statement, signature, kid, state, attempts, next_at, error_code, rekor_entry,
       timestamp_token, created_at, anchored_at
FROM pc.anchors
WHERE id = sqlc.arg(id);

-- name: AnchorsDue :many
-- Anchors still to log and timestamp: pending, or failed with attempts left
-- and their backoff over.
SELECT id
FROM pc.anchors
WHERE state IN ('PENDING', 'FAILED') AND attempts < sqlc.arg(max_attempts) AND next_at <= now()
ORDER BY period
LIMIT sqlc.arg(max_rows);

-- name: KeepAnchorRekorEntry :execrows
-- The verified log entry is kept as soon as it verifies, so a retry after
-- a timestamp failure does not enter the statement again.
UPDATE pc.anchors
SET rekor_entry = sqlc.arg(rekor_entry)
WHERE id = sqlc.arg(id) AND state IN ('PENDING', 'FAILED') AND rekor_entry IS NULL;

-- name: MarkAnchorAnchored :execrows
-- HR-004: only a pending or failed anchor becomes anchored, once.
UPDATE pc.anchors
SET state = 'ANCHORED', rekor_entry = sqlc.arg(rekor_entry), timestamp_token = sqlc.arg(timestamp_token),
    anchored_at = now(), attempts = attempts + 1, error_code = NULL
WHERE id = sqlc.arg(id) AND state IN ('PENDING', 'FAILED') AND attempts = sqlc.arg(attempts);

-- name: MarkAnchorFailed :execrows
UPDATE pc.anchors
SET state = 'FAILED', attempts = attempts + 1, error_code = sqlc.arg(error_code)::text, next_at = sqlc.arg(next_at)
WHERE id = sqlc.arg(id) AND state IN ('PENDING', 'FAILED') AND attempts = sqlc.arg(attempts);

-- name: InsertAnchorLeaf :exec
INSERT INTO pc.anchor_leaves (org_id, anchor_id, leaf_index, nonce, checkpoint_size)
VALUES (sqlc.arg(org_id), sqlc.arg(anchor_id), sqlc.arg(leaf_index), sqlc.arg(nonce), sqlc.arg(checkpoint_size));

-- name: ListOrgAnchorsPage :many
-- The anchors that hold one of the org's checkpoints, newest period first.
SELECT a.id, a.period, a.state, a.root, a.kid, a.attempts, a.error_code, a.created_at, a.anchored_at,
       (octet_length(a.leaves) / 32)::integer AS leaf_count, l.leaf_index, l.checkpoint_size
FROM pc.anchor_leaves l
JOIN pc.anchors a ON a.id = l.anchor_id
WHERE l.org_id = sqlc.arg(org_id)
  AND (sqlc.narg(before_period)::timestamptz IS NULL OR a.period < sqlc.narg(before_period)::timestamptz)
ORDER BY a.period DESC
LIMIT sqlc.arg(page_limit);

-- name: LatestOrgAnchor :one
-- The org's newest anchored leaf with what a verify bundle needs: the
-- nonce, the anchor's leaves, statement, signature and both responses, and
-- the checkpoint the leaf commits to.
SELECT l.anchor_id, l.leaf_index, l.nonce, l.checkpoint_size, c.note, a.period, a.leaves, a.statement, a.signature,
       a.rekor_entry, a.timestamp_token
FROM pc.anchor_leaves l
JOIN pc.anchors a ON a.id = l.anchor_id
JOIN pc.checkpoints c ON c.org_id = l.org_id AND c.tree_size = l.checkpoint_size
WHERE l.org_id = sqlc.arg(org_id) AND a.state = 'ANCHORED' AND l.checkpoint_size <= sqlc.arg(max_size)
ORDER BY a.period DESC
LIMIT 1;
