-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Agent payment trust anchors and the signature nonce cache (G0 M39
-- D1121, D1123; HR-831, HR-832, HR-838). Every state change is a
-- conditional update.

-- name: InsertPaymentTrustAnchor :exec
INSERT INTO pc.payment_trust_anchors (org_id, id, kind, name, jwks, url, sandbox, created_by)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(kind), sqlc.arg(name), sqlc.narg(jwks), sqlc.narg(url), sqlc.arg(sandbox),
        sqlc.arg(created_by));

-- name: GetPaymentTrustAnchor :one
SELECT id, kind, name, jwks, url, sandbox, state, created_by, created_at, activated_by, activated_at, revoked_at
FROM pc.payment_trust_anchors
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: ListPaymentTrustAnchors :many
SELECT id, kind, name, jwks, url, sandbox, state, created_by, created_at, activated_by, activated_at, revoked_at
FROM pc.payment_trust_anchors
WHERE org_id = sqlc.arg(org_id) AND state <> 'REVOKED'
  AND (sqlc.narg(after_id)::uuid IS NULL OR id > sqlc.narg(after_id)::uuid)
ORDER BY id
LIMIT sqlc.arg(max_rows)::int;

-- name: ListActivePaymentTrustAnchors :many
-- The anchors a verifier uses, by kind (D1122, D1123).
SELECT id, kind, name, jwks, url, sandbox, state, created_by, created_at, activated_by, activated_at, revoked_at
FROM pc.payment_trust_anchors
WHERE org_id = sqlc.arg(org_id) AND state = 'ACTIVE' AND kind = sqlc.arg(kind)
ORDER BY id
LIMIT 50;

-- name: ActivatePaymentTrustAnchor :execrows
-- A person with a fresh step-up activates a PENDING anchor (HR-832). The
-- guard sets activated_at by the database clock.
UPDATE pc.payment_trust_anchors
SET state = 'ACTIVE', activated_by = sqlc.arg(activated_by), activated_credential = sqlc.arg(activated_credential)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'PENDING';

-- name: RevokePaymentTrustAnchor :execrows
UPDATE pc.payment_trust_anchors SET state = 'REVOKED'
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state <> 'REVOKED';

-- name: PrunePaymentSigNonces :exec
-- Nonces are kept 10 minutes, longer than any signature's 480-second
-- window (HR-838).
DELETE FROM pc.payment_sig_nonces
WHERE org_id = sqlc.arg(org_id) AND seen_at < now() - interval '10 minutes';

-- name: UsePaymentSigNonce :execrows
-- 1 when the nonce is new for the anchor, 0 when it was seen (a replay).
INSERT INTO pc.payment_sig_nonces (org_id, anchor_id, nonce)
VALUES (sqlc.arg(org_id), sqlc.arg(anchor_id), sqlc.arg(nonce))
ON CONFLICT (org_id, anchor_id, nonce) DO NOTHING;
