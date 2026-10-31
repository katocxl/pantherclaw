-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

-- name: ListSigningKeys :many
SELECT id, kid, purpose, algorithm, public_key, wrapped_private_key, kek_id, state
FROM pc.keys
WHERE org_id = sqlc.arg(org_id) AND state <> 'REVOKED'
ORDER BY created_at, kid;

-- name: InsertSigningKey :exec
INSERT INTO pc.keys (org_id, id, kid, purpose, algorithm, public_key, wrapped_private_key, kek_id, state)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(kid), sqlc.arg(purpose), sqlc.arg(algorithm), sqlc.arg(public_key),
        sqlc.arg(wrapped_private_key), sqlc.arg(kek_id), 'ACTIVE');

-- name: TransitionSigningKey :execresult
UPDATE pc.keys
SET state = sqlc.arg(to_state), state_changed_at = now()
WHERE org_id = sqlc.arg(org_id) AND kid = sqlc.arg(kid) AND state = sqlc.arg(from_state);

-- name: LockKeystore :exec
SELECT pg_advisory_xact_lock(hashtextextended('pc.keystore:' || sqlc.arg(org_id)::uuid::text, 0));

-- name: ActiveDEK :one
SELECT version, wrapped_key, kek_id
FROM pc.deks
WHERE org_id = sqlc.arg(org_id) AND purpose = sqlc.arg(purpose) AND state = 'ACTIVE';

-- name: GetDEK :one
SELECT wrapped_key, kek_id
FROM pc.deks
WHERE org_id = sqlc.arg(org_id) AND purpose = sqlc.arg(purpose) AND version = sqlc.arg(version);

-- name: NextDEKVersion :one
SELECT (coalesce(max(version), 0) + 1)::integer AS version
FROM pc.deks
WHERE org_id = sqlc.arg(org_id) AND purpose = sqlc.arg(purpose);

-- name: InsertDEK :exec
INSERT INTO pc.deks (org_id, purpose, version, wrapped_key, kek_id, state)
VALUES (sqlc.arg(org_id), sqlc.arg(purpose), sqlc.arg(version), sqlc.arg(wrapped_key), sqlc.arg(kek_id), 'ACTIVE');

-- name: ListPublishedKeys :many
-- Public halves only, revoked keys included, for the well-known documents
-- (PAP-1 §11).
SELECT kid, purpose, algorithm, public_key, state, created_at, state_changed_at
FROM pc.keys
WHERE org_id = sqlc.arg(org_id) AND purpose = ANY(sqlc.arg(purposes)::text[])
ORDER BY created_at, kid;

-- name: ListDEKsToRewrap :many
-- DEKs to re-wrap (D157, migration 00224): all but those whose kek_id is
-- skipped (the current KEK in any spelling, and KEKs no provider holds).
SELECT purpose, version, wrapped_key, kek_id
FROM pc.deks
WHERE org_id = sqlc.arg(org_id) AND kek_id <> ALL(sqlc.arg(skip_kek_ids)::text[])
ORDER BY purpose, version
LIMIT sqlc.arg(row_limit);

-- name: RewrapDEK :execrows
-- A compare-and-swap on both old columns; the 00224 trigger refuses a
-- change of one without the other (HR-487).
UPDATE pc.deks
SET wrapped_key = sqlc.arg(wrapped_key), kek_id = sqlc.arg(kek_id)
WHERE org_id = sqlc.arg(org_id) AND purpose = sqlc.arg(purpose) AND version = sqlc.arg(version)
  AND wrapped_key = sqlc.arg(old_wrapped_key) AND kek_id = sqlc.arg(old_kek_id);

-- name: ListSigningKeysToRewrap :many
-- Revoked keys are never unwrapped, so they stay as they are.
SELECT kid, purpose, wrapped_private_key, kek_id
FROM pc.keys
WHERE org_id = sqlc.arg(org_id) AND state <> 'REVOKED' AND kek_id <> ALL(sqlc.arg(skip_kek_ids)::text[])
ORDER BY created_at, kid
LIMIT sqlc.arg(row_limit);

-- name: RewrapSigningKey :execrows
UPDATE pc.keys
SET wrapped_private_key = sqlc.arg(wrapped_private_key), kek_id = sqlc.arg(kek_id)
WHERE org_id = sqlc.arg(org_id) AND kid = sqlc.arg(kid)
  AND wrapped_private_key = sqlc.arg(old_wrapped_private_key) AND kek_id = sqlc.arg(old_kek_id);

-- name: ListWebhookKeys :many
-- An org's webhooks keys that are not revoked (G0 M20 D251). live is false
-- for a RETIRING key whose overlap has ended: it verifies nothing and is in
-- no JWKS (HR-512).
SELECT kid, public_key, wrapped_private_key, kek_id, state, created_at, state_changed_at,
       (state_changed_at + make_interval(secs => sqlc.arg(overlap_seconds)::int))::timestamptz AS retires_at,
       (state = 'ACTIVE' OR state_changed_at > now() - make_interval(secs => sqlc.arg(overlap_seconds)::int))::bool AS live
FROM pc.keys
WHERE org_id = sqlc.arg(org_id) AND purpose = 'webhooks' AND state <> 'REVOKED'
ORDER BY created_at, kid;

-- name: ListStoredKEKIDs :many
-- The distinct kek_id values of an org's stored keys, for the start-up
-- check that every one has a provider (D165). Revoked signing keys are
-- never unwrapped, so they don't count.
SELECT k.kek_id FROM pc.keys AS k WHERE k.org_id = sqlc.arg(org_id) AND k.state <> 'REVOKED'
UNION
SELECT d.kek_id FROM pc.deks AS d WHERE d.org_id = sqlc.arg(org_id)
ORDER BY kek_id;
