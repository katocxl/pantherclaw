-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- SIEM export (G0 M10 D35, D36; HR-259, HR-260). Destinations, their feed
-- cursors and batch logs. Every state change is a conditional update.

-- name: InsertSIEMDestination :exec
INSERT INTO pc.siem_destinations (org_id, id, name, url, internal, data_classes, secret, created_by)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(name), sqlc.arg(url), sqlc.arg(internal), sqlc.arg(data_classes),
        sqlc.arg(secret), sqlc.arg(created_by));

-- name: InsertSIEMCursor :exec
INSERT INTO pc.siem_cursors (org_id, destination_id, seq) VALUES (sqlc.arg(org_id), sqlc.arg(destination_id), sqlc.arg(seq));

-- name: GetSIEMDestination :one
SELECT d.id, d.name, d.url, d.internal, d.data_classes, d.format, d.state, d.created_by, d.created_at, d.activated_by,
       d.activated_at, d.updated_at, d.confirmed_at, coalesce(d.last_delivered_seq, 0)::bigint AS last_delivered_seq, d.last_delivered_at, d.consecutive_failures,
       d.failing_since, d.last_failure_at, d.last_failure_code, d.delivered_batches, d.failed_batches, d.retries,
       d.prev_secret_expires_at, coalesce(c.seq, 0)::bigint AS cursor_seq, ob.created_at AS open_batch_since, d.signature_scheme
FROM pc.siem_destinations d
LEFT JOIN pc.siem_cursors c ON c.org_id = d.org_id AND c.destination_id = d.id
LEFT JOIN pc.siem_batches ob ON ob.org_id = d.org_id AND ob.destination_id = d.id AND ob.state <> 'DELIVERED'
WHERE d.org_id = sqlc.arg(org_id) AND d.id = sqlc.arg(id);

-- name: ListSIEMDestinations :many
SELECT d.id, d.name, d.url, d.internal, d.data_classes, d.format, d.state, d.created_by, d.created_at, d.activated_by,
       d.activated_at, d.updated_at, d.confirmed_at, coalesce(d.last_delivered_seq, 0)::bigint AS last_delivered_seq, d.last_delivered_at, d.consecutive_failures,
       d.failing_since, d.last_failure_at, d.last_failure_code, d.delivered_batches, d.failed_batches, d.retries,
       d.prev_secret_expires_at, coalesce(c.seq, 0)::bigint AS cursor_seq, ob.created_at AS open_batch_since, d.signature_scheme
FROM pc.siem_destinations d
LEFT JOIN pc.siem_cursors c ON c.org_id = d.org_id AND c.destination_id = d.id
LEFT JOIN pc.siem_batches ob ON ob.org_id = d.org_id AND ob.destination_id = d.id AND ob.state <> 'DELIVERED'
WHERE d.org_id = sqlc.arg(org_id) AND d.state <> 'DISABLED'
  AND (sqlc.narg(after_id)::uuid IS NULL OR d.id > sqlc.narg(after_id)::uuid)
ORDER BY d.id
LIMIT sqlc.arg(max_rows)::int;

-- name: ActivateSIEMDestination :execrows
-- A person with a fresh step-up activates a PENDING destination (HR-259);
-- the database clock sets activated_at.
UPDATE pc.siem_destinations
SET state = 'ACTIVE', activated_by = sqlc.arg(activated_by), activated_credential = sqlc.arg(activated_credential),
    updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'PENDING';

-- name: SetSIEMDestinationState :execrows
UPDATE pc.siem_destinations SET state = sqlc.arg(state), updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = sqlc.arg(expected);

-- name: RotateSIEMSecret :execrows
-- The old secret keeps signing alongside the new one for the overlap; a
-- rotation never starts while another overlap runs (D64 L4).
UPDATE pc.siem_destinations
SET prev_secret = sqlc.arg(prev_secret), secret = sqlc.arg(secret),
    prev_secret_expires_at = now() + make_interval(secs => sqlc.arg(overlap_seconds)::int), updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state IN ('PENDING', 'ACTIVE', 'PAUSED')
  AND (prev_secret_expires_at IS NULL OR prev_secret_expires_at <= now());

-- Export (the per-destination worker).

-- name: LoadSIEMExport :one
-- What one export step needs: the destination, its secrets, its cursor and
-- its open batch, if any. FOR UPDATE OF the cursor serializes the workers
-- of one destination.
SELECT d.state, d.url, d.internal, d.data_classes, d.secret, d.prev_secret,
       coalesce(d.prev_secret_expires_at > now(), false)::bool AS prev_secret_live, d.consecutive_failures,
       d.failing_since, d.signature_scheme, c.seq AS cursor_seq,
       b.id AS batch_id, coalesce(b.from_seq, 0)::bigint AS batch_from, coalesce(b.to_seq, 0)::bigint AS batch_to, b.attempts AS batch_attempts,
       b.state AS batch_state, coalesce(b.next_attempt_at <= now(), false)::bool AS batch_due, now()::timestamptz AS now
FROM pc.siem_destinations d
JOIN pc.siem_cursors c ON c.org_id = d.org_id AND c.destination_id = d.id
LEFT JOIN pc.siem_batches b ON b.org_id = d.org_id AND b.destination_id = d.id AND b.state <> 'DELIVERED'
WHERE d.org_id = sqlc.arg(org_id) AND d.id = sqlc.arg(id)
FOR UPDATE OF c;

-- name: AdvanceSIEMCursor :execrows
-- Compare-and-set (D36): only from the seq the step read.
UPDATE pc.siem_cursors SET seq = sqlc.arg(seq)
WHERE org_id = sqlc.arg(org_id) AND destination_id = sqlc.arg(destination_id) AND seq = sqlc.arg(expected);

-- name: InsertSIEMBatch :exec
INSERT INTO pc.siem_batches (org_id, id, destination_id, from_seq, to_seq, event_count, body_bytes, skipped_uids, next_attempt_at)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(destination_id), sqlc.arg(from_seq), sqlc.arg(to_seq),
        sqlc.arg(event_count), sqlc.arg(body_bytes), coalesce(sqlc.arg(skipped_uids)::uuid[], '{}'), now() + make_interval(secs => sqlc.arg(lease_seconds)::int));

-- name: DeliveredSIEMBatch :execrows
UPDATE pc.siem_batches
SET state = 'DELIVERED', attempts = attempts + 1, last_attempt_at = now(), last_status = sqlc.arg(last_status),
    last_error = NULL, delivered_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state <> 'DELIVERED';

-- name: FailedSIEMBatchAttempt :execrows
-- A failed attempt: the batch stays open (PENDING, or FAILED after the
-- schedule's last attempt) and is tried again at next_attempt_at.
UPDATE pc.siem_batches
SET state = sqlc.arg(state), attempts = attempts + 1, last_attempt_at = now(), last_status = sqlc.narg(last_status),
    last_error = sqlc.arg(last_error), next_attempt_at = now() + make_interval(secs => sqlc.arg(delay_seconds)::int)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state <> 'DELIVERED';

-- name: SIEMDelivered :exec
-- Health after a 2xx: the first one confirms delivery (F537).
UPDATE pc.siem_destinations
SET confirmed_at = coalesce(confirmed_at, now()), last_delivered_seq = sqlc.arg(seq)::bigint, last_delivered_at = now(),
    consecutive_failures = 0, failing_since = NULL, delivered_batches = delivered_batches + 1,
    retries = retries + sqlc.arg(retries)::bigint
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: SIEMFailed :one
-- Health after a failed attempt; returns the new failure count.
UPDATE pc.siem_destinations
SET consecutive_failures = consecutive_failures + 1, failing_since = coalesce(failing_since, now()),
    last_failure_at = now(), last_failure_code = sqlc.arg(code),
    failed_batches = failed_batches + sqlc.arg(failed_batch)::bigint, retries = retries + sqlc.arg(retries)::bigint
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id)
RETURNING consecutive_failures;

-- name: ListActiveSIEMDestinations :many
SELECT id FROM pc.siem_destinations WHERE org_id = sqlc.arg(org_id) AND state = 'ACTIVE' ORDER BY id LIMIT 100;

-- name: RecentSIEMBatches :many
SELECT id, from_seq, to_seq, event_count, body_bytes, skipped_uids, state, attempts, next_attempt_at, last_attempt_at, last_status,
       last_error, created_at, delivered_at
FROM pc.siem_batches
WHERE org_id = sqlc.arg(org_id) AND destination_id = sqlc.arg(destination_id)
ORDER BY created_at DESC
LIMIT 20;

-- name: DeleteOldSIEMBatches :execrows
-- Delivered batches are kept 30 days (their ranges and outcomes only).
DELETE FROM pc.siem_batches
WHERE org_id = sqlc.arg(org_id) AND state = 'DELIVERED' AND delivered_at < now() - interval '30 days';

-- name: LoadSIEMSecrets :one
SELECT state, secret, coalesce(prev_secret_expires_at > now(), false)::bool AS rotating FROM pc.siem_destinations
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id)
FOR UPDATE;

-- name: LeaseSIEMBatch :execrows
-- The worker sending a batch holds it until its attempt is recorded: no
-- other worker re-sends it meanwhile.
UPDATE pc.siem_batches SET next_attempt_at = now() + make_interval(secs => sqlc.arg(lease_seconds)::int)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state <> 'DELIVERED' AND next_attempt_at <= now();

-- name: RetrySIEMBatchNow :execrows
-- A person asks for the open batch to be tried again now, with a fresh
-- schedule (D46).
UPDATE pc.siem_batches SET state = 'PENDING', attempts = 0, next_attempt_at = now()
WHERE org_id = sqlc.arg(org_id) AND destination_id = sqlc.arg(destination_id) AND state <> 'DELIVERED';

-- name: SetSIEMDestinationSignatureScheme :one
-- Opts a destination in to or out of Ed25519 signatures (G0 M20 D251,
-- HR-510); it returns the previous scheme for the audit entry.
WITH old AS (
    SELECT d.id, d.signature_scheme FROM pc.siem_destinations d
    WHERE d.org_id = sqlc.arg(org_id) AND d.id = sqlc.arg(id) AND d.state <> 'DISABLED'
    FOR UPDATE
)
UPDATE pc.siem_destinations d SET signature_scheme = sqlc.arg(scheme), updated_at = now()
FROM old
WHERE d.org_id = sqlc.arg(org_id) AND d.id = old.id
RETURNING old.signature_scheme AS previous;
