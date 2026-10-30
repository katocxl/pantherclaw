-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Delivery receipts of export destinations (G0 M20 D252; HR-514..516). Every
-- state change is a conditional update.

-- name: InsertExportReceipt :exec
INSERT INTO pc.export_receipts (org_id, id, destination_id, class, artifact_id, streamed, from_seq, to_seq, requested_by, object_key)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(destination_id), sqlc.arg(class), sqlc.narg(artifact_id), sqlc.arg(streamed),
        sqlc.narg(from_seq), sqlc.narg(to_seq), sqlc.arg(requested_by), sqlc.arg(object_key));

-- name: GetExportReceipt :one
SELECT r.id, r.destination_id, d.name AS destination_name, r.class, r.artifact_id, r.streamed, r.from_seq, r.to_seq, r.requested_by,
       r.object_key, r.state, r.abort_state, r.size_bytes, r.sha256, r.parts, r.etag, r.attempts, r.last_status, r.failure_code,
       r.created_at, r.started_at, r.delivered_at, r.removed_here_at, r.notice_state, r.notice_key, r.notice_sha256, r.notice_sent_at
FROM pc.export_receipts r
JOIN pc.export_destinations d ON d.org_id = r.org_id AND d.id = r.destination_id
WHERE r.org_id = sqlc.arg(org_id) AND r.id = sqlc.arg(id);

-- name: ListExportReceipts :many
-- Newest first; a destination narrows them.
SELECT r.id, r.destination_id, d.name AS destination_name, r.class, r.artifact_id, r.streamed, r.from_seq, r.to_seq, r.requested_by,
       r.object_key, r.state, r.abort_state, r.size_bytes, r.sha256, r.parts, r.etag, r.attempts, r.last_status, r.failure_code,
       r.created_at, r.started_at, r.delivered_at, r.removed_here_at, r.notice_state, r.notice_key, r.notice_sha256, r.notice_sent_at
FROM pc.export_receipts r
JOIN pc.export_destinations d ON d.org_id = r.org_id AND d.id = r.destination_id
WHERE r.org_id = sqlc.arg(org_id)
  AND (sqlc.narg(destination_id)::uuid IS NULL OR r.destination_id = sqlc.narg(destination_id)::uuid)
  AND (sqlc.narg(after_id)::uuid IS NULL OR r.id < sqlc.narg(after_id)::uuid)
ORDER BY r.id DESC
LIMIT sqlc.arg(max_rows)::int;

-- name: LoadExportPush :one
-- What one push needs: the receipt, its destination and the sealed
-- credential.
SELECT r.class, r.artifact_id, r.streamed, r.from_seq, r.to_seq, r.requested_by, r.object_key, r.state AS receipt_state, r.upload_id,
       r.parts,
       r.abort_state, r.destination_id, d.name, d.kind, d.url, d.bucket, d.region, d.key_prefix, d.path_style, d.internal,
       d.data_classes, d.state AS destination_state, d.secret
FROM pc.export_receipts r
JOIN pc.export_destinations d ON d.org_id = r.org_id AND d.id = r.destination_id
WHERE r.org_id = sqlc.arg(org_id) AND r.id = sqlc.arg(id);

-- name: StartExportPush :execrows
UPDATE pc.export_receipts SET state = 'PUSHING', attempts = attempts + 1, started_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'QUEUED';

-- name: SetExportUpload :execrows
-- Stored before the first part, so a crash cannot lose the upload.
UPDATE pc.export_receipts SET upload_id = sqlc.arg(upload_id), abort_state = 'PENDING', parts = 0
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'PUSHING';

-- name: SetExportPartBegun :execrows
-- The highest part begun, stored before it is sent: an abort must reach
-- every part, whatever an earlier abort already deleted.
UPDATE pc.export_receipts SET parts = sqlc.arg(parts)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'PUSHING';

-- name: SetExportAborted :execrows
UPDATE pc.export_receipts SET abort_state = 'ABORTED'
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND abort_state = 'PENDING';

-- name: DeliverExportReceipt :execrows
-- A completed upload needs no abort.
UPDATE pc.export_receipts
SET state = 'DELIVERED', delivered_at = now(), size_bytes = sqlc.arg(size_bytes), sha256 = sqlc.arg(sha256), parts = sqlc.arg(parts),
    etag = sqlc.narg(etag), last_status = sqlc.narg(last_status), failure_code = NULL, abort_state = 'NONE'
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'PUSHING';

-- name: RetryExportReceipt :execrows
-- A failed attempt with attempts left.
UPDATE pc.export_receipts
SET state = 'QUEUED', failure_code = sqlc.arg(failure_code), last_status = sqlc.narg(last_status)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'PUSHING';

-- name: FailExportReceipt :execrows
UPDATE pc.export_receipts
SET state = 'FAILED', failure_code = sqlc.arg(failure_code), last_status = sqlc.narg(last_status)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state IN ('QUEUED', 'PUSHING');

-- name: ClaimStreamedExportReceipt :one
-- The oldest waiting streamed push of the person whose export is building,
-- claimed and started at once: no failure can leave it QUEUED with an
-- artifact, which nothing would ever pick up.
UPDATE pc.export_receipts AS r
SET artifact_id = sqlc.arg(request_id), state = 'PUSHING', attempts = attempts + 1, started_at = now()
WHERE r.org_id = sqlc.arg(org_id) AND r.id = (
    SELECT w.id FROM pc.export_receipts w
    WHERE w.org_id = sqlc.arg(org_id) AND w.requested_by = sqlc.arg(requested_by) AND w.streamed AND w.artifact_id IS NULL
      AND w.state = 'QUEUED' AND w.created_at > now() - make_interval(secs => sqlc.arg(wait_seconds)::int)
    ORDER BY w.id
    LIMIT 1
    FOR UPDATE)
RETURNING r.id;

-- name: FailUnclaimedExportReceipts :execrows
UPDATE pc.export_receipts
SET state = 'FAILED', failure_code = 'no_export_started'
WHERE org_id = sqlc.arg(org_id) AND streamed AND artifact_id IS NULL AND state = 'QUEUED'
  AND created_at <= now() - make_interval(secs => sqlc.arg(wait_seconds)::int);

-- name: RecordExportDelivered :exec
UPDATE pc.export_destinations
SET confirmed_at = coalesce(confirmed_at, now()), last_delivered_at = now(), consecutive_failures = 0, failing_since = NULL,
    delivered_pushes = delivered_pushes + 1, updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: RecordExportFailure :one
UPDATE pc.export_destinations
SET consecutive_failures = consecutive_failures + 1, failing_since = coalesce(failing_since, now()), last_failure_at = now(),
    last_failure_code = sqlc.arg(code), failed_pushes = failed_pushes + 1, updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id)
RETURNING consecutive_failures, failing_since;

-- name: GetPackForPush :one
SELECT state, coalesce((include ->> 'captures')::boolean, false)::boolean AS captures, content, content_sha256,
       coalesce(expires_at > now(), false)::boolean AS live
FROM pc.evidence_packs
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: GetExportForPush :one
SELECT state, parts, manifest, coalesce(expires_at > now(), false)::boolean AS live
FROM pc.data_requests
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND kind = 'EXPORT';

-- Removal (the hourly sweep).

-- name: ListExportRemovals :many
-- Delivered artifacts whose copy here is gone: a pack or an export past its
-- expiry, a proof bundle one of whose ledger bodies retention removed.
SELECT r.id
FROM pc.export_receipts r
WHERE r.org_id = sqlc.arg(org_id) AND r.state = 'DELIVERED' AND r.removed_here_at IS NULL AND (
    (r.class = 'evidence_packs' AND EXISTS (
        SELECT 1 FROM pc.evidence_packs p WHERE p.org_id = r.org_id AND p.id = r.artifact_id AND p.state = 'EXPIRED'))
    OR (r.class = 'org_exports' AND EXISTS (
        SELECT 1 FROM pc.data_requests q WHERE q.org_id = r.org_id AND q.id = r.artifact_id AND q.state = 'EXPIRED'))
    OR (r.class = 'proof_bundles' AND EXISTS (
        SELECT 1 FROM pc.ledger_chain c
        JOIN pc.ledger_entries l ON l.org_id = c.org_id AND l.id = c.entry_id
        WHERE c.org_id = r.org_id AND c.seq BETWEEN r.from_seq AND r.to_seq AND l.body_removed_at IS NOT NULL)))
ORDER BY r.id
LIMIT sqlc.arg(max_rows)::int;

-- name: MarkExportRemovedHere :execrows
UPDATE pc.export_receipts SET removed_here_at = now(), notice_state = 'PENDING'
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND removed_here_at IS NULL;

-- name: ListExportNotices :many
-- The least tried first: a failing destination cannot fill every run.
SELECT r.id, r.notice_attempts
FROM pc.export_receipts r
WHERE r.org_id = sqlc.arg(org_id) AND r.notice_state = 'PENDING'
ORDER BY r.notice_attempts, r.id
LIMIT sqlc.arg(max_rows)::int;

-- name: LoadExportNotice :one
SELECT r.class, r.artifact_id, r.from_seq, r.to_seq, r.object_key, r.size_bytes, r.sha256, r.etag, r.delivered_at, r.removed_here_at,
       r.destination_id, d.name, d.kind, d.url, d.bucket, d.region, d.key_prefix, d.path_style, d.internal,
       d.state AS destination_state, d.secret
FROM pc.export_receipts r
JOIN pc.export_destinations d ON d.org_id = r.org_id AND d.id = r.destination_id
WHERE r.org_id = sqlc.arg(org_id) AND r.id = sqlc.arg(id);

-- name: SetExportNoticeSent :execrows
UPDATE pc.export_receipts
SET notice_state = 'SENT', notice_key = sqlc.arg(notice_key), notice_sha256 = sqlc.arg(notice_sha256), notice_sent_at = now(),
    notice_attempts = notice_attempts + 1
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND notice_state = 'PENDING';

-- name: SetExportNoticeFailed :execrows
UPDATE pc.export_receipts SET notice_attempts = notice_attempts + 1
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND notice_state = 'PENDING';

-- name: SetExportNoticeUndeliverable :execrows
-- The destination was disabled: nothing goes to it any more.
UPDATE pc.export_receipts SET notice_state = 'UNDELIVERABLE'
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND notice_state = 'PENDING';

-- Uploads left behind (HR-516).

-- name: ListExportAborts :many
-- Uploads whose abort failed, and those of pushes that stopped: a crash
-- leaves a receipt PUSHING long after any push could have ended.
SELECT r.id
FROM pc.export_receipts r
WHERE r.org_id = sqlc.arg(org_id) AND r.abort_state = 'PENDING' AND r.upload_id IS NOT NULL
  AND (r.state <> 'PUSHING' OR r.started_at <= now() - make_interval(secs => sqlc.arg(stale_seconds)::int))
ORDER BY r.abort_tried_at NULLS FIRST, r.id
LIMIT sqlc.arg(max_rows)::int;

-- name: SetExportAbortTried :execrows
UPDATE pc.export_receipts SET abort_tried_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND abort_state = 'PENDING';

-- name: FailStaleExportReceipts :execrows
UPDATE pc.export_receipts
SET state = 'FAILED', failure_code = 'push_stopped'
WHERE org_id = sqlc.arg(org_id) AND state = 'PUSHING'
  AND started_at <= now() - make_interval(secs => sqlc.arg(stale_seconds)::int);
