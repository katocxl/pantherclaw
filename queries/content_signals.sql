-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Content signals (G0 M27 D507, D512).

-- EnsureContentSignalSettings creates the org's row at OFF.
-- name: EnsureContentSignalSettings :exec
INSERT INTO pc.content_signal_settings (org_id) VALUES (sqlc.arg(org_id)) ON CONFLICT (org_id) DO NOTHING;

-- GetContentSignalSettings reads the org's row.
-- name: GetContentSignalSettings :one
SELECT * FROM pc.content_signal_settings WHERE org_id = sqlc.arg(org_id);

-- LockContentSignalSettings takes the row a mode change writes.
-- name: LockContentSignalSettings :one
SELECT * FROM pc.content_signal_settings WHERE org_id = sqlc.arg(org_id) FOR UPDATE;

-- name: SetContentSignalMode :one
UPDATE pc.content_signal_settings SET mode = sqlc.arg(mode), updated_by = sqlc.arg(updated_by), updated_at = now()
WHERE org_id = sqlc.arg(org_id)
RETURNING *;

-- CountContentWouldHold adds to what WATCHING would have held (D512).
-- name: CountContentWouldHold :exec
INSERT INTO pc.content_signal_would_holds AS w (org_id, reason, count)
VALUES (sqlc.arg(org_id), sqlc.arg(reason), sqlc.arg(n))
ON CONFLICT (org_id, reason) DO UPDATE SET count = w.count + EXCLUDED.count, last_at = now();

-- ContentWouldHolds lists them, most first.
-- name: ContentWouldHolds :many
SELECT * FROM pc.content_signal_would_holds WHERE org_id = sqlc.arg(org_id) ORDER BY count DESC, reason;

-- ContentSignalMode reads the org's mode; no row is OFF.
-- name: ContentSignalMode :one
SELECT coalesce((SELECT s.mode FROM pc.content_signal_settings s WHERE s.org_id = sqlc.arg(org_id)), 'OFF')::text;

-- BumpOrgGateways gives every gateway of the org a new configuration.
-- name: BumpOrgGateways :exec
UPDATE pc.gateways SET config_version = config_version + 1 WHERE org_id = sqlc.arg(org_id);

-- ContentRunState finds the root of a run's tree and the flag on it.
-- name: ContentRunState :one
WITH RECURSIVE up (id, parent_run_id, hop) AS (
    SELECT r.id, r.parent_run_id, 0 FROM pc.runs r WHERE r.org_id = sqlc.arg(org_id) AND r.id = sqlc.arg(run_id)
    UNION ALL
    SELECT p.id, p.parent_run_id, up.hop + 1 FROM up JOIN pc.runs p ON p.org_id = sqlc.arg(org_id) AND p.id = up.parent_run_id
    WHERE up.hop < 8
), root AS (
    SELECT up.id FROM up ORDER BY up.hop DESC LIMIT 1
)
SELECT root.id::uuid AS root, f.value AS flag
FROM root LEFT JOIN pc.facts f ON f.org_id = sqlc.arg(org_id) AND f.name = 'pc.content.flag' AND f.subject_type = 'run'
    AND f.subject_id = root.id::text AND f.connection_id IS NULL;

-- ContentTransactionRun is a transaction's run.
-- name: ContentTransactionRun :one
SELECT t.run_id FROM pc.transactions t WHERE t.org_id = sqlc.arg(org_id) AND t.id = sqlc.arg(id);
