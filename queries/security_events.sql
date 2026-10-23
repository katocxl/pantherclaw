-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

-- name: InsertSecurityEvent :exec
INSERT INTO pc.security_event_outbox (org_id, ledger_seq, payload)
VALUES (sqlc.arg(org_id), sqlc.arg(ledger_seq), sqlc.arg(payload));

-- name: AttemptSecurityEvents :many
WITH due AS (
    SELECT ledger_seq FROM pc.security_event_outbox
    WHERE org_id = sqlc.arg(org_id) AND acknowledged_at IS NULL
      AND (last_emitted_at IS NULL OR last_emitted_at <= now() - interval '5 minutes')
    ORDER BY last_emitted_at NULLS FIRST, ledger_seq
    LIMIT sqlc.arg(max_rows) FOR UPDATE SKIP LOCKED
)
UPDATE pc.security_event_outbox o
SET attempts = least(o.attempts::bigint + 1, 2147483647)::integer, last_emitted_at = now()
FROM due WHERE o.org_id = sqlc.arg(org_id) AND o.ledger_seq = due.ledger_seq
RETURNING o.payload;

-- name: ExportSecurityEvents :many
SELECT ledger_seq, payload FROM pc.security_event_outbox
WHERE org_id = sqlc.arg(org_id) AND ledger_seq > sqlc.arg(after_seq)
ORDER BY ledger_seq LIMIT sqlc.arg(max_rows);

-- name: AcknowledgeSecurityEvents :execrows
UPDATE pc.security_event_outbox SET acknowledged_at = now()
WHERE org_id = sqlc.arg(org_id) AND ledger_seq <= sqlc.arg(through_seq) AND acknowledged_at IS NULL;

-- name: SecurityEventExists :one
SELECT EXISTS (SELECT 1 FROM pc.security_event_outbox WHERE org_id = sqlc.arg(org_id) AND ledger_seq = sqlc.arg(ledger_seq));

-- name: SecurityIntentAcknowledged :one
SELECT EXISTS (
    SELECT 1 FROM pc.security_event_outbox
    WHERE org_id = sqlc.arg(org_id) AND acknowledged_at IS NOT NULL
      AND payload->>'kind' IN ('org.deletion_started', 'account.deletion_started')
      AND payload->>'kind' = sqlc.arg(event_kind)::text
      AND payload->'object'->>'type' = sqlc.arg(object_type)::text
      AND payload->'object'->>'id' = sqlc.arg(object_id)::text
      AND payload->>'journal_digest' = sqlc.arg(journal_digest)::text
);

