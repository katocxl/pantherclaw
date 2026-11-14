-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Per-org OTLP destinations and their span export (G0 M36 D1061, D1062;
-- HR-786..788). Every state change is a conditional update.

-- name: InsertOTLPDestination :exec
INSERT INTO pc.otlp_destinations (org_id, id, name, url, header_secret_ref, header_names, created_by)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(name), sqlc.arg(url), sqlc.narg(header_secret_ref), sqlc.arg(header_names),
        sqlc.arg(created_by));

-- name: GetOTLPDestination :one
SELECT id, name, url, header_names, state, created_by, created_at, activated_by, activated_at, disabled_at, cursor_seq,
       last_success_at, failure_count, failing_since, last_failure_code, next_attempt_at
FROM pc.otlp_destinations
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: ListOTLPDestinations :many
SELECT id, name, url, header_names, state, created_by, created_at, activated_by, activated_at, disabled_at, cursor_seq,
       last_success_at, failure_count, failing_since, last_failure_code, next_attempt_at
FROM pc.otlp_destinations
WHERE org_id = sqlc.arg(org_id) AND state <> 'DISABLED'
  AND (sqlc.narg(after_id)::uuid IS NULL OR id > sqlc.narg(after_id)::uuid)
ORDER BY id
LIMIT sqlc.arg(max_rows)::int;

-- name: ActivateOTLPDestination :execrows
-- A person with a fresh step-up activates a PENDING destination (HR-786);
-- its cursor starts at the feed's head, so nothing recorded before is
-- sent. The guard sets activated_at by the database clock.
UPDATE pc.otlp_destinations
SET state = 'ACTIVE', activated_by = sqlc.arg(activated_by), activated_credential = sqlc.arg(activated_credential),
    cursor_seq = sqlc.arg(cursor_seq), next_attempt_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'PENDING';

-- name: DisableOTLPDestination :execrows
UPDATE pc.otlp_destinations SET state = 'DISABLED'
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state <> 'DISABLED';

-- name: ListDueOTLPDestinations :many
SELECT id FROM pc.otlp_destinations
WHERE org_id = sqlc.arg(org_id) AND state = 'ACTIVE' AND next_attempt_at <= now()
ORDER BY id
LIMIT 100;

-- name: LoadOTLPExport :one
-- What one export step needs: the destination, its sealed headers and
-- cursor. FOR UPDATE serializes the workers of one destination.
SELECT state, url, header_secret_ref, cursor_seq, failure_count, failing_since,
       coalesce(next_attempt_at <= now(), false)::bool AS due, now()::timestamptz AS now
FROM pc.otlp_destinations
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id)
FOR UPDATE;

-- name: LeaseOTLPExport :execrows
-- The worker sending a batch holds the destination until its attempt is
-- recorded: no other worker sends meanwhile.
UPDATE pc.otlp_destinations SET next_attempt_at = now() + make_interval(secs => sqlc.arg(lease_seconds)::int)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'ACTIVE' AND next_attempt_at <= now();

-- name: OTLPExported :execrows
-- After a 2xx: the cursor moves by compare-and-set to the end of the batch
-- (HR-788) and the failure streak ends.
UPDATE pc.otlp_destinations
SET cursor_seq = sqlc.arg(cursor_seq), last_success_at = now(), failure_count = 0, failing_since = NULL,
    last_failure_code = NULL, next_attempt_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND cursor_seq = sqlc.arg(expected);

-- name: OTLPSkipped :execrows
-- A range with nothing to send: the cursor moves past it (compare-and-set).
UPDATE pc.otlp_destinations SET cursor_seq = sqlc.arg(cursor_seq), next_attempt_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND cursor_seq = sqlc.arg(expected);

-- name: OTLPExportFailed :one
-- A failed attempt: the cursor stays, the next attempt waits the backoff.
UPDATE pc.otlp_destinations
SET failure_count = failure_count + 1, failing_since = coalesce(failing_since, now()), last_failure_code = sqlc.arg(code),
    next_attempt_at = now() + make_interval(secs => sqlc.arg(delay_seconds)::int)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id)
RETURNING failure_count, coalesce(failing_since <= now() - interval '24 hours', false)::bool AS failing_a_day;

-- name: DisableFailingOTLPDestination :execrows
-- After 24 hours of failures the exporter disables the destination (D1061).
UPDATE pc.otlp_destinations SET state = 'DISABLED'
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'ACTIVE' AND failing_since <= now() - interval '24 hours';

-- name: LoadOTLPHeaders :one
SELECT state, url, header_secret_ref FROM pc.otlp_destinations
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: OTLPSpanTransactions :many
-- The metadata of the transactions a feed batch names (D1062, HR-787):
-- ids, operation, channel, target type, decision and reason, the trace
-- context, the decision window, the last dispatch and the model usage.
-- Never a target id, a payload, a prompt or an answer.
SELECT t.id, t.run_id, r.agent_id, t.operation, coalesce(t.channel, '')::text AS channel,
       coalesce(t.target_type, '')::text AS target_type, t.decision, t.reason_code, t.mode, t.simulated,
       t.trace_id, t.parent_span_id, t.trace_flags, t.created_at,
       coalesce(d.created_at, t.created_at)::timestamptz AS decided_at, coalesce(d.receipt_jws, '')::text AS receipt_jws,
       coalesce(e.outcome, '')::text AS dispatch_outcome, e.dispatch_ms,
       coalesce(e.recorded_at, t.created_at)::timestamptz AS dispatched_at,
       m.model, coalesce(m.input_tokens, 0)::bigint AS input_tokens, coalesce(m.output_tokens, 0)::bigint AS output_tokens
FROM pc.transactions t
JOIN pc.runs r ON r.org_id = t.org_id AND r.id = t.run_id
LEFT JOIN LATERAL (
    SELECT dr.created_at, dr.receipt_jws FROM pc.decision_receipts dr
    WHERE dr.org_id = t.org_id AND dr.transaction_id = t.id
    ORDER BY dr.evaluation DESC LIMIT 1
) d ON true
LEFT JOIN LATERAL (
    SELECT ea.outcome, ea.dispatch_ms, ea.recorded_at FROM pc.execution_attempts ea
    WHERE ea.org_id = t.org_id AND ea.transaction_id = t.id
    ORDER BY ea.recorded_at DESC LIMIT 1
) e ON true
LEFT JOIN pc.model_usage m ON m.org_id = t.org_id AND m.transaction_id = t.id
WHERE t.org_id = sqlc.arg(org_id) AND t.id = ANY (sqlc.arg(ids)::uuid[]);

-- name: OTLPSpanEffects :many
-- The effect states of those transactions, for span events.
SELECT transaction_id, seq, state, created_at FROM pc.effect_receipts
WHERE org_id = sqlc.arg(org_id) AND transaction_id = ANY (sqlc.arg(ids)::uuid[])
ORDER BY transaction_id, seq;
