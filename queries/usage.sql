-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Daily usage meters (G0 M13 D10, D11, D45; HR-377), computed by the jobs
-- usage.meter_daily and usage.recount_weekly from the org's own records in
-- its tenant transaction. Days are UTC. The method is documented in
-- migration 00171. Each day reads only that day's rows, through the
-- (org_id, created/occurred) indexes.

-- name: CountAdmittedInstances :one
-- The instances_peak sample: ADMITTED instances of the org's agents now
-- (range agents excluded).
SELECT count(*)::int FROM pc.agent_instances i
JOIN pc.agents a ON a.org_id = i.org_id AND a.id = i.agent_id
WHERE i.org_id = sqlc.arg(org_id) AND i.state = 'ADMITTED' AND NOT a.range_agent;

-- name: MeterUsageDay :exec
-- Recomputes one day of the org's meters from that day's rows.
-- instances_peak keeps the highest sample seen for the day: a
-- recomputation passes 0 for a day it cannot sample (yesterday).
-- stored_bytes is the previous day's plus the day's bytes_written minus
-- the day's bytes_removed.
WITH bounds AS (
    SELECT (sqlc.arg(day)::date)::timestamp AT TIME ZONE 'UTC' AS day_start,
           (sqlc.arg(day)::date + 1)::timestamp AT TIME ZONE 'UTC' AS day_end
), written AS (
    SELECT ((SELECT coalesce(sum(octet_length(e.body)), 0) FROM pc.ledger_entries e
             WHERE e.org_id = sqlc.arg(org_id) AND e.body_removed_at IS NULL
               AND e.occurred_at >= b.day_start AND e.occurred_at < b.day_end)
          + (SELECT coalesce(sum(octet_length(d.receipt_jws)), 0) FROM pc.decision_receipts d
             WHERE d.org_id = sqlc.arg(org_id) AND d.body_removed_at IS NULL
               AND d.created_at >= b.day_start AND d.created_at < b.day_end)
          + (SELECT coalesce(sum(octet_length(c.content)), 0) FROM pc.payload_captures c
             WHERE c.org_id = sqlc.arg(org_id) AND c.remove_at > b.day_start AND c.remove_at <= b.day_end + interval '30 days'
               AND c.created_at >= b.day_start AND c.created_at < b.day_end)
          + (SELECT coalesce(sum(coalesce(octet_length(p.manifest), 0) + coalesce(octet_length(p.content), 0)), 0)
             FROM pc.evidence_packs p
             WHERE p.org_id = sqlc.arg(org_id) AND p.created_at >= b.day_start AND p.created_at < b.day_end))::bigint AS bytes
    FROM bounds b
), prev AS (
    SELECT coalesce((SELECT u.stored_bytes FROM pc.usage_daily u
                     WHERE u.org_id = sqlc.arg(org_id) AND u.day = sqlc.arg(day)::date - 1), 0)::bigint AS stored
)
INSERT INTO pc.usage_daily (org_id, day, agents, instances_peak, runs, bytes_written, stored_bytes, computed_at)
SELECT sqlc.arg(org_id), sqlc.arg(day)::date,
    (SELECT count(*) FROM pc.agents a
     WHERE a.org_id = sqlc.arg(org_id) AND NOT a.range_agent AND a.created_at < b.day_end
       AND (a.retired_at IS NULL OR a.retired_at >= b.day_start))::int,
    sqlc.arg(instances_sample)::int,
    (SELECT count(*) FROM pc.runs r
     JOIN pc.agents a ON a.org_id = r.org_id AND a.id = r.agent_id
     WHERE r.org_id = sqlc.arg(org_id) AND NOT a.range_agent AND r.created_at >= b.day_start AND r.created_at < b.day_end)::int,
    w.bytes,
    prev.stored + w.bytes,
    now()
FROM bounds b, written w, prev
ON CONFLICT (org_id, day) DO UPDATE SET
    agents = EXCLUDED.agents,
    instances_peak = GREATEST(pc.usage_daily.instances_peak, EXCLUDED.instances_peak),
    runs = EXCLUDED.runs,
    bytes_written = EXCLUDED.bytes_written,
    stored_bytes = GREATEST(EXCLUDED.stored_bytes - pc.usage_daily.bytes_removed, 0),
    computed_at = EXCLUDED.computed_at;

-- name: RebaselineStoredBytes :execrows
-- The weekly recount: sets a day's stored_bytes from a full sum of the
-- stored byte columns of the rows created before the next day, plus what
-- the remover took out since (on later days' rows), so the following days'
-- running totals end at the true total.
WITH bounds AS (
    SELECT (sqlc.arg(day)::date + 1)::timestamp AT TIME ZONE 'UTC' AS day_end
), total AS (
    SELECT ((SELECT coalesce(sum(octet_length(e.body)), 0) FROM pc.ledger_entries e
             WHERE e.org_id = sqlc.arg(org_id) AND e.body_removed_at IS NULL AND e.occurred_at < b.day_end)
          + (SELECT coalesce(sum(octet_length(d.receipt_jws)), 0) FROM pc.decision_receipts d
             WHERE d.org_id = sqlc.arg(org_id) AND d.body_removed_at IS NULL AND d.created_at < b.day_end)
          + (SELECT coalesce(sum(octet_length(c.content)), 0) FROM pc.payload_captures c
             WHERE c.org_id = sqlc.arg(org_id) AND c.created_at < b.day_end)
          + (SELECT coalesce(sum(coalesce(octet_length(p.manifest), 0) + coalesce(octet_length(p.content), 0)), 0)
             FROM pc.evidence_packs p WHERE p.org_id = sqlc.arg(org_id) AND p.created_at < b.day_end)
          + (SELECT coalesce(sum(u.bytes_removed), 0) FROM pc.usage_daily u
             WHERE u.org_id = sqlc.arg(org_id) AND u.day > sqlc.arg(day)::date))::bigint AS bytes
    FROM bounds b
)
UPDATE pc.usage_daily SET stored_bytes = t.bytes, computed_at = now()
FROM total t
WHERE pc.usage_daily.org_id = sqlc.arg(org_id) AND pc.usage_daily.day = sqlc.arg(day)::date;

-- name: AddUsageBytesRemoved :exec
-- After each batch, the retention remover adds (as pc_app) the ledger
-- body bytes the batch removed to today's row, creating it when the meter
-- has not yet.
INSERT INTO pc.usage_daily (org_id, day, bytes_removed)
VALUES (sqlc.arg(org_id), (now() AT TIME ZONE 'UTC')::date, sqlc.arg(bytes)::bigint)
ON CONFLICT (org_id, day) DO UPDATE SET bytes_removed = pc.usage_daily.bytes_removed + EXCLUDED.bytes_removed;

-- name: ListUsageDays :many
-- UsageService.ListUsage: the org's days from since, newest first.
SELECT day, agents, instances_peak, runs, stored_bytes FROM pc.usage_daily
WHERE org_id = sqlc.arg(org_id) AND day >= sqlc.arg(since)::date
ORDER BY day DESC;
