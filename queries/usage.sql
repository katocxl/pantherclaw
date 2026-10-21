-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Daily usage meters (G0 M13 D10, D11; HR-377), computed by the job
-- usage.meter_daily from the org's own records in its tenant transaction.
-- Days are UTC. The method is documented in migration 00171.

-- name: CountAdmittedInstances :one
-- The instances_peak sample: ADMITTED instances of the org's agents now
-- (range agents excluded).
SELECT count(*)::int FROM pc.agent_instances i
JOIN pc.agents a ON a.org_id = i.org_id AND a.id = i.agent_id
WHERE i.org_id = sqlc.arg(org_id) AND i.state = 'ADMITTED' AND NOT a.range_agent;

-- name: MeterUsageDay :exec
-- Recomputes one day of the org's meters. instances_peak keeps the highest
-- sample seen for the day: a recomputation passes 0 for a day it cannot
-- sample (yesterday), which keeps the peak recorded.
WITH bounds AS (
    SELECT (sqlc.arg(day)::date)::timestamp AT TIME ZONE 'UTC' AS day_start,
           (sqlc.arg(day)::date + 1)::timestamp AT TIME ZONE 'UTC' AS day_end
)
INSERT INTO pc.usage_daily (org_id, day, agents, instances_peak, runs, stored_bytes, computed_at)
SELECT sqlc.arg(org_id), sqlc.arg(day)::date,
    (SELECT count(*) FROM pc.agents a
     WHERE a.org_id = sqlc.arg(org_id) AND NOT a.range_agent AND a.created_at < b.day_end
       AND (a.retired_at IS NULL OR a.retired_at >= b.day_start))::int,
    sqlc.arg(instances_sample)::int,
    (SELECT count(*) FROM pc.runs r
     JOIN pc.agents a ON a.org_id = r.org_id AND a.id = r.agent_id
     WHERE r.org_id = sqlc.arg(org_id) AND NOT a.range_agent AND r.created_at >= b.day_start AND r.created_at < b.day_end)::int,
    ((SELECT coalesce(sum(octet_length(e.body)), 0) FROM pc.ledger_entries e
      WHERE e.org_id = sqlc.arg(org_id) AND e.occurred_at < b.day_end)
     + (SELECT coalesce(sum(octet_length(d.receipt_jws)), 0) FROM pc.decision_receipts d
        WHERE d.org_id = sqlc.arg(org_id) AND d.created_at < b.day_end)
     + (SELECT coalesce(sum(octet_length(c.content)), 0) FROM pc.payload_captures c
        WHERE c.org_id = sqlc.arg(org_id) AND c.created_at < b.day_end)
     + (SELECT coalesce(sum(coalesce(octet_length(p.manifest), 0) + coalesce(octet_length(p.content), 0)), 0) FROM pc.evidence_packs p
        WHERE p.org_id = sqlc.arg(org_id) AND p.created_at < b.day_end))::bigint,
    now()
FROM bounds b
ON CONFLICT (org_id, day) DO UPDATE SET
    agents = EXCLUDED.agents,
    instances_peak = GREATEST(pc.usage_daily.instances_peak, EXCLUDED.instances_peak),
    runs = EXCLUDED.runs,
    stored_bytes = EXCLUDED.stored_bytes,
    computed_at = EXCLUDED.computed_at;

-- name: ListUsageDays :many
-- UsageService.ListUsage: the org's days from since, newest first.
SELECT day, agents, instances_peak, runs, stored_bytes FROM pc.usage_daily
WHERE org_id = sqlc.arg(org_id) AND day >= sqlc.arg(since)::date
ORDER BY day DESC;
