-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Model usage queries (G0 M29 D825). Every query runs inside
-- db.InTenantTx and also filters by org_id explicitly. Rows are
-- append-only: no query updates or deletes one.

-- name: InsertModelUsage :exec
-- One model call's usage, written in the transaction that records its
-- outcome (one row per transaction).
INSERT INTO pc.model_usage (org_id, id, transaction_id, run_id, agent_id, team_id, connection_id,
    operation, model, outcome, reported, input_tokens, output_tokens, cache_read_tokens,
    cache_write_tokens, estimate, estimate_currency, recorded_at)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(transaction_id), sqlc.narg(run_id), sqlc.narg(agent_id),
    sqlc.narg(team_id), sqlc.arg(connection_id), sqlc.arg(operation), sqlc.arg(model), sqlc.arg(outcome),
    sqlc.arg(reported), sqlc.arg(input_tokens), sqlc.arg(output_tokens), sqlc.arg(cache_read_tokens),
    sqlc.arg(cache_write_tokens), sqlc.narg(estimate), sqlc.narg(estimate_currency), sqlc.arg(recorded_at));

-- name: ModelUsageReport :many
-- One UTC month of usage summed per key (team, agent, connection or model;
-- the empty key for a call without a team or agent), with the estimates summed per
-- currency. Keys page in byte order after the last key of the previous
-- page.
SELECT g.key::text AS key,
    sum(g.calls)::bigint AS calls,
    sum(g.unreported_calls)::bigint AS unreported_calls,
    sum(g.unknown_calls)::bigint AS unknown_calls,
    sum(g.input_tokens)::bigint AS input_tokens,
    sum(g.output_tokens)::bigint AS output_tokens,
    sum(g.cache_read_tokens)::bigint AS cache_read_tokens,
    sum(g.cache_write_tokens)::bigint AS cache_write_tokens,
    coalesce(array_agg(g.estimate_currency ORDER BY g.estimate_currency)
        FILTER (WHERE g.estimate_currency IS NOT NULL), '{}')::text[] AS estimate_currencies,
    coalesce(array_agg(g.estimate::text ORDER BY g.estimate_currency)
        FILTER (WHERE g.estimate_currency IS NOT NULL), '{}')::text[] AS estimate_amounts
FROM (
    SELECT k.key, u.estimate_currency,
        count(*) AS calls,
        count(*) FILTER (WHERE NOT u.reported) AS unreported_calls,
        count(*) FILTER (WHERE u.outcome = 'UNKNOWN') AS unknown_calls,
        sum(u.input_tokens) AS input_tokens,
        sum(u.output_tokens) AS output_tokens,
        sum(u.cache_read_tokens) AS cache_read_tokens,
        sum(u.cache_write_tokens) AS cache_write_tokens,
        sum(u.estimate) AS estimate
    FROM pc.model_usage u
    CROSS JOIN LATERAL (SELECT (CASE sqlc.arg(group_by)::text
        WHEN 'team' THEN coalesce(u.team_id::text, '')
        WHEN 'agent' THEN coalesce(u.agent_id::text, '')
        WHEN 'connection' THEN u.connection_id::text
        ELSE u.model END) COLLATE "C" AS key) k
    WHERE u.org_id = sqlc.arg(org_id)
        AND u.recorded_at >= sqlc.arg(month_start) AND u.recorded_at < sqlc.arg(month_end)
        AND (NOT sqlc.arg(has_after)::boolean OR k.key > (sqlc.arg(after)::text COLLATE "C"))
    GROUP BY k.key, u.estimate_currency
) g
GROUP BY g.key
ORDER BY g.key
LIMIT sqlc.arg(row_limit);
