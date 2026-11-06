-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

-- A model connection's settings (G0 M29 D811; capture_prompts G0 M30
-- D945b), written in the transaction that creates or changes the
-- connection.
-- name: PutModelConnection :exec
INSERT INTO pc.model_connections (org_id, connection_id, max_output_tokens, allowed_server_tools, price_currency,
    price_input, price_output, price_cache_read, price_cache_write, capture_prompts)
VALUES (@org_id, @connection_id, @max_output_tokens, @allowed_server_tools, sqlc.narg('price_currency'),
    sqlc.narg('price_input')::numeric, sqlc.narg('price_output')::numeric, sqlc.narg('price_cache_read')::numeric,
    sqlc.narg('price_cache_write')::numeric, @capture_prompts)
ON CONFLICT (org_id, connection_id) DO UPDATE
SET max_output_tokens = EXCLUDED.max_output_tokens, allowed_server_tools = EXCLUDED.allowed_server_tools,
    price_currency = EXCLUDED.price_currency, price_input = EXCLUDED.price_input, price_output = EXCLUDED.price_output,
    price_cache_read = EXCLUDED.price_cache_read, price_cache_write = EXCLUDED.price_cache_write,
    capture_prompts = EXCLUDED.capture_prompts, updated_at = now();

-- name: GetModelConnection :one
SELECT max_output_tokens, allowed_server_tools, price_currency, price_input, price_output, price_cache_read, price_cache_write,
    capture_prompts
FROM pc.model_connections WHERE org_id = @org_id AND connection_id = @connection_id;

-- How many of these connections are model connections whose prompts and
-- replies are not captured (G0 M29 D820): every one but those with prompt
-- capture on (G0 M30 D945b).
-- name: CountModelConnections :one
SELECT count(*)::integer FROM pc.connections c
WHERE c.org_id = sqlc.arg(org_id) AND c.id = ANY (sqlc.arg(connection_ids)::uuid[]) AND c.kind = 'model'
  AND NOT EXISTS (
    SELECT 1 FROM pc.model_connections m
    WHERE m.org_id = c.org_id AND m.connection_id = c.id AND m.capture_prompts);
