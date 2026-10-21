-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- The shared rate limiter (G0 M13 D9, HR-376), in a global transaction of
-- the purpose "rate_limit". Windows are aligned to the Unix epoch on the
-- database's clock, so every replica counts in the same window.

-- name: TakeRateCounter :one
-- Adds n events to the key's current window if they fit within the limit
-- and returns the new count; no row means they do not fit (nothing is
-- added). The caller refuses n > limit before asking.
INSERT INTO pc.rate_counters AS c (scope, key, window_start, count)
VALUES (sqlc.arg(scope), sqlc.arg(key),
        date_bin(make_interval(secs => sqlc.arg(window_seconds)::float8), now(), timestamptz '1970-01-01 00:00:00+00'),
        sqlc.arg(n)::int)
ON CONFLICT (scope, key, window_start) DO UPDATE SET count = c.count + EXCLUDED.count
WHERE c.count + EXCLUDED.count <= sqlc.arg(max_count)::int
RETURNING c.count;

-- name: DeleteOldRateCounters :execrows
-- The janitor: windows that started more than two hours ago.
DELETE FROM pc.rate_counters WHERE window_start < now() - interval '2 hours';
