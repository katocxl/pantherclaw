-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- The shared rate limiter (G0 M13 D9, HR-376), in a global transaction of
-- the purpose "rate_limit". Windows are aligned to the Unix epoch on the
-- database's clock, so every replica counts in the same window.

-- name: TakeRateCounter :one
-- Adds n events to the key's current window if they fit within the limit.
-- count is the new count, 0 when they do not fit (nothing is added);
-- retry_seconds is the time left in the window on the database's clock.
-- The caller refuses n > limit before asking.
WITH w AS (
    SELECT date_bin(make_interval(secs => sqlc.arg(window_seconds)::float8), now(), timestamptz '1970-01-01 00:00:00+00') AS start
), ins AS (
    INSERT INTO pc.rate_counters AS c (scope, key, window_start, count)
    SELECT sqlc.arg(scope), sqlc.arg(key), w.start, sqlc.arg(n)::int FROM w
    ON CONFLICT (scope, key, window_start) DO UPDATE SET count = c.count + EXCLUDED.count
    WHERE c.count + EXCLUDED.count <= sqlc.arg(max_count)::int
    RETURNING c.count
)
SELECT coalesce((SELECT ins.count FROM ins), 0)::int AS count,
       extract(epoch FROM w.start + make_interval(secs => sqlc.arg(window_seconds)::float8) - now())::float8 AS retry_seconds
FROM w;

-- name: DeleteOldRateCounters :execrows
-- The janitor: windows that started more than two hours ago.
DELETE FROM pc.rate_counters WHERE window_start < now() - interval '2 hours';
