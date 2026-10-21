-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- The shared rate limiter (G0 M13 D9, HR-376). Limits that must hold
-- across replicas (automation inbound per source, AuthZEN per enforcement
-- point) count here, in fixed windows aligned to the Unix epoch: one row
-- per scope, key and window, raised atomically by INSERT … ON CONFLICT DO
-- UPDATE. The table is global: it is written only in a global transaction
-- of the purpose "rate_limit", and has no row-level security because it
-- holds no tenant data — a key is an opaque id that carries the org id
-- where one applies. It is UNLOGGED: counters are short-lived and losing
-- them in a crash only starts every window afresh. The janitor removes
-- windows older than two hours.

-- +goose Up
CREATE UNLOGGED TABLE pc.rate_counters (
    scope        text        NOT NULL CHECK (scope ~ '^[a-z][a-z0-9_.]{0,63}$'),
    key          text        NOT NULL CHECK (char_length(key) BETWEEN 1 AND 256),
    window_start timestamptz NOT NULL,
    count        integer     NOT NULL CHECK (count >= 0),
    PRIMARY KEY (scope, key, window_start)
);
CREATE INDEX rate_counters_window ON pc.rate_counters (window_start);

GRANT SELECT, INSERT, DELETE ON pc.rate_counters TO pc_app;
GRANT UPDATE (count) ON pc.rate_counters TO pc_app;

-- +goose Down
DROP TABLE pc.rate_counters;
