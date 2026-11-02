-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- The behaviour rollup's index on pc.transactions (G0 M27 D502, D526 P8).
-- The rollup reads an org's transactions by time; nothing else does. It is
-- built concurrently, outside a transaction, so writes to pc.transactions
-- go on during the build. A build that failed leaves an invalid index,
-- which the first statement drops before the next try.

-- +goose NO TRANSACTION

-- +goose Up
-- squawk: this migration runs outside a transaction (goose NO TRANSACTION
-- above), which CONCURRENTLY needs; .squawk.toml assumes every migration
-- runs in one.
-- squawk-ignore ban-concurrent-index-creation-in-transaction
DROP INDEX CONCURRENTLY IF EXISTS pc.transactions_behavior;
-- squawk-ignore ban-concurrent-index-creation-in-transaction
CREATE INDEX CONCURRENTLY IF NOT EXISTS transactions_behavior ON pc.transactions (org_id, created_at);

-- +goose Down
DROP INDEX CONCURRENTLY IF EXISTS pc.transactions_behavior;
