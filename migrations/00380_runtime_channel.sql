-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Channel runtime (G0 M34 D990; HR-760): a cloud agent runtime's gateway
-- asked before it ran the tool itself. It is a cooperative channel, so a
-- decision on it is DELEGATED and its coverage PARTIAL; the gateway never
-- forwards it upstream. It widens the channel lists of transactions and
-- coverage routes, following 00150's pattern.

-- +goose Up
-- squawk: each CHECK only widens a value list; goose runs each migration
-- in one transaction, and NOT VALID then VALIDATE keeps the lock short.
ALTER TABLE pc.transactions
    DROP CONSTRAINT transactions_channel_check,
    ADD CONSTRAINT transactions_channel_check
        CHECK (channel IS NULL OR channel IN ('mcp', 'http', 'sdk', 'hook', 'authzen', 'a2a', 'runtime')) NOT VALID;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.transactions VALIDATE CONSTRAINT transactions_channel_check;

ALTER TABLE pc.coverage_routes
    DROP CONSTRAINT coverage_routes_channel_check,
    ADD CONSTRAINT coverage_routes_channel_check
        CHECK (channel IN ('http', 'mcp', 'sdk', 'hook', 'authzen', 'a2a', 'runtime')) NOT VALID;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.coverage_routes VALIDATE CONSTRAINT coverage_routes_channel_check;

-- +goose Down
ALTER TABLE pc.coverage_routes
    DROP CONSTRAINT coverage_routes_channel_check,
    ADD CONSTRAINT coverage_routes_channel_check CHECK (channel IN ('http', 'mcp', 'sdk', 'hook', 'authzen', 'a2a'));
ALTER TABLE pc.transactions
    DROP CONSTRAINT transactions_channel_check,
    ADD CONSTRAINT transactions_channel_check CHECK (channel IS NULL OR channel IN ('mcp', 'http', 'sdk', 'hook', 'authzen', 'a2a'));
