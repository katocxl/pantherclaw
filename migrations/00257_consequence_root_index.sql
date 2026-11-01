-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

-- G0 M22 D33: the causal graph finds a decision's consequence transactions
-- by their root. Few transactions are consequences, so the index is partial.

-- +goose Up
-- squawk: consequence_root is set only on the few transactions an accepted
-- consequence opened, so the index stays small, though the build reads the
-- whole table and holds writes to it until it ends; goose runs each migration
-- in one transaction (.squawk.toml), so CONCURRENTLY is not possible.
-- squawk-ignore require-concurrent-index-creation
CREATE INDEX transactions_consequence_root ON pc.transactions (org_id, consequence_root)
    WHERE consequence_root IS NOT NULL;

-- +goose Down
DROP INDEX pc.transactions_consequence_root;
