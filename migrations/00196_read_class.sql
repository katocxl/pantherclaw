-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Read history (G0 M16 D72, HR-430, HR-434): an allowed read records the
-- class of the data it returned, from the package's declarations, the
-- decision's data_classes obligation and classification facts, never
-- lowered. Only the class is recorded, never the content of the answer.
-- The data-flow hold (D73, D76) counts the pii and secret reads of a run
-- tree through the partial index. Transactions recorded before this
-- migration have none: no read class was known then.
-- +goose Up
ALTER TABLE pc.transactions ADD COLUMN read_class text;
ALTER TABLE pc.transactions
    ADD CONSTRAINT transactions_read_class
        CHECK (read_class IS NULL OR read_class IN ('public', 'internal', 'pii', 'secret')) NOT VALID;
-- The new column is NULL in every row: the scan finds nothing to refuse,
-- and validating blocks neither reads nor writes.
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.transactions VALIDATE CONSTRAINT transactions_read_class;

-- A read that is first held and then allowed is recorded by the evaluation
-- that allows it (UpdateDecision).
GRANT UPDATE (read_class) ON pc.transactions TO pc_app;

-- The sensitive reads of a run tree (D73): a small subset of transactions.
-- The new column is NULL in every row, so the partial index is empty and
-- built at once.
-- squawk-ignore require-concurrent-index-creation
CREATE INDEX transactions_sensitive_reads ON pc.transactions (org_id, run_id)
    WHERE read_class IN ('pii', 'secret');

-- +goose Down
DROP INDEX pc.transactions_sensitive_reads;
REVOKE UPDATE (read_class) ON pc.transactions FROM pc_app;
ALTER TABLE pc.transactions DROP COLUMN read_class;
