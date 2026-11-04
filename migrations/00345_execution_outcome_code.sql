-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- The code of a connector's refusal after the decision (G0 M30 D947a;
-- HR-715): the gateway records table_not_allowed or column_not_allowed with
-- the execution, and the threat map counts them in Seen. NULL for every
-- other execution.

-- +goose Up
ALTER TABLE pc.execution_attempts
    ADD COLUMN outcome_code text CHECK (outcome_code IS NULL OR char_length(outcome_code) BETWEEN 1 AND 64);

-- +goose Down
ALTER TABLE pc.execution_attempts DROP COLUMN outcome_code;
