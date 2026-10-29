-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Downstream verification (G0 M17, F414, D102, HR-450, HR-451). When an
-- action is confirmed and its decision predicted consequences, the action
-- carries the state of those consequences apart from its own effect:
-- PENDING while an opened consequence transaction is not yet confirmed,
-- CONFIRMED once every one is, UNCONFIRMED when one is not (a reconciliation
-- of kind consequence_unconfirmed or a negative effect state), and
-- NOT_VERIFIABLE when consequences were predicted but none could be opened
-- for verification. NULL when nothing was predicted. CONFIRMED appends an
-- effect receipt at level downstream with basis consequence; earlier
-- receipts are never rewritten.
--
-- Precedence over the whole subtree (D131): UNCONFIRMED > NOT_VERIFIABLE >
-- PENDING > CONFIRMED. downstream_not_verifiable remembers that one of the
-- action's predicted consequences could not be opened, so a later roll-up
-- (a person's "occurred" after UNCONFIRMED) never lifts it above
-- NOT_VERIFIABLE; once set it is never cleared.
--
-- Chains (D104): a consequence transaction names the action at the root of
-- its chain and the position of the predicted consequence it was opened
-- for in that action's latest evaluation, so that once it is confirmed it
-- opens the consequences that follow from that position (depth + 1).

-- Every CHECK is added NOT VALID and validated apart: VALIDATE CONSTRAINT
-- takes only SHARE UPDATE EXCLUSIVE, so decisions and reports keep writing
-- while pc.transactions and pc.effect_receipts are scanned (as 00163).

-- +goose Up
ALTER TABLE pc.transactions
    ADD COLUMN downstream_state text,
    ADD COLUMN downstream_not_verifiable boolean NOT NULL DEFAULT false,
    ADD COLUMN consequence_root uuid,
    ADD COLUMN consequence_position integer,
    ADD CONSTRAINT transactions_downstream_state
        CHECK (downstream_state IN ('PENDING', 'CONFIRMED', 'UNCONFIRMED', 'NOT_VERIFIABLE')) NOT VALID,
    ADD CONSTRAINT transactions_consequence_position CHECK (consequence_position BETWEEN 0 AND 255) NOT VALID,
    ADD CONSTRAINT transactions_downstream CHECK (NOT downstream_not_verifiable OR downstream_state IS NOT NULL) NOT VALID,
    ADD CONSTRAINT transactions_consequence_origin CHECK ((consequence_root IS NULL) = (consequence_position IS NULL)) NOT VALID;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.transactions VALIDATE CONSTRAINT transactions_downstream_state;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.transactions VALIDATE CONSTRAINT transactions_consequence_position;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.transactions VALIDATE CONSTRAINT transactions_downstream;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.transactions VALIDATE CONSTRAINT transactions_consequence_origin;

GRANT UPDATE (downstream_state, downstream_not_verifiable) ON pc.transactions TO pc_app;

ALTER TABLE pc.effect_receipts
    DROP CONSTRAINT effect_receipts_basis_check,
    ADD CONSTRAINT effect_receipts_basis_check CHECK (basis IN ('verifier', 'late_report', 'target_log', 'person',
        'compensation', 'definition', 'deadline', 'consequence')) NOT VALID;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.effect_receipts VALIDATE CONSTRAINT effect_receipts_basis_check;

-- +goose Down
-- Effect receipts are evidence: a down migration never deletes one, so it
-- fails while a downstream receipt exists.
ALTER TABLE pc.effect_receipts
    DROP CONSTRAINT effect_receipts_basis_check,
    ADD CONSTRAINT effect_receipts_basis_check CHECK (basis IN ('verifier', 'late_report', 'target_log', 'person',
        'compensation', 'definition', 'deadline')) NOT VALID;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.effect_receipts VALIDATE CONSTRAINT effect_receipts_basis_check;

REVOKE UPDATE (downstream_state, downstream_not_verifiable) ON pc.transactions FROM pc_app;

ALTER TABLE pc.transactions DROP CONSTRAINT transactions_consequence_origin, DROP CONSTRAINT transactions_downstream,
    DROP CONSTRAINT transactions_consequence_position, DROP CONSTRAINT transactions_downstream_state,
    DROP COLUMN consequence_position, DROP COLUMN consequence_root, DROP COLUMN downstream_not_verifiable,
    DROP COLUMN downstream_state;
