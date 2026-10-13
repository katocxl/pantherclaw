-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Restoring an approval whose permit was never used (G0 M6 slice 23,
-- HR-011, founder decision 2026-10-10). A permit reaches RELEASED only from
-- ISSUED: it expired, or BeginDispatch refused it, so the server can prove
-- nothing was sent. When such a permit had consumed an approval, the
-- approval returns to APPROVED and the transaction is reopened, so the
-- agent's resubmission of the same run and action (PAP-1 §8) is evaluated
-- again and may get a new permit. A transaction therefore keeps at most
-- one current permit: a released one is marked replaced when its successor
-- is issued, and every query that reads "the transaction's permit" reads
-- the one that is not replaced. A replaced permit stays as evidence. The
-- approval request needs no change: 00050 already lets pc_app clear
-- consumed_at, permit_id and ended_at. Reaches main after 00071-00074. The
-- down migration fails while a transaction has a replaced permit.

-- +goose Up
ALTER TABLE pc.permits
    ADD COLUMN replaced boolean NOT NULL DEFAULT false,
    ADD CONSTRAINT permits_replaced CHECK (NOT replaced OR state = 'RELEASED'),
    DROP CONSTRAINT permits_org_id_transaction_id_key;
CREATE UNIQUE INDEX permits_current ON pc.permits (org_id, transaction_id) WHERE NOT replaced;

GRANT UPDATE (replaced) ON pc.permits TO pc_app;

-- +goose Down
REVOKE UPDATE (replaced) ON pc.permits FROM pc_app;
DROP INDEX pc.permits_current;
ALTER TABLE pc.permits
    ADD CONSTRAINT permits_org_id_transaction_id_key UNIQUE (org_id, transaction_id),
    DROP CONSTRAINT permits_replaced,
    DROP COLUMN replaced;
