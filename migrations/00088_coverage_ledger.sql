-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- An invalidation's coverage.invalidation ledger entry (G0 M9 track A
-- slice A5; HR-211, HR-217). The reassess job enters each invalidation in
-- the ledger when it marks it reassessed, in the same transaction; an
-- evidence bundle carries the entries of a scope's invalidations beside
-- the receipts whose coverage claims they lapse.

-- +goose Up
ALTER TABLE pc.coverage_invalidations ADD COLUMN ledger_entry_id uuid;
ALTER TABLE pc.coverage_invalidations
    ADD CONSTRAINT coverage_invalidations_ledger_entry FOREIGN KEY (org_id, ledger_entry_id)
        REFERENCES pc.ledger_entries (org_id, id),
    ADD CONSTRAINT coverage_invalidations_entered CHECK (ledger_entry_id IS NULL OR reassessed_at IS NOT NULL);
GRANT UPDATE (ledger_entry_id) ON pc.coverage_invalidations TO pc_app;

-- +goose Down
REVOKE UPDATE (ledger_entry_id) ON pc.coverage_invalidations FROM pc_app;
ALTER TABLE pc.coverage_invalidations DROP COLUMN ledger_entry_id;
