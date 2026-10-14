-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- The coverage snapshot a decision receipt's claim names (G0 M9 track A
-- slice A6; HR-217), for lookups: which decisions claimed a snapshot. The
-- claim itself lives in the signed receipt; this column only indexes it,
-- and outlives a receipt body removed by retention.

-- +goose Up
ALTER TABLE pc.decision_receipts ADD COLUMN coverage_snapshot_id uuid;
ALTER TABLE pc.decision_receipts ADD CONSTRAINT decision_receipts_coverage_snapshot
    FOREIGN KEY (org_id, coverage_snapshot_id) REFERENCES pc.coverage_snapshots (org_id, id);
CREATE INDEX decision_receipts_coverage_snapshot ON pc.decision_receipts (org_id, coverage_snapshot_id)
    WHERE coverage_snapshot_id IS NOT NULL;

-- +goose Down
DROP INDEX pc.decision_receipts_coverage_snapshot;
ALTER TABLE pc.decision_receipts DROP COLUMN coverage_snapshot_id;
