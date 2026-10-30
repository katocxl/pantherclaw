-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Grant flows (G0 M16 D75, D94, HR-432): the data flows a grant revision
-- allows after a sensitive read in its run tree, stored with the revision
-- as its bounds, requirements and limits are. NULL allows none, as for
-- every revision stored before this migration. pc_app's table-level
-- SELECT and INSERT on grant_revisions (00022) cover the new column;
-- revisions are never updated.
-- +goose Up
ALTER TABLE pc.grant_revisions ADD COLUMN flows bytea;
ALTER TABLE pc.grant_revisions
    ADD CONSTRAINT grant_revisions_flows
        CHECK (flows IS NULL OR octet_length(flows) BETWEEN 2 AND 65536) NOT VALID;
-- The new column is NULL in every row: the scan finds nothing to refuse,
-- and validating blocks neither reads nor writes.
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.grant_revisions VALIDATE CONSTRAINT grant_revisions_flows;

-- +goose Down
ALTER TABLE pc.grant_revisions DROP COLUMN flows;
