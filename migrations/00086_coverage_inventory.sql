-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- The route inventory's watermark (G0 M9 track A slice A4; F443, F450).
-- The inventory reads each org's transactions in id order (UUIDv7, so
-- creation order) after transactions_after and records the channels and
-- route modes the gateway carried as observed routes; transactions has no
-- other index the inventory could use, and a full scan per refresh would
-- not scale.

-- +goose Up
CREATE TABLE pc.coverage_inventory (
    org_id             uuid        NOT NULL REFERENCES pc.orgs (id),
    transactions_after uuid        NOT NULL,
    refreshed_at       timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id)
);

ALTER TABLE pc.coverage_inventory ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.coverage_inventory FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.coverage_inventory
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));

GRANT SELECT, INSERT ON pc.coverage_inventory TO pc_app;
GRANT UPDATE (transactions_after, refreshed_at) ON pc.coverage_inventory TO pc_app;
GRANT SELECT ON pc.coverage_inventory TO pc_audit_ro;

-- +goose Down
DROP TABLE pc.coverage_inventory;
