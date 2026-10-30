-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
-- API-key IP allow lists (G0 M18 D153, PN-012.8, HR-475): an API key may
-- carry up to 32 CIDR ranges, set when it is created. NULL means any
-- address. pc_app has no UPDATE on the column, so the list is immutable:
-- rotating the key is the way to change it. Authentication refuses a key
-- used from an address outside its ranges exactly like a bad key.
-- +goose Up
ALTER TABLE pc.api_keys ADD COLUMN allowed_cidrs cidr[]
    CHECK (allowed_cidrs IS NULL OR (cardinality(allowed_cidrs) BETWEEN 1 AND 32
        AND array_position(allowed_cidrs, NULL) IS NULL));

GRANT SELECT (allowed_cidrs) ON pc.api_keys TO pc_audit_ro;

-- +goose Down
REVOKE SELECT (allowed_cidrs) ON pc.api_keys FROM pc_audit_ro;
ALTER TABLE pc.api_keys DROP COLUMN allowed_cidrs;
