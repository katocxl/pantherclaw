-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- The deployment-wide root log (G0 M35 D1041; HR-781, HR-782). Each
-- anchoring period's global tree is built afresh over the orgs' blinded
-- leaves, so on its own it is no append-only log. global_log_leaves makes
-- one: its leaves are the anchors' global roots in period order, stored as
-- C2SP tlog tiles of height 8 (global_log_tiles, insert-only like
-- ledger_tiles), and global_checkpoints keeps each signed C2SP checkpoint
-- note of origin "<log origin>/global", signed by the global_log key. Only
-- this log is ever shown to witnesses (FQ35-3); it holds global roots and
-- nothing that names an org.
--
-- These are platform tables without tenant data or org_id, written and read
-- in a global transaction for the "global_log" purpose, like pc.anchors
-- (no row security: HR-050 covers tenant tables). Evidence rows are
-- insert-only (HR-055).
--
-- Signing keys gain the purposes global_log (Ed25519) and receipts_pq
-- (ML-DSA-65, G0 M35 D1042), each pinned to its algorithm (HR-095).

-- +goose Up
CREATE TABLE pc.global_log_leaves (
    leaf_index bigint      PRIMARY KEY CHECK (leaf_index >= 0),
    anchor_id  uuid        NOT NULL UNIQUE REFERENCES pc.anchors (id),
    root       bytea       NOT NULL CHECK (octet_length(root) = 32),
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE pc.global_log_tiles (
    level      smallint    NOT NULL CHECK (level BETWEEN 0 AND 63),
    tile_index bigint      NOT NULL CHECK (tile_index >= 0),
    width      smallint    NOT NULL CHECK (width BETWEEN 1 AND 256),
    hashes     bytea       NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (level, tile_index, width),
    CHECK (octet_length(hashes) = 32 * width)
);

CREATE TABLE pc.global_checkpoints (
    tree_size  bigint      PRIMARY KEY CHECK (tree_size > 0),
    root_hash  bytea       NOT NULL CHECK (octet_length(root_hash) = 32),
    note       bytea       NOT NULL CHECK (octet_length(note) BETWEEN 64 AND 16384),
    kid        text        NOT NULL CHECK (char_length(kid) BETWEEN 1 AND 128),
    created_at timestamptz NOT NULL DEFAULT now()
);

GRANT SELECT, INSERT ON pc.global_log_leaves, pc.global_log_tiles, pc.global_checkpoints TO pc_app;
GRANT SELECT ON pc.global_log_leaves, pc.global_log_tiles, pc.global_checkpoints TO pc_audit_ro;

-- squawk: each CHECK only widens a value list; goose runs each migration in
-- one transaction, and NOT VALID then VALIDATE keeps the lock short.
ALTER TABLE pc.keys DROP CONSTRAINT keys_purpose_check;
ALTER TABLE pc.keys ADD CONSTRAINT keys_purpose_check
    CHECK (purpose IN ('receipts', 'permits', 'workload_tokens', 'checkpoints', 'access_tokens', 'gateway_ca',
                       'action_tokens', 'anchors', 'evidence_packs', 'checkpoints_pq', 'webhooks', 'a2a_card',
                       'mcp_tokens', 'global_log', 'receipts_pq')) NOT VALID;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.keys VALIDATE CONSTRAINT keys_purpose_check;
ALTER TABLE pc.keys DROP CONSTRAINT keys_algorithm_check;
ALTER TABLE pc.keys ADD CONSTRAINT keys_algorithm_check
    CHECK (algorithm IN ('EdDSA', 'ES256', 'ML-DSA-65') AND algorithm = CASE purpose
        WHEN 'anchors' THEN 'ES256' WHEN 'checkpoints_pq' THEN 'ML-DSA-65' WHEN 'receipts_pq' THEN 'ML-DSA-65'
        ELSE 'EdDSA' END) NOT VALID;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.keys VALIDATE CONSTRAINT keys_algorithm_check;

-- +goose Down
DELETE FROM pc.keys WHERE purpose IN ('global_log', 'receipts_pq');
ALTER TABLE pc.keys DROP CONSTRAINT keys_algorithm_check;
ALTER TABLE pc.keys ADD CONSTRAINT keys_algorithm_check
    CHECK (algorithm IN ('EdDSA', 'ES256', 'ML-DSA-65') AND algorithm = CASE purpose
        WHEN 'anchors' THEN 'ES256' WHEN 'checkpoints_pq' THEN 'ML-DSA-65' ELSE 'EdDSA' END);
ALTER TABLE pc.keys DROP CONSTRAINT keys_purpose_check;
ALTER TABLE pc.keys ADD CONSTRAINT keys_purpose_check
    CHECK (purpose IN ('receipts', 'permits', 'workload_tokens', 'checkpoints', 'access_tokens', 'gateway_ca',
                       'action_tokens', 'anchors', 'evidence_packs', 'checkpoints_pq', 'webhooks', 'a2a_card',
                       'mcp_tokens'));
DROP TABLE pc.global_checkpoints;
DROP TABLE pc.global_log_tiles;
DROP TABLE pc.global_log_leaves;
