-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Witness cosignatures and receipt co-signatures (G0 M35 D1041, D1042;
-- HR-782..784).
--
-- global_checkpoint_cosignatures keeps each witness's verified
-- cosignature/v1 line (c2sp.org/tlog-cosignature) on a checkpoint of the
-- deployment-wide root log, one per (checkpoint, witness). The newest size
-- a witness cosigned is where the next add-checkpoint request starts
-- (c2sp.org/tlog-witness). A platform table without tenant data, written in
-- the "global_log" global transaction; insert-only (HR-055).
--
-- receipt_signatures keeps the PAP-1 §9.4 sigs[] of a receipt, by the
-- SHA-256 of its compact JWS: the ML-DSA-65 co-signature of the receipts_pq
-- key over the JWS signing input. It is written in the transaction that
-- stores the receipt, under the org's row security, and is evidence:
-- insert-only.

-- +goose Up
CREATE TABLE pc.global_checkpoint_cosignatures (
    tree_size  bigint      NOT NULL REFERENCES pc.global_checkpoints (tree_size),
    witness    text        NOT NULL CHECK (char_length(witness) BETWEEN 1 AND 256),
    key_id     bigint      NOT NULL CHECK (key_id BETWEEN 0 AND 4294967295),
    signed_at  timestamptz NOT NULL,
    line       text        NOT NULL CHECK (char_length(line) BETWEEN 16 AND 1024),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tree_size, witness)
);

CREATE INDEX global_checkpoint_cosignatures_witness ON pc.global_checkpoint_cosignatures (witness, tree_size DESC);

CREATE TABLE pc.receipt_signatures (
    org_id         uuid        NOT NULL REFERENCES pc.orgs (id),
    receipt_sha256 bytea       NOT NULL CHECK (octet_length(receipt_sha256) = 32),
    sigs           jsonb       NOT NULL CHECK (jsonb_typeof(sigs) = 'array' AND octet_length(sigs::text) BETWEEN 2 AND 32768),
    created_at     timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, receipt_sha256)
);

ALTER TABLE pc.receipt_signatures ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.receipt_signatures FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.receipt_signatures
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));
CREATE TRIGGER org_write_guard BEFORE INSERT OR UPDATE ON pc.receipt_signatures
    FOR EACH ROW EXECUTE FUNCTION pc.org_write_guard();

GRANT SELECT, INSERT ON pc.global_checkpoint_cosignatures, pc.receipt_signatures TO pc_app;
GRANT SELECT ON pc.global_checkpoint_cosignatures, pc.receipt_signatures TO pc_audit_ro;
-- +goose StatementBegin
DO $$ BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'pc_deleter') THEN
        GRANT SELECT, DELETE ON pc.receipt_signatures TO pc_deleter;
    END IF;
END $$;
-- +goose StatementEnd

-- +goose Down
DROP TABLE pc.receipt_signatures;
DROP TABLE pc.global_checkpoint_cosignatures;
