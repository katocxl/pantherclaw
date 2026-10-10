-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Checkpoints (G0 M7 track B, design decisions 4, 8, 12, 16 and 17; HR-111,
-- HR-194, HR-195; PAP-1 §9.4). Each org's chained entry hashes are the
-- leaves of an RFC 9162 Merkle tree stored as C2SP tlog tiles of height 8.
-- ledger_tiles is insert-only: a partial tile that grows gets a new, wider
-- row, and readers use the widest. A checkpoint keeps the exact signed note.
-- evidence_integrity is the one mutable status row per org: a FAILED org is
-- no longer checkpointed until an operator investigates.
--
-- anchors is a global table with no tenant data: only the blinded leaves
-- and the global root (HR-195). An org's own leaf, its nonce and the
-- checkpoint it commits to stay in the org's anchor_leaves row; the link to
-- the anchor is not a foreign key, because tenant foreign keys lead with
-- org_id (HR-050) and anchors has none.
--
-- Signing keys gain ES256 (the anchors key) and ML-DSA-65 (the optional
-- checkpoints_pq key), each pinned to its purpose (HR-095), and the
-- evidence_packs purpose. Evidence rows gain the retention tombstone
-- (decision 4); the retention slice removes the bodies.

-- +goose Up
CREATE TABLE pc.ledger_tiles (
    org_id     uuid        NOT NULL REFERENCES pc.orgs (id),
    level      smallint    NOT NULL CHECK (level BETWEEN 0 AND 63),
    tile_index bigint      NOT NULL CHECK (tile_index >= 0),
    width      smallint    NOT NULL CHECK (width BETWEEN 1 AND 256),
    hashes     bytea       NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, level, tile_index, width),
    CHECK (octet_length(hashes) = 32 * width)
);

CREATE TABLE pc.checkpoints (
    org_id     uuid        NOT NULL REFERENCES pc.orgs (id),
    tree_size  bigint      NOT NULL CHECK (tree_size > 0),
    root_hash  bytea       NOT NULL CHECK (octet_length(root_hash) = 32),
    note       bytea       NOT NULL CHECK (octet_length(note) BETWEEN 64 AND 16384),
    kid        text        NOT NULL CHECK (char_length(kid) BETWEEN 1 AND 128),
    pq_kid     text        CHECK (pq_kid IS NULL OR char_length(pq_kid) BETWEEN 1 AND 128),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, tree_size)
);

CREATE TABLE pc.evidence_integrity (
    org_id        uuid        NOT NULL REFERENCES pc.orgs (id),
    state         text        NOT NULL DEFAULT 'OK' CHECK (state IN ('OK', 'FAILED')),
    failure_code  text        CHECK (failure_code IS NULL OR failure_code ~ '^[A-Z][A-Z0-9_]{0,63}$'),
    failed_seq    bigint      CHECK (failed_seq IS NULL OR failed_seq > 0),
    failed_at     timestamptz,
    verified_size bigint      CHECK (verified_size IS NULL OR verified_size > 0),
    verified_at   timestamptz,
    updated_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id),
    CHECK ((state = 'FAILED') = (failure_code IS NOT NULL AND failed_at IS NOT NULL)),
    CHECK ((verified_size IS NULL) = (verified_at IS NULL))
);

CREATE TABLE pc.anchors (
    id              uuid        PRIMARY KEY,
    period          timestamptz NOT NULL UNIQUE,
    leaves          bytea       NOT NULL CHECK (octet_length(leaves) BETWEEN 32 AND 33554432 AND octet_length(leaves) % 32 = 0),
    root            bytea       NOT NULL CHECK (octet_length(root) = 32),
    statement       bytea       NOT NULL CHECK (octet_length(statement) BETWEEN 2 AND 4096),
    signature       bytea       NOT NULL CHECK (octet_length(signature) BETWEEN 8 AND 256),
    kid             text        NOT NULL CHECK (char_length(kid) BETWEEN 1 AND 128),
    state           text        NOT NULL DEFAULT 'PENDING' CHECK (state IN ('PENDING', 'ANCHORED', 'FAILED')),
    attempts        integer     NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 1000),
    next_at         timestamptz NOT NULL DEFAULT now(),
    error_code      text        CHECK (error_code IS NULL OR error_code ~ '^[A-Z][A-Z0-9_]{0,63}$'),
    rekor_entry     bytea       CHECK (rekor_entry IS NULL OR octet_length(rekor_entry) BETWEEN 2 AND 1048576),
    timestamp_token bytea       CHECK (timestamp_token IS NULL OR octet_length(timestamp_token) BETWEEN 1 AND 65536),
    created_at      timestamptz NOT NULL DEFAULT now(),
    anchored_at     timestamptz,
    -- An anchor counts only with both responses kept (HR-195).
    CHECK ((state = 'ANCHORED') = (rekor_entry IS NOT NULL AND timestamp_token IS NOT NULL AND anchored_at IS NOT NULL))
);

CREATE TABLE pc.anchor_leaves (
    org_id          uuid        NOT NULL REFERENCES pc.orgs (id),
    anchor_id       uuid        NOT NULL,
    leaf_index      integer     NOT NULL CHECK (leaf_index BETWEEN 0 AND 1048575),
    nonce           bytea       NOT NULL CHECK (octet_length(nonce) = 32),
    checkpoint_size bigint      NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, anchor_id),
    FOREIGN KEY (org_id, checkpoint_size) REFERENCES pc.checkpoints (org_id, tree_size)
);

-- +goose StatementBegin
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['ledger_tiles', 'checkpoints', 'evidence_integrity', 'anchor_leaves']
    LOOP
        EXECUTE format('ALTER TABLE pc.%I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE pc.%I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format($p$CREATE POLICY tenant_isolation ON pc.%I
            USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
            WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))$p$, t);
    END LOOP;
END
$$;
-- +goose StatementEnd

-- Tiles, checkpoints and anchor leaves are evidence: no UPDATE or DELETE
-- (HR-055). An anchor changes only its state and the responses it waits for.
GRANT SELECT, INSERT ON pc.ledger_tiles, pc.checkpoints, pc.evidence_integrity, pc.anchors, pc.anchor_leaves TO pc_app;
GRANT UPDATE (state, failure_code, failed_seq, failed_at, verified_size, verified_at, updated_at)
    ON pc.evidence_integrity TO pc_app;
GRANT UPDATE (state, attempts, next_at, error_code, rekor_entry, timestamp_token, anchored_at) ON pc.anchors TO pc_app;
GRANT SELECT ON pc.ledger_tiles, pc.checkpoints, pc.evidence_integrity, pc.anchors, pc.anchor_leaves TO pc_audit_ro;

-- Signing keys: three algorithms, each pinned to its purposes (HR-095), and
-- the public key length of each (EdDSA: the 32-byte key; ES256: PKIX DER of
-- a P-256 key; ML-DSA-65: the FIPS 204 encoding).
ALTER TABLE pc.keys DROP CONSTRAINT keys_purpose_check;
ALTER TABLE pc.keys ADD CONSTRAINT keys_purpose_check
    CHECK (purpose IN ('receipts', 'permits', 'workload_tokens', 'checkpoints', 'access_tokens', 'gateway_ca',
                       'action_tokens', 'anchors', 'evidence_packs', 'checkpoints_pq')) NOT VALID;
ALTER TABLE pc.keys VALIDATE CONSTRAINT keys_purpose_check;
ALTER TABLE pc.keys DROP CONSTRAINT keys_algorithm_check;
ALTER TABLE pc.keys ADD CONSTRAINT keys_algorithm_check
    CHECK (algorithm IN ('EdDSA', 'ES256', 'ML-DSA-65') AND algorithm = CASE purpose
        WHEN 'anchors' THEN 'ES256' WHEN 'checkpoints_pq' THEN 'ML-DSA-65' ELSE 'EdDSA' END) NOT VALID;
ALTER TABLE pc.keys VALIDATE CONSTRAINT keys_algorithm_check;
ALTER TABLE pc.keys DROP CONSTRAINT keys_public_key_check;
ALTER TABLE pc.keys ADD CONSTRAINT keys_public_key_check
    CHECK ((algorithm = 'EdDSA' AND octet_length(public_key) = 32)
        OR (algorithm = 'ES256' AND octet_length(public_key) = 91)
        OR (algorithm = 'ML-DSA-65' AND octet_length(public_key) = 1952)) NOT VALID;
ALTER TABLE pc.keys VALIDATE CONSTRAINT keys_public_key_check;

-- The retention tombstone (decision 4): when and under which retention
-- policy revision a body was removed. Hashes, links and leaves stay.
ALTER TABLE pc.ledger_entries
    ADD COLUMN body_removed_at   timestamptz,
    ADD COLUMN removed_by_policy uuid,
    ADD CONSTRAINT ledger_entries_removal CHECK ((body_removed_at IS NULL) = (removed_by_policy IS NULL));
ALTER TABLE pc.decision_receipts
    ADD COLUMN body_removed_at   timestamptz,
    ADD COLUMN removed_by_policy uuid,
    ADD CONSTRAINT decision_receipts_removal CHECK ((body_removed_at IS NULL) = (removed_by_policy IS NULL));
ALTER TABLE pc.execution_receipts
    ADD COLUMN body_removed_at   timestamptz,
    ADD COLUMN removed_by_policy uuid,
    ADD CONSTRAINT execution_receipts_removal CHECK ((body_removed_at IS NULL) = (removed_by_policy IS NULL));
ALTER TABLE pc.effect_receipts
    ADD COLUMN body_removed_at   timestamptz,
    ADD COLUMN removed_by_policy uuid,
    ADD CONSTRAINT effect_receipts_removal CHECK ((body_removed_at IS NULL) = (removed_by_policy IS NULL));

-- Bundles for a sequence range find the receipts their entries record.
CREATE INDEX decision_receipts_ledger_entry ON pc.decision_receipts (org_id, ledger_entry_id);
CREATE INDEX execution_receipts_ledger_entry ON pc.execution_receipts (org_id, ledger_entry_id);
CREATE INDEX effect_receipts_ledger_entry ON pc.effect_receipts (org_id, ledger_entry_id);

-- The worker finds orgs whose chain grew past their latest checkpoint, and
-- orgs whose chain was not re-verified for a day (HR-194).
GRANT SELECT (seq) ON pc.ledger_heads TO pc_lister;
GRANT SELECT (org_id, tree_size) ON pc.checkpoints TO pc_lister;
GRANT SELECT (org_id, state, verified_at) ON pc.evidence_integrity TO pc_lister;

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION pc.cross_org_list(p_purpose text, p_max_rows integer)
RETURNS TABLE (org_id uuid, id uuid)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pc, pg_temp
AS $$
BEGIN
    IF p_max_rows IS NULL OR p_max_rows < 1 OR p_max_rows > 10000 THEN
        RAISE EXCEPTION 'cross_org_list: max_rows must be between 1 and 10000';
    END IF;
    INSERT INTO pc.cross_org_list_audit (purpose, max_rows, caller)
    VALUES (left(p_purpose, 64), p_max_rows, session_user);
    CASE p_purpose
        WHEN 'orgs' THEN
            RETURN QUERY SELECT o.id, o.id FROM pc.orgs o WHERE o.state = 'ACTIVE' ORDER BY o.id LIMIT p_max_rows;
        WHEN 'ledger_unchained' THEN
            RETURN QUERY
                SELECT DISTINCT e.org_id, e.org_id
                FROM pc.ledger_entries e
                LEFT JOIN pc.ledger_heads h ON h.org_id = e.org_id
                WHERE e.xid >= coalesce(h.xid_watermark, '0'::xid8)
                ORDER BY 1
                LIMIT p_max_rows;
        WHEN 'permits_sweep' THEN
            RETURN QUERY
                SELECT DISTINCT p.org_id, p.org_id
                FROM pc.permits p
                WHERE (p.state = 'ISSUED' AND p.expires_at < now())
                   OR (p.state = 'DISPATCHING' AND p.dispatching_at < now() - interval '30 seconds')
                ORDER BY 1
                LIMIT p_max_rows;
        WHEN 'verifications_due' THEN
            RETURN QUERY
                SELECT DISTINCT v.org_id, v.org_id
                FROM pc.verifications v
                WHERE (v.state IN ('PENDING', 'LEASED') AND v.deadline_at <= now())
                   OR (v.state = 'LEASED' AND v.lease_expires_at <= now())
                ORDER BY 1
                LIMIT p_max_rows;
        WHEN 'checkpoints_due' THEN
            -- Orgs whose chain grew past their latest checkpoint and whose
            -- checkpointing has not stopped.
            RETURN QUERY
                SELECT h.org_id, h.org_id
                FROM pc.ledger_heads h
                WHERE h.seq > coalesce((SELECT max(c.tree_size) FROM pc.checkpoints c WHERE c.org_id = h.org_id), 0)
                  AND NOT EXISTS (SELECT 1 FROM pc.evidence_integrity i WHERE i.org_id = h.org_id AND i.state = 'FAILED')
                ORDER BY 1
                LIMIT p_max_rows;
        WHEN 'integrity_due' THEN
            -- Orgs with a checkpoint whose chain was not re-verified in the
            -- last day.
            RETURN QUERY
                SELECT h.org_id, h.org_id
                FROM pc.ledger_heads h
                WHERE EXISTS (SELECT 1 FROM pc.checkpoints c WHERE c.org_id = h.org_id)
                  AND NOT EXISTS (SELECT 1 FROM pc.evidence_integrity i WHERE i.org_id = h.org_id
                                  AND (i.state = 'FAILED' OR i.verified_at > now() - interval '1 day'))
                ORDER BY 1
                LIMIT p_max_rows;
        ELSE
            RAISE EXCEPTION 'cross_org_list: unknown purpose';
    END CASE;
END;
$$;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION pc.cross_org_list(p_purpose text, p_max_rows integer)
RETURNS TABLE (org_id uuid, id uuid)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pc, pg_temp
AS $$
BEGIN
    IF p_max_rows IS NULL OR p_max_rows < 1 OR p_max_rows > 10000 THEN
        RAISE EXCEPTION 'cross_org_list: max_rows must be between 1 and 10000';
    END IF;
    INSERT INTO pc.cross_org_list_audit (purpose, max_rows, caller)
    VALUES (left(p_purpose, 64), p_max_rows, session_user);
    CASE p_purpose
        WHEN 'orgs' THEN
            RETURN QUERY SELECT o.id, o.id FROM pc.orgs o WHERE o.state = 'ACTIVE' ORDER BY o.id LIMIT p_max_rows;
        WHEN 'ledger_unchained' THEN
            RETURN QUERY
                SELECT DISTINCT e.org_id, e.org_id
                FROM pc.ledger_entries e
                LEFT JOIN pc.ledger_heads h ON h.org_id = e.org_id
                WHERE e.xid >= coalesce(h.xid_watermark, '0'::xid8)
                ORDER BY 1
                LIMIT p_max_rows;
        WHEN 'permits_sweep' THEN
            RETURN QUERY
                SELECT DISTINCT p.org_id, p.org_id
                FROM pc.permits p
                WHERE (p.state = 'ISSUED' AND p.expires_at < now())
                   OR (p.state = 'DISPATCHING' AND p.dispatching_at < now() - interval '30 seconds')
                ORDER BY 1
                LIMIT p_max_rows;
        WHEN 'verifications_due' THEN
            RETURN QUERY
                SELECT DISTINCT v.org_id, v.org_id
                FROM pc.verifications v
                WHERE (v.state IN ('PENDING', 'LEASED') AND v.deadline_at <= now())
                   OR (v.state = 'LEASED' AND v.lease_expires_at <= now())
                ORDER BY 1
                LIMIT p_max_rows;
        ELSE
            RAISE EXCEPTION 'cross_org_list: unknown purpose';
    END CASE;
END;
$$;
-- +goose StatementEnd
REVOKE SELECT (org_id, state, verified_at) ON pc.evidence_integrity FROM pc_lister;
REVOKE SELECT (org_id, tree_size) ON pc.checkpoints FROM pc_lister;
REVOKE SELECT (seq) ON pc.ledger_heads FROM pc_lister;
DROP INDEX pc.effect_receipts_ledger_entry;
DROP INDEX pc.execution_receipts_ledger_entry;
DROP INDEX pc.decision_receipts_ledger_entry;
ALTER TABLE pc.effect_receipts DROP CONSTRAINT effect_receipts_removal, DROP COLUMN removed_by_policy,
    DROP COLUMN body_removed_at;
ALTER TABLE pc.execution_receipts DROP CONSTRAINT execution_receipts_removal, DROP COLUMN removed_by_policy,
    DROP COLUMN body_removed_at;
ALTER TABLE pc.decision_receipts DROP CONSTRAINT decision_receipts_removal, DROP COLUMN removed_by_policy,
    DROP COLUMN body_removed_at;
ALTER TABLE pc.ledger_entries DROP CONSTRAINT ledger_entries_removal, DROP COLUMN removed_by_policy,
    DROP COLUMN body_removed_at;
-- The new purposes' keys are platform keys; RLS is forced even for the
-- table owner.
SELECT set_config('app.org_id', '00000000-0000-7000-8000-000000000001', true);
DELETE FROM pc.keys WHERE purpose IN ('anchors', 'evidence_packs', 'checkpoints_pq');
SELECT set_config('app.org_id', '', true);
ALTER TABLE pc.keys DROP CONSTRAINT keys_public_key_check;
ALTER TABLE pc.keys ADD CONSTRAINT keys_public_key_check CHECK (octet_length(public_key) = 32) NOT VALID;
ALTER TABLE pc.keys DROP CONSTRAINT keys_algorithm_check;
ALTER TABLE pc.keys ADD CONSTRAINT keys_algorithm_check CHECK (algorithm = 'EdDSA') NOT VALID;
ALTER TABLE pc.keys DROP CONSTRAINT keys_purpose_check;
ALTER TABLE pc.keys ADD CONSTRAINT keys_purpose_check
    CHECK (purpose IN ('receipts', 'permits', 'workload_tokens', 'checkpoints', 'access_tokens', 'gateway_ca',
                       'action_tokens')) NOT VALID;
DROP TABLE pc.anchor_leaves;
DROP TABLE pc.anchors;
DROP TABLE pc.evidence_integrity;
DROP TABLE pc.checkpoints;
DROP TABLE pc.ledger_tiles;
