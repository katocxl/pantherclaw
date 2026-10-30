-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Delivery receipts of export destinations (G0 M20 D252; F517, HR-514..516,
-- T-223). Every push has one receipt, delivered or not: which artifact, who
-- asked, the object key, its size and SHA-256, and what the destination
-- answered. A multipart upload's id is stored before its first part, so an
-- upload a crash left behind is still aborted (abort_state, HR-516).
--
-- A receipt outlives the copy here. When the artifact is removed here
-- (removed_here_at) a signed removal notice is pushed next to the object
-- (notice_state); nothing here ever says the remote copy is gone (HR-515).
-- A receipt is never deleted, and what it says about delivered bytes never
-- changes.

-- +goose Up
CREATE TABLE pc.export_receipts (
    org_id          uuid        NOT NULL REFERENCES pc.orgs (id),
    id              uuid        NOT NULL,
    destination_id  uuid        NOT NULL,
    class           text        NOT NULL CHECK (class IN ('evidence_packs', 'proof_bundles', 'org_exports')),
    -- The pack or the data request; for a streamed export NULL until its
    -- build claims the receipt.
    artifact_id     uuid,
    streamed        boolean     NOT NULL DEFAULT false,
    -- A proof bundle's ledger range.
    from_seq        bigint      CHECK (from_seq IS NULL OR from_seq > 0),
    to_seq          bigint,
    requested_by    uuid        NOT NULL,
    object_key      text        NOT NULL CHECK (char_length(object_key) BETWEEN 1 AND 1024),
    state           text        NOT NULL DEFAULT 'QUEUED' CHECK (state IN ('QUEUED', 'PUSHING', 'DELIVERED', 'FAILED')),
    upload_id       text        CHECK (upload_id IS NULL OR char_length(upload_id) BETWEEN 1 AND 1024),
    abort_state     text        NOT NULL DEFAULT 'NONE' CHECK (abort_state IN ('NONE', 'PENDING', 'ABORTED')),
    size_bytes      bigint      NOT NULL DEFAULT 0 CHECK (size_bytes >= 0),
    sha256          bytea       CHECK (sha256 IS NULL OR octet_length(sha256) = 32),
    parts           integer     NOT NULL DEFAULT 0 CHECK (parts >= 0),
    etag            text        CHECK (etag IS NULL OR char_length(etag) <= 256),
    attempts        integer     NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    last_status     integer     CHECK (last_status IS NULL OR last_status BETWEEN 100 AND 599),
    failure_code    text        CHECK (failure_code IS NULL OR failure_code ~ '^[a-z0-9_]{1,64}$'),
    created_at      timestamptz NOT NULL DEFAULT now(),
    started_at      timestamptz,
    delivered_at    timestamptz,
    -- The copy here is gone; the signed notice follows.
    removed_here_at timestamptz,
    notice_state    text        NOT NULL DEFAULT 'NONE' CHECK (notice_state IN ('NONE', 'PENDING', 'SENT', 'UNDELIVERABLE')),
    notice_key      text        CHECK (notice_key IS NULL OR char_length(notice_key) BETWEEN 1 AND 1024),
    notice_sha256   bytea       CHECK (notice_sha256 IS NULL OR octet_length(notice_sha256) = 32),
    notice_sent_at  timestamptz,
    notice_attempts integer     NOT NULL DEFAULT 0 CHECK (notice_attempts >= 0),
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, destination_id) REFERENCES pc.export_destinations (org_id, id),
    FOREIGN KEY (org_id, requested_by) REFERENCES pc.users (org_id, id),
    CHECK ((class = 'proof_bundles') = (from_seq IS NOT NULL)),
    CHECK ((from_seq IS NULL) = (to_seq IS NULL) AND (to_seq IS NULL OR to_seq >= from_seq)),
    CHECK (class = 'org_exports' OR NOT streamed),
    CHECK (class <> 'evidence_packs' OR artifact_id IS NOT NULL),
    CHECK ((state = 'DELIVERED') = (delivered_at IS NOT NULL)),
    CHECK (state <> 'DELIVERED' OR sha256 IS NOT NULL),
    CHECK (state <> 'FAILED' OR failure_code IS NOT NULL),
    CHECK ((notice_state = 'NONE') = (removed_here_at IS NULL)),
    CHECK (removed_here_at IS NULL OR state = 'DELIVERED'),
    CHECK ((notice_state = 'SENT') = (notice_sent_at IS NOT NULL))
);
CREATE INDEX export_receipts_destination ON pc.export_receipts (org_id, destination_id, id DESC);
-- What the hourly sweep looks at.
CREATE INDEX export_receipts_removal ON pc.export_receipts (org_id, id) WHERE state = 'DELIVERED' AND removed_here_at IS NULL;
CREATE INDEX export_receipts_notices ON pc.export_receipts (org_id, id) WHERE notice_state = 'PENDING';
CREATE INDEX export_receipts_uploads ON pc.export_receipts (org_id, id) WHERE upload_id IS NOT NULL AND abort_state <> 'ABORTED';
-- A streamed export waiting for its build.
CREATE INDEX export_receipts_waiting ON pc.export_receipts (org_id, requested_by, id) WHERE streamed AND artifact_id IS NULL;

-- What a delivered receipt says never changes, and a removal is recorded
-- once (HR-514, HR-515).
-- +goose StatementBegin
CREATE FUNCTION pc.export_receipt_guard() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pc, pg_temp
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.state IS DISTINCT FROM 'QUEUED' OR NEW.delivered_at IS NOT NULL OR NEW.removed_here_at IS NOT NULL THEN
            RAISE EXCEPTION 'a receipt is inserted QUEUED' USING ERRCODE = 'check_violation';
        END IF;
        NEW.created_at := now();
        RETURN NEW;
    END IF;
    IF OLD.state = 'DELIVERED' AND (NEW.state IS DISTINCT FROM OLD.state OR NEW.size_bytes IS DISTINCT FROM OLD.size_bytes
            OR NEW.sha256 IS DISTINCT FROM OLD.sha256 OR NEW.parts IS DISTINCT FROM OLD.parts OR NEW.etag IS DISTINCT FROM OLD.etag
            OR NEW.delivered_at IS DISTINCT FROM OLD.delivered_at OR NEW.artifact_id IS DISTINCT FROM OLD.artifact_id) THEN
        RAISE EXCEPTION 'a delivered receipt never changes' USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.artifact_id IS NOT NULL AND NEW.artifact_id IS DISTINCT FROM OLD.artifact_id THEN
        RAISE EXCEPTION 'a receipt names one artifact' USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.removed_here_at IS NOT NULL AND NEW.removed_here_at IS DISTINCT FROM OLD.removed_here_at THEN
        RAISE EXCEPTION 'a removal is recorded once' USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.notice_state = 'SENT' AND NEW.notice_state IS DISTINCT FROM 'SENT' THEN
        RAISE EXCEPTION 'a sent notice stays sent' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER export_receipts_guard BEFORE INSERT OR UPDATE ON pc.export_receipts
    FOR EACH ROW EXECUTE FUNCTION pc.export_receipt_guard();
CREATE TRIGGER org_write_guard BEFORE INSERT OR UPDATE ON pc.export_receipts
    FOR EACH ROW EXECUTE FUNCTION pc.org_write_guard();

ALTER TABLE pc.export_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.export_receipts FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.export_receipts
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));

GRANT SELECT, INSERT ON pc.export_receipts TO pc_app;
GRANT UPDATE (artifact_id, state, upload_id, abort_state, size_bytes, sha256, parts, etag, attempts, last_status, failure_code,
    started_at, delivered_at, removed_here_at, notice_state, notice_key, notice_sha256, notice_sent_at, notice_attempts)
    ON pc.export_receipts TO pc_app;
GRANT SELECT ON pc.export_receipts TO pc_audit_ro;

-- +goose Down
DROP TABLE pc.export_receipts;
DROP FUNCTION pc.export_receipt_guard();
