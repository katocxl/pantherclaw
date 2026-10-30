-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
-- Stream and wait leases (G0 M19 D201, HR-491): the caps on concurrent
-- operations streams per caller, containment streams per gateway
-- certificate and wait handles per instance hold across every replica.
-- A replica inserts a lease when a stream or wait opens and counts the
-- key's live leases in the same transaction, under a transaction lock of
-- the key, so two replicas never both take the last slot. holder names
-- the replica's process; key is an opaque id (a principal, a certificate
-- or an instance), never a credential. The holder renews its lease every
-- 10 seconds (expires_at = now() + 30 seconds on the database's clock) and
-- deletes it on close; a lease whose replica died expires after 30
-- seconds and no longer counts. Expired leases of an org are removed
-- whenever one of its leases is taken.
-- +goose Up
CREATE TABLE pc.stream_leases (
    org_id     uuid        NOT NULL REFERENCES pc.orgs (id),
    kind       text        NOT NULL CHECK (kind IN ('OPS_STREAM', 'CONTAINMENT_STREAM', 'WAIT')),
    key        text        NOT NULL CHECK (char_length(key) BETWEEN 1 AND 256),
    id         uuid        NOT NULL,
    holder     text        NOT NULL CHECK (char_length(holder) BETWEEN 1 AND 64),
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, kind, key, id)
);
CREATE INDEX stream_leases_expiry ON pc.stream_leases (org_id, expires_at);

ALTER TABLE pc.stream_leases ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.stream_leases FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.stream_leases
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));
CREATE TRIGGER org_write_guard BEFORE INSERT OR UPDATE ON pc.stream_leases
    FOR EACH ROW EXECUTE FUNCTION pc.org_write_guard();

GRANT SELECT, INSERT, DELETE ON pc.stream_leases TO pc_app;
GRANT UPDATE (expires_at) ON pc.stream_leases TO pc_app;
-- +goose StatementBegin
DO $$ BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'pc_deleter') THEN
        GRANT SELECT, DELETE ON pc.stream_leases TO pc_deleter;
    END IF;
END $$;
-- +goose StatementEnd

-- +goose Down
DROP TABLE pc.stream_leases;
