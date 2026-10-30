-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Export destinations (G0 M20 D252; F517, HR-513, T-223). A destination is
-- an HTTPS PUT target or an S3-compatible bucket that receives evidence
-- packs, proof bundles and organization exports. The model is SIEM's
-- (00126): created PENDING through the API, ACTIVE only when a person
-- activates it on its page with a fresh WebAuthn step-up (activated_by,
-- activated_credential). The kind, URL, bucket, region, prefix, addressing
-- style, internal flag and data classes never change once stored: another
-- target is another destination, so a step-up always covers what is sent
-- where. A private or loopback target needs internal = true, which the
-- same activation confirms. The credential is an envelope ciphertext bound
-- to org, table, column and row (HR-062); pc_audit_ro cannot read it.
--
-- Delivery health is kept on the destination: configured (ACTIVE) is
-- separate from delivery confirmed (confirmed_at, the first delivered
-- push).

-- +goose Up
CREATE TABLE pc.export_destinations (
    org_id               uuid        NOT NULL REFERENCES pc.orgs (id),
    id                   uuid        NOT NULL,
    name                 text        NOT NULL CHECK (name ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),
    kind                 text        NOT NULL CHECK (kind IN ('https_put', 's3')),
    url                  text        NOT NULL CHECK (char_length(url) BETWEEN 9 AND 2048 AND url LIKE 'https://%'),
    bucket               text        CHECK (bucket IS NULL OR bucket ~ '^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$'),
    region               text        CHECK (region IS NULL OR region ~ '^[a-z0-9-]{1,32}$'),
    key_prefix           text        NOT NULL DEFAULT ''
                                     CHECK (key_prefix = '' OR (char_length(key_prefix) <= 256
                                            AND key_prefix ~ '^[A-Za-z0-9_-][A-Za-z0-9._-]*(/[A-Za-z0-9_-][A-Za-z0-9._-]*)*$')),
    path_style           boolean     NOT NULL DEFAULT false,
    internal             boolean     NOT NULL DEFAULT false,
    data_classes         text[]      NOT NULL CHECK (cardinality(data_classes) BETWEEN 1 AND 4
                                                     AND array_position(data_classes, NULL) IS NULL
                                                     AND data_classes <@ ARRAY['evidence_packs', 'payload_captures', 'proof_bundles',
                                                                               'org_exports']::text[]),
    state                text        NOT NULL DEFAULT 'PENDING' CHECK (state IN ('PENDING', 'ACTIVE', 'PAUSED', 'DISABLED')),
    secret               bytea       NOT NULL CHECK (octet_length(secret) BETWEEN 16 AND 8192),
    secret_replaced_at   timestamptz,
    created_by           text        NOT NULL CHECK (char_length(created_by) BETWEEN 1 AND 128),
    created_at           timestamptz NOT NULL DEFAULT now(),
    activated_by         uuid,
    activated_credential uuid,
    activated_at         timestamptz,
    updated_at           timestamptz NOT NULL DEFAULT now(),
    -- Delivery health.
    confirmed_at         timestamptz,
    last_delivered_at    timestamptz,
    consecutive_failures integer     NOT NULL DEFAULT 0 CHECK (consecutive_failures >= 0),
    failing_since        timestamptz,
    last_failure_at      timestamptz,
    last_failure_code    text        CHECK (last_failure_code IS NULL OR last_failure_code ~ '^[a-z0-9_]{1,64}$'),
    delivered_pushes     bigint      NOT NULL DEFAULT 0 CHECK (delivered_pushes >= 0),
    failed_pushes        bigint      NOT NULL DEFAULT 0 CHECK (failed_pushes >= 0),
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, activated_by) REFERENCES pc.users (org_id, id),
    FOREIGN KEY (org_id, activated_credential) REFERENCES pc.webauthn_credentials (org_id, id),
    CHECK ((kind = 's3') = (bucket IS NOT NULL)),
    CHECK ((kind = 's3') = (region IS NOT NULL)),
    CHECK (kind = 's3' OR NOT path_style),
    CHECK ((activated_at IS NULL) = (activated_by IS NULL) AND (activated_by IS NULL) = (activated_credential IS NULL)),
    CHECK (state IN ('PENDING', 'DISABLED') OR activated_at IS NOT NULL),
    CHECK ((consecutive_failures = 0) = (failing_since IS NULL)),
    CHECK (confirmed_at IS NOT NULL OR last_delivered_at IS NULL)
);
-- A deleted (DISABLED) destination frees its name.
CREATE UNIQUE INDEX export_destinations_name ON pc.export_destinations (org_id, name) WHERE state <> 'DISABLED';

-- The target and the data classes never change (no column grant), a
-- destination is inserted PENDING and never activated without a person and
-- a key, and DISABLED is final (HR-513).
-- +goose StatementBegin
CREATE FUNCTION pc.export_destination_guard() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pc, pg_temp
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.state IS DISTINCT FROM 'PENDING' OR NEW.activated_by IS NOT NULL OR NEW.confirmed_at IS NOT NULL THEN
            RAISE EXCEPTION 'an export destination is inserted PENDING' USING ERRCODE = 'check_violation';
        END IF;
        NEW.created_at := now();
        RETURN NEW;
    END IF;
    IF OLD.state = 'DISABLED' AND NEW.state IS DISTINCT FROM 'DISABLED' THEN
        RAISE EXCEPTION 'a disabled export destination stays disabled' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.state = 'PENDING' AND OLD.state IS DISTINCT FROM 'PENDING' THEN
        RAISE EXCEPTION 'an export destination cannot return to PENDING' USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.activated_by IS NOT NULL AND (NEW.activated_by IS DISTINCT FROM OLD.activated_by
            OR NEW.activated_credential IS DISTINCT FROM OLD.activated_credential
            OR NEW.activated_at IS DISTINCT FROM OLD.activated_at) THEN
        RAISE EXCEPTION 'an export destination is activated once' USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.activated_by IS NULL AND NEW.activated_by IS NOT NULL THEN
        NEW.activated_at := now();
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER export_destinations_guard BEFORE INSERT OR UPDATE ON pc.export_destinations
    FOR EACH ROW EXECUTE FUNCTION pc.export_destination_guard();
CREATE TRIGGER org_write_guard BEFORE INSERT OR UPDATE ON pc.export_destinations
    FOR EACH ROW EXECUTE FUNCTION pc.org_write_guard();

ALTER TABLE pc.export_destinations ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.export_destinations FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.export_destinations
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));

GRANT SELECT, INSERT ON pc.export_destinations TO pc_app;
GRANT UPDATE (state, secret, secret_replaced_at, activated_by, activated_credential, activated_at, updated_at, confirmed_at,
    last_delivered_at, consecutive_failures, failing_since, last_failure_at, last_failure_code, delivered_pushes,
    failed_pushes) ON pc.export_destinations TO pc_app;
GRANT SELECT (org_id, id, name, kind, url, bucket, region, key_prefix, path_style, internal, data_classes, state,
    secret_replaced_at, created_by, created_at, activated_by, activated_credential, activated_at, updated_at, confirmed_at,
    last_delivered_at, consecutive_failures, failing_since, last_failure_at, last_failure_code, delivered_pushes,
    failed_pushes) ON pc.export_destinations TO pc_audit_ro;

-- +goose Down
DROP TABLE pc.export_destinations;
DROP FUNCTION pc.export_destination_guard();
