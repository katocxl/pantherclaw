-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Per-org OTLP destinations (G0 M36 D1061, D1062; FQ36-1, FQ36-2;
-- HR-786..788). An org sends the spans of its own agents' decisions, tool
-- calls and model calls to its own OpenTelemetry collector: an OTLP/HTTP
-- traces endpoint. It is created PENDING through the API by a person
-- holding otlp.manage and becomes ACTIVE only when a person activates it on
-- its page with a fresh WebAuthn step-up (activated_by,
-- activated_credential), as a SIEM destination (HR-259). The URL never
-- changes once stored: another endpoint is another destination, so the
-- step-up always covers where spans go. The operator's own telemetry
-- (HR-380) is separate and unchanged.
--
-- header_secret_ref holds the request headers the collector needs (such as
-- DD-API-KEY or a Basic authorization), sealed as one envelope ciphertext
-- bound to org, table, column and row (HR-062); it is never shown again and
-- pc_audit_ro cannot read it.
--
-- cursor_seq is the last evidence feed seq (the ledger chain seq) exported,
-- moved only forward by compare-and-set after a 2xx. Spans carry metadata
-- only, never prompts, arguments or answers (HR-787), and their ids are
-- derived from the transaction, so a re-export is idempotent (HR-788).
-- After 24 hours of failed exports the exporter disables the destination,
-- audited; DISABLED is final.

-- +goose Up
CREATE TABLE pc.otlp_destinations (
    org_id               uuid        NOT NULL REFERENCES pc.orgs (id),
    id                   uuid        NOT NULL,
    name                 text        NOT NULL CHECK (name ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),
    url                  text        NOT NULL CHECK (char_length(url) BETWEEN 9 AND 2048 AND url LIKE 'https://%'),
    header_secret_ref    bytea       CHECK (header_secret_ref IS NULL OR octet_length(header_secret_ref) BETWEEN 16 AND 16384),
    -- The header names only (never values), to show which are set.
    header_names         text[]      NOT NULL DEFAULT '{}' CHECK (cardinality(header_names) <= 8
                                                                  AND array_position(header_names, NULL) IS NULL),
    state                text        NOT NULL DEFAULT 'PENDING' CHECK (state IN ('PENDING', 'ACTIVE', 'DISABLED')),
    created_by           text        NOT NULL CHECK (char_length(created_by) BETWEEN 1 AND 128),
    created_at           timestamptz NOT NULL DEFAULT now(),
    activated_by         uuid,
    activated_credential uuid,
    activated_at         timestamptz,
    disabled_at          timestamptz,
    updated_at           timestamptz NOT NULL DEFAULT now(),
    -- Export progress and health.
    cursor_seq           bigint      NOT NULL DEFAULT 0 CHECK (cursor_seq >= 0),
    last_success_at      timestamptz,
    failure_count        integer     NOT NULL DEFAULT 0 CHECK (failure_count >= 0),
    failing_since        timestamptz,
    last_failure_code    text        CHECK (last_failure_code IS NULL OR last_failure_code ~ '^[a-z0-9_]{1,64}$'),
    next_attempt_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, activated_by) REFERENCES pc.users (org_id, id),
    FOREIGN KEY (org_id, activated_credential) REFERENCES pc.webauthn_credentials (org_id, id),
    CHECK ((activated_at IS NULL) = (activated_by IS NULL) AND (activated_by IS NULL) = (activated_credential IS NULL)),
    CHECK (state IN ('PENDING', 'DISABLED') OR activated_at IS NOT NULL),
    CHECK ((state = 'DISABLED') = (disabled_at IS NOT NULL)),
    CHECK ((failure_count = 0) = (failing_since IS NULL)),
    CHECK ((header_secret_ref IS NULL) = (cardinality(header_names) = 0))
);
-- A disabled destination frees its name.
CREATE UNIQUE INDEX otlp_destinations_name ON pc.otlp_destinations (org_id, name) WHERE state <> 'DISABLED';
CREATE INDEX otlp_destinations_active ON pc.otlp_destinations (org_id) WHERE state = 'ACTIVE';

-- The URL, the headers and the creator never change, a destination is
-- inserted PENDING and never activated without a person and a key, the
-- cursor never moves backwards, and DISABLED is final (HR-786).
-- +goose StatementBegin
CREATE FUNCTION pc.otlp_destination_guard() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pc, pg_temp
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.state IS DISTINCT FROM 'PENDING' OR NEW.activated_by IS NOT NULL OR NEW.cursor_seq <> 0 THEN
            RAISE EXCEPTION 'an OTLP destination is inserted PENDING' USING ERRCODE = 'check_violation';
        END IF;
        NEW.created_at := now();
        RETURN NEW;
    END IF;
    IF NEW.url IS DISTINCT FROM OLD.url OR NEW.header_secret_ref IS DISTINCT FROM OLD.header_secret_ref
            OR NEW.header_names IS DISTINCT FROM OLD.header_names OR NEW.created_by IS DISTINCT FROM OLD.created_by THEN
        RAISE EXCEPTION 'an OTLP destination''s URL and headers never change' USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.state = 'DISABLED' AND NEW.state IS DISTINCT FROM 'DISABLED' THEN
        RAISE EXCEPTION 'a disabled OTLP destination stays disabled' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.state = 'PENDING' AND OLD.state IS DISTINCT FROM 'PENDING' THEN
        RAISE EXCEPTION 'an OTLP destination cannot return to PENDING' USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.activated_by IS NOT NULL AND (NEW.activated_by IS DISTINCT FROM OLD.activated_by
            OR NEW.activated_credential IS DISTINCT FROM OLD.activated_credential
            OR NEW.activated_at IS DISTINCT FROM OLD.activated_at) THEN
        RAISE EXCEPTION 'an OTLP destination is activated once' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.cursor_seq < OLD.cursor_seq THEN
        RAISE EXCEPTION 'an OTLP cursor never moves backwards' USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.activated_by IS NULL AND NEW.activated_by IS NOT NULL THEN
        NEW.activated_at := now();
    END IF;
    IF OLD.state IS DISTINCT FROM 'DISABLED' AND NEW.state = 'DISABLED' THEN
        NEW.disabled_at := now();
    END IF;
    NEW.updated_at := now();
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER otlp_destinations_guard BEFORE INSERT OR UPDATE ON pc.otlp_destinations
    FOR EACH ROW EXECUTE FUNCTION pc.otlp_destination_guard();

ALTER TABLE pc.otlp_destinations ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.otlp_destinations FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.otlp_destinations
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));
CREATE TRIGGER org_write_guard BEFORE INSERT OR UPDATE ON pc.otlp_destinations
    FOR EACH ROW EXECUTE FUNCTION pc.org_write_guard();

GRANT SELECT, INSERT ON pc.otlp_destinations TO pc_app;
GRANT UPDATE (state, activated_by, activated_credential, activated_at, disabled_at, updated_at, cursor_seq, last_success_at,
    failure_count, failing_since, last_failure_code, next_attempt_at) ON pc.otlp_destinations TO pc_app;
GRANT SELECT (org_id, id, name, url, header_names, state, created_by, created_at, activated_by, activated_credential,
    activated_at, disabled_at, updated_at, cursor_seq, last_success_at, failure_count, failing_since, last_failure_code,
    next_attempt_at) ON pc.otlp_destinations TO pc_audit_ro;
-- +goose StatementBegin
DO $$ BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'pc_deleter') THEN
        GRANT SELECT, DELETE ON pc.otlp_destinations TO pc_deleter;
    END IF;
END $$;
-- +goose StatementEnd

-- +goose Down
DROP TABLE pc.otlp_destinations;
DROP FUNCTION pc.otlp_destination_guard();
